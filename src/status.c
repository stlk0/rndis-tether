#include "status.h"
#include "runtime.h"

#include <dispatch/dispatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void put(char **at, size_t *left, const char *format, ...) __attribute__((format(printf, 3, 4)));
static void put(char **at, size_t *left, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vsnprintf(*at, *left, format, args);
    va_end(args);
    if (n < 0 || !*left) return;
    size_t used = (size_t)n < *left ? (size_t)n : *left - 1;
    *at += used;
    *left -= used;
}

static const char *choose_state(const StatusFacts *f, const SessionStatus *s) {
    if (f->paused) return STATUS_STATE_PAUSED; /* wins over every other state */
    if (!f->phone) return STATUS_STATE_NO_PHONE;
    if (f->rejected) return STATUS_STATE_UNSUPPORTED;
    if (f->sleeping) return STATUS_STATE_SLEEPING;
    if (s) {
        if (s->address[0]) return STATUS_STATE_ONLINE;
        return STATUS_STATE_CONNECTING;
    }
    if (f->last_failure[0]) return STATUS_STATE_RETRYING;
    return STATUS_STATE_CONNECTING;
}

void status_choose(const StatusFacts *f, StatusReport *r) {
    const SessionStatus *s = f->paused ? NULL : f->session;
    r->state = choose_state(f, s);
    r->paused = f->paused;
    r->phone = f->phone;
    r->problem = f->phone && !s && !f->paused && f->last_failure[0] ? f->last_failure : NULL;
    r->session = s;
}

size_t status_format(const StatusReport *r, char *buffer, size_t size) {
    char *at = buffer;
    size_t left = size;
    if (size) buffer[0] = 0;
    put(&at, &left, "protocol=%d\nversion=%s\npid=%d\nstate=%s\nprefer-phone=%s\npaused=%s\n", STATUS_PROTOCOL,
        VERSION, (int)getpid(), r->state, config_bool_text(r->prefer_phone), config_bool_text(r->paused));
    if (r->phone) put(&at, &left, "phone=%s\n", r->phone);
    const SessionStatus *s = r->session;
    if (s) {
        const DataStats *stats = &s->data;
        put(&at, &left, "interface=%s\nconnected-since=%lld\n", s->interface, (long long)s->connected_at);
        if (s->address[0]) put(&at, &left, "address=%s\ngateway=%s\n", s->address, s->gateway);
        put(&at, &left, "primary=%s\n", s->primary);
        put(&at, &left, "rx-bytes=%llu\ntx-bytes=%llu\nrx-dropped=%llu\ntx-dropped=%llu\nusb-errors=%llu\n"
            "resets=%u\n", stats->rx_bytes, stats->tx_bytes, stats->rx_dropped, stats->tx_dropped,
            s->usb_errors, s->resets);
    }
    if (r->problem) put(&at, &left, "problem=%s\n", r->problem);
    if (r->settings_problem) put(&at, &left, "settings-problem=%s\n", r->settings_problem);
    return size - left;
}

_Static_assert(RUNTIME_BACKLOG >= 2 * STATUS_ACCEPT_BATCH, "the backlog holds two batches of clients");

typedef struct {
    int listener;
    size_t (*report)(char *buffer, size_t size);
} Server;

/* A bounded batch per event, with one report for all of it: a flood of clients must not
 * keep USB completions, BPF and timers waiting. The source fires again for the rest.
 * The reply fits the socket buffer, so the write never blocks. */
static void accept_some(void *context) {
    const Server *server = context;
    char text[STATUS_TEXT_SIZE];
    size_t n = 0;
    for (unsigned i = 0; i < STATUS_ACCEPT_BATCH; ++i) {
        int fd = accept(server->listener, NULL, NULL);
        if (fd < 0) return;
        if (!n) n = server->report(text, sizeof text);
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        (void)write(fd, text, n);
        close(fd);
    }
}

bool status_serve(const char *dir, const char *path, size_t (*report)(char *buffer, size_t size)) {
    static Server server; /* lives as long as the daemon */
    int fd = runtime_listen(dir, path, getegid(), 0666);
    if (fd < 0) return false;
    server = (Server){fd, report};
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0,
                                                      dispatch_get_main_queue());
    if (!source) {
        close(fd);
        unlink(path);
        return false;
    }
    dispatch_set_context(source, &server);
    dispatch_source_set_event_handler_f(source, accept_some);
    dispatch_resume(source);
    return true;
}
