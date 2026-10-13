#include "status.h"

#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

size_t status_format(const StatusReport *r, char *buffer, size_t size) {
    char *at = buffer;
    size_t left = size;
    if (size) buffer[0] = 0;
    put(&at, &left, "protocol=%d\nversion=%s\npid=%d\nstate=%s\nprefer-phone=%s\n", STATUS_PROTOCOL, VERSION,
        (int)getpid(), r->state, r->prefer_phone ? "yes" : "no");
    if (r->phone) put(&at, &left, "phone=%s\n", r->phone);
    const SessionStatus *s = r->session;
    if (s) {
        const DataStats *t = &s->data;
        put(&at, &left, "interface=%s\nconnected-since=%lld\n", s->interface, (long long)s->connected_at);
        if (s->address[0]) put(&at, &left, "address=%s\ngateway=%s\n", s->address, s->gateway);
        put(&at, &left, "primary=%s\n", s->primary);
        put(&at, &left, "rx-bytes=%llu\ntx-bytes=%llu\nrx-dropped=%llu\ntx-dropped=%llu\nusb-errors=%llu\n"
            "resets=%u\n", t->rx_bytes, t->tx_bytes, t->rx_dropped, t->tx_dropped, s->usb_errors, s->resets);
    }
    if (r->problem) put(&at, &left, "problem=%s\n", r->problem);
    if (r->settings_problem) put(&at, &left, "settings-problem=%s\n", r->settings_problem);
    return size - left;
}

typedef struct {
    int listener;
    size_t (*report)(char *buffer, size_t size);
} Server;

/* The reply fits the socket buffer, so the write never blocks. */
static void accept_all(void *context) {
    const Server *server = context;
    int fd;
    while ((fd = accept(server->listener, NULL, NULL)) >= 0) {
        char text[2048];
        size_t n = server->report(text, sizeof text);
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        (void)write(fd, text, n);
        close(fd);
    }
}

bool status_serve(size_t (*report)(char *buffer, size_t size)) {
    static Server server; /* lives as long as the daemon */
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strlcpy(address.sun_path, STATUS_SOCKET, sizeof address.sun_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    unlink(STATUS_SOCKET);
    if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK) ||
        bind(fd, (const struct sockaddr *)&address, sizeof address) || chmod(STATUS_SOCKET, 0666) ||
        listen(fd, 8)) {
        if (fd >= 0) close(fd);
        return false;
    }
    server = (Server){fd, report};
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0,
                                                      dispatch_get_main_queue());
    if (!source) {
        close(fd);
        return false;
    }
    dispatch_set_context(source, &server);
    dispatch_source_set_event_handler_f(source, accept_all);
    dispatch_resume(source);
    return true;
}
