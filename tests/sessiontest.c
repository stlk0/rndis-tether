/* Offline scenarios for the data path (datapath.c), KEEPALIVE and RESET (health.c),
 * the status reply and socket (status.c), the admin socket (admin.c) and how both
 * sockets are put in place (runtime.c). USB transfers and control requests are captured
 * by fakes and completed by hand; BPF is one end of a socket pair; the sockets are
 * real, in a private directory under /tmp, for the user's own group.
 */
#include "admin.h"
#include "clock.h"
#include "health.h"
#include "runtime.h"
#include "status.h"

#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned tests, failures;
#define CHECK(x) do { ++tests; if (!(x)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

/* ------------------------------------------------------------------- fakes */

static uint64_t test_now = 100000;
uint64_t now_ms(void) { return test_now; }
void sleep_ms(unsigned ms) { test_now += ms; }

static UsbLink usb_link = {.out_packet_size = 512};
static UsbTransfer *reads[64];
static unsigned read_count;
static UsbTransfer *written;
static const uint8_t *written_buffer;
static uint32_t written_size;
static unsigned write_count;
static IOReturn write_error;

IOReturn usb_read(UsbLink *u, UsbPipe pipe, UsbTransfer *t, void *buffer, uint32_t size) {
    (void)u; (void)buffer; (void)size;
    CHECK(pipe == USB_BULK_IN);
    reads[read_count++ % 64] = t;
    return kIOReturnSuccess;
}

IOReturn usb_write(UsbLink *u, UsbTransfer *t, const void *buffer, uint32_t size) {
    (void)u;
    ++write_count;
    if (write_error) return write_error;
    written = t;
    written_buffer = buffer;
    written_size = size;
    return kIOReturnSuccess;
}

void usb_clear_stall(UsbLink *u, UsbPipe pipe) { (void)u; (void)pipe; }

static ControlMessage sent[16];
static unsigned sent_count;
static uint32_t last_id;

uint32_t control_next_id(void) { return ++last_id; }

bool control_send(Control *c, const ControlMessage *m, bool urgent) {
    (void)c; (void)urgent;
    sent[sent_count++ % 16] = *m;
    return true;
}

/* -------------------------------------------- the session's wiring, in small */

static Datapath data;
static Health health;
static Control control; /* only its address is used */
static int macos = -1;  /* the other end of "BPF": what macOS would receive */
static unsigned heard, failed;
static const char *failed_reason;

static void on_heard(void) { ++heard; health_heard(&health); }
static void on_errors(const char *reason) { health_reset(&health, reason); }
static void on_drained(void) { health_drained(&health); }

static void on_failed(const char *reason, IOReturn status) {
    (void)status;
    ++failed;
    failed_reason = reason;
    datapath_stop(&data);
    health_stop(&health);
}

static const DatapathEvents events = {on_heard, on_errors, on_drained, on_failed};

static void fixture(uint32_t max_transfer, unsigned batch_limit) {
    if (data.usb) datapath_close(&data);
    if (macos >= 0) close(macos);
    int pair[2];
    CHECK(!socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));
    macos = pair[1];
    (void)fcntl(macos, F_SETFL, O_NONBLOCK);
    test_now = 100000;
    read_count = write_count = sent_count = heard = failed = 0;
    write_error = 0;
    written = NULL;
    failed_reason = NULL;
    DatapathLimits limits = {.mtu = 1500, .batch_limit = batch_limit, .max_transfer = max_transfer};
    health_start(&health, &control, &data, 0x0b, on_failed);
    CHECK(!datapath_start(&data, &usb_link, pair[0], BPF_BUFFER, &limits, &events));
    CHECK(read_count == RX_SLOTS && data.free_count == TX_SLOTS && !data.bpf_batch);
}

static void make_frame(uint8_t *f, size_t n, uint8_t tag) {
    memset(f, 0xff, 6);
    for (size_t i = 6; i < n; ++i) f[i] = (uint8_t)(tag + i);
}

static void complete_write(IOReturn status) {
    UsbTransfer *t = written;
    written = NULL;
    CHECK(t != NULL);
    if (t) t->done(t, status, written_size);
}

static void reply(unsigned index, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    ControlMessage m = sent[index];
    m.done(m.context, result, status, addressing_reset);
}

/* ------------------------------------------------------------------- tests */

static void test_tx_batching(void) {
    fixture(23700, 15);
    uint8_t a[60], b[1514];
    make_frame(a, sizeof a, 1);
    make_frame(b, sizeof b, 2);
    datapath_send(&data, a, sizeof a);
    datapath_send(&data, b, sizeof b);
    CHECK(write_count == 0); /* nothing waits, but nothing goes before the end of the burst */
    datapath_flush(&data);
    CHECK(write_count == 1 && data.free_count == TX_SLOTS - 1);
    RndisCursor cursor = {written_buffer, written_size};
    const uint8_t *frame = NULL;
    size_t length = 0;
    const char *why = NULL;
    CHECK(rndis_next_frame(&cursor, &frame, &length, &why) == 1 && length == sizeof a && !memcmp(frame, a, sizeof a));
    CHECK(rndis_next_frame(&cursor, &frame, &length, &why) == 1 && length == sizeof b && !memcmp(frame, b, sizeof b));
    CHECK(rndis_next_frame(&cursor, &frame, &length, &why) == 0);
    complete_write(kIOReturnSuccess);
    CHECK(data.free_count == TX_SLOTS && data.stats.tx_frames == 2 && data.stats.tx_transfers == 1);

    /* The phone's limit splits a burst into transfers; batch_limit sends early. */
    fixture(1580, 2);
    datapath_send(&data, b, sizeof b);
    datapath_send(&data, b, sizeof b);
    CHECK(write_count == 1);
    complete_write(kIOReturnSuccess);
    datapath_send(&data, a, sizeof a); /* no room after the big frame: that one goes out */
    datapath_send(&data, a, sizeof a); /* the second packet reaches batch_limit */
    CHECK(write_count == 3);
    datapath_send(&data, a, sizeof a);
    datapath_flush(&data);
    CHECK(write_count == 4 && data.stats.tx_dropped == 0);
}

/* A transfer of whole 512-byte packets ends with one zero byte; it counts towards the
 * phone's MaxTransferSize too. */
static void test_tx_transfer_limit(void) {
    uint8_t big[1514], rest[2048 - 2 * RNDIS_PACKET_HEADER - 1514];
    make_frame(big, sizeof big, 8);
    make_frame(rest, sizeof rest, 9);
    fixture(2048, 8); /* without the byte, both would make exactly 2048 */
    datapath_send(&data, big, sizeof big);
    datapath_send(&data, rest, sizeof rest);
    CHECK(write_count == 1 && written_size == RNDIS_PACKET_HEADER + sizeof big);
    complete_write(kIOReturnSuccess);
    datapath_flush(&data);
    CHECK(write_count == 2 && written_size <= 2048 && !data.stats.tx_dropped);
    complete_write(kIOReturnSuccess);

    fixture(1558, 8); /* the Linux gadget's limit: a full-size frame still goes in one transfer */
    datapath_send(&data, big, sizeof big);
    datapath_flush(&data);
    CHECK(write_count == 1 && written_size == 1558 && !data.stats.tx_dropped);
    complete_write(kIOReturnSuccess);
}

static void test_rx_delivery(void) {
    fixture(23700, 15);
    RxSlot *slot = USB_OWNER(reads[0], RxSlot, usb);
    uint8_t a[60], b[1514];
    make_frame(a, sizeof a, 3);
    make_frame(b, sizeof b, 4);
    size_t used = rndis_append_packet(slot->buffer, 0, sizeof slot->buffer, a, sizeof a, 0);
    used += rndis_append_packet(slot->buffer, used, sizeof slot->buffer, b, sizeof b, 0);
    reads[0]->done(reads[0], kIOReturnSuccess, used);
    uint8_t got[2048];
    CHECK(read(macos, got, sizeof got) == (ssize_t)sizeof a && !memcmp(got, a, sizeof a));
    CHECK(read(macos, got, sizeof got) == (ssize_t)sizeof b && !memcmp(got, b, sizeof b));
    CHECK(data.stats.rx_frames == 2 && data.stats.rx_transfers == 1 && heard == 1);
    CHECK(read_count == RX_SLOTS + 1 && reads[RX_SLOTS] == reads[0]); /* the read is armed again */
}

static void test_rx_abort_storm(void) {
    fixture(23700, 15);
    UsbTransfer *t = reads[0];
    /* Stall recovery aborts sibling reads; those are re-armed, not counted as errors. */
    for (unsigned i = 0; i < RX_SLOTS * USB_ERROR_BURST; ++i) t->done(t, kIOReturnAborted, 0);
    CHECK(!failed && read_count == RX_SLOTS + RX_SLOTS * USB_ERROR_BURST && !data.stats.usb_errors);
    t->done(t, kIOReturnSuccess, 0);
    CHECK(!data.rx_aborted_row);
    /* Aborts with no data in between cannot go on forever. */
    for (unsigned i = 0; i <= RX_SLOTS * USB_ERROR_BURST; ++i) t->done(t, kIOReturnAborted, 0);
    CHECK(failed == 1 && !strcmp(failed_reason, "bulk IN reads keep being aborted"));
}

static void test_reset_during_batch_flush(void) {
    fixture(1580, 8);
    uint8_t frame[1514];
    make_frame(frame, sizeof frame, 5);
    datapath_send(&data, frame, sizeof frame);
    write_error = kIOReturnError;
    data.tx_errors_row = USB_ERROR_BURST / 2 - 1;
    datapath_send(&data, frame, sizeof frame); /* the full transfer fails to go out and asks for RESET */
    CHECK(write_count == 1 && health.resetting && health.reset_queued && data.held && !data.filling);
    CHECK(data.stats.tx_dropped == 2 && data.free_count == TX_SLOTS && !failed);
    CHECK(sent_count == 1 && sent[0].type == RNDIS_RESET_MSG);
}

static void test_reset_filter_restore(void) {
    fixture(23700, 15);
    uint8_t frame[60];
    make_frame(frame, sizeof frame, 6);
    datapath_send(&data, frame, sizeof frame);
    datapath_flush(&data); /* one bulk OUT write in flight */
    health_reset(&health, "offline test");
    CHECK(health.resetting && !health.reset_queued && health.resets == 1 && !sent_count && data.held);
    health_reset(&health, "the same RESET is still in progress");
    CHECK(health.resets == 1 && !failed);
    datapath_send(&data, frame, sizeof frame);
    CHECK(data.stats.tx_dropped == 1 && !data.filling); /* held: nothing new goes out */
    complete_write(kIOReturnSuccess);
    CHECK(health.reset_queued && sent_count == 1 && sent[0].type == RNDIS_RESET_MSG);
    reply(0, CONTROL_SUCCESS, 0, 1); /* the phone lost its addressing: restore the packet filter */
    CHECK(health.resetting && sent_count == 2 && sent[1].type == RNDIS_SET_MSG);
    CHECK(rndis_le32(sent[1].bytes + 12) == OID_GEN_CURRENT_PACKET_FILTER && rndis_le32(sent[1].bytes + 28) == 0x0b);
    reply(1, CONTROL_SUCCESS, 0, 0);
    CHECK(!health.resetting && !data.held && !failed && health.resets == 1);
}

static void test_keepalive(void) {
    fixture(23700, 15);
    health_tick(&health);
    CHECK(!sent_count);
    test_now += 5000;
    health_tick(&health);
    health_tick(&health);
    CHECK(sent_count == 1 && sent[0].type == RNDIS_KEEPALIVE_MSG && health.keepalive_outstanding);
    CHECK(sent[0].wanted(sent[0].context));
    health_heard(&health);
    CHECK(!sent[0].wanted(sent[0].context)); /* traffic came back while it waited in the queue */
    reply(0, CONTROL_SKIPPED, 0, 0);
    CHECK(!health.keepalive_outstanding && !health.keepalive_failures);

    test_now += 5000;
    health_tick(&health);
    reply(1, CONTROL_TIMEOUT, 0, 0);
    health_tick(&health);
    reply(2, CONTROL_USB_ERROR, (uint32_t)kIOReturnError, 0);
    CHECK(!failed && health.keepalive_failures == 2);
    health_tick(&health);
    reply(3, CONTROL_SUCCESS, 0, 0);
    CHECK(!health.keepalive_failures);
    for (unsigned i = 0; i < 3; ++i) {
        health_tick(&health);
        reply(4 + i, CONTROL_TIMEOUT, 0, 0);
    }
    CHECK(failed == 1 && !strcmp(failed_reason, "phone stopped responding to keepalive"));

    fixture(23700, 15);
    test_now += 5000;
    health_tick(&health);
    reply(0, CONTROL_DEVICE_STATUS, 1, 0); /* rejected: RESET */
    CHECK(health.resetting && health.reset_queued && sent[1].type == RNDIS_RESET_MSG);
    reply(1, CONTROL_TIMEOUT, 0, 0);
    CHECK(failed == 1 && !strcmp(failed_reason, "soft RESET failed"));
}

static void test_reset_limits(void) {
    fixture(23700, 15);
    health_reset(&health, "offline test");
    reply(0, CONTROL_SUCCESS, 0, 0);
    CHECK(!health.resetting && !failed);
    test_now += 29999;
    health_reset(&health, "another need within 30 seconds");
    CHECK(failed == 1 && health.resets == 1);

    fixture(23700, 15);
    uint8_t frame[60];
    make_frame(frame, sizeof frame, 7);
    datapath_send(&data, frame, sizeof frame);
    datapath_flush(&data);
    health_reset(&health, "bulk OUT never drains");
    test_now += 4999;
    health_tick(&health);
    CHECK(!failed);
    ++test_now;
    health_tick(&health);
    CHECK(failed == 1 && !strcmp(failed_reason, "bulk OUT did not drain before RESET"));
}

static void test_status_format(void) {
    char text[2048];
    StatusReport report = {.state = "no-phone", .prefer_phone = true};
    status_format(&report, text, sizeof text);
    CHECK(!strncmp(text, "protocol=1\n", 11)); /* readers check it first */
    CHECK(strstr(text, "version=" VERSION "\n") && strstr(text, "state=no-phone\n") && !strstr(text, "\nphone="));
    CHECK(strstr(text, "\npaused=no\n")); /* always there: clients tell a service that can pause by it */
    report = (StatusReport){.state = "paused", .paused = true, .phone = "Phone 04e8:6864"};
    status_format(&report, text, sizeof text);
    CHECK(strstr(text, "state=paused\n") && strstr(text, "\npaused=yes\n") &&
          strstr(text, "\nphone=Phone 04e8:6864\n"));
    report = (StatusReport){.state = "retrying", .phone = "Phone 04e8:6864",
                            .problem = "interface is already open by another program"};
    status_format(&report, text, sizeof text);
    CHECK(strstr(text, "state=retrying\n") && strstr(text, "\nphone=Phone 04e8:6864\n") &&
          strstr(text, "problem=interface is already open by another program\n") && strstr(text, "prefer-phone=no\n"));
    SessionStatus session = {.interface = "feth50", .connected_at = 1234, .address = "10.0.0.2",
                             .gateway = "10.0.0.1", .primary = "feth50", .usb_errors = 3, .resets = 1};
    session.data.rx_bytes = 1234;
    report = (StatusReport){.state = "online", .phone = "Phone", .session = &session, .settings_problem = "line 2"};
    status_format(&report, text, sizeof text);
    CHECK(strstr(text, "state=online\n") && strstr(text, "address=10.0.0.2\n") && strstr(text, "primary=feth50\n"));
    CHECK(strstr(text, "rx-bytes=1234\n") && strstr(text, "usb-errors=3\n") && strstr(text, "resets=1\n"));
    CHECK(strstr(text, "settings-problem=line 2\n"));
    session.address[0] = 0;
    status_format(&report, text, sizeof text);
    CHECK(!strstr(text, "address=") && strstr(text, "connected-since=1234\n"));
    char tiny[16];
    CHECK(status_format(&report, tiny, sizeof tiny) == sizeof tiny - 1 && strlen(tiny) == sizeof tiny - 1);
}

static void test_status_choose(void) {
    SessionStatus session = {.interface = "feth50", .address = "10.0.0.2"};
    StatusFacts f = {.phone = "Phone", .last_failure = "", .session = &session};
    StatusReport r = {0};
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "online") && r.session == &session && !r.paused && !r.problem);
    session.address[0] = 0;
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "connecting"));
    f.session = NULL;
    f.last_failure = "interface is already open by another program";
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "retrying") && r.problem == f.last_failure);
    f.sleeping = true;
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "sleeping") && r.problem);
    f.rejected = true;
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "unsupported"));
    f.phone = NULL;
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "no-phone") && !r.problem && !r.phone);
    /* Paused wins over everything; the phone stays, the problem and the session do not
     * (a status read between `set paused yes` and the teardown). */
    f = (StatusFacts){.phone = "Phone", .rejected = true, .sleeping = true, .paused = true,
                      .last_failure = "no answer", .session = &session};
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "paused") && r.paused && !strcmp(r.phone, "Phone") && !r.problem && !r.session);
    f.phone = NULL;
    status_choose(&f, &r);
    CHECK(!strcmp(r.state, "paused") && !r.phone);
}

/* ------------------------------------------------------------------ sockets */

static char socket_dir[64], admin_path[96], status_path[96];
static unsigned set_calls;
static uid_t set_uid;
static char set_name[64], set_value[64];

static int connect_to(const char *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strlcpy(address.sun_path, path, sizeof address.sun_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0 && !connect(fd, (const struct sockaddr *)&address, sizeof address));
    return fd;
}

static void test_runtime(void) {
    strlcpy(socket_dir, "/tmp/rndis-tether-test-XXXXXX", sizeof socket_dir);
    CHECK(mkdtemp(socket_dir) != NULL);
    CHECK(runtime_dir(socket_dir)); /* mkdtemp makes it 0700 */
    char path[128], other[128];
    snprintf(path, sizeof path, "%s/open", socket_dir);
    CHECK(!mkdir(path, 0755) && !runtime_dir(path) && errno == EPERM);
    CHECK(!rmdir(path));
    snprintf(path, sizeof path, "%s/new", socket_dir);
    CHECK(runtime_dir(path) && runtime_dir(path)); /* made, then found */
    CHECK(!rmdir(path));

    /* Whatever is at the public name is replaced, never followed: a symlink to someone
     * else's file leaves that file alone. */
    snprintf(path, sizeof path, "%s/victim", socket_dir);
    snprintf(other, sizeof other, "%s/public.sock", socket_dir);
    int victim = open(path, O_WRONLY | O_CREAT, 0600);
    CHECK(victim >= 0 && !symlink(path, other));
    close(victim);
    int fd = runtime_listen(socket_dir, other, getgid(), 0666);
    struct stat st;
    CHECK(fd >= 0 && !lstat(other, &st) && S_ISSOCK(st.st_mode) && (st.st_mode & 0777) == 0666);
    CHECK(!stat(path, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600);
    snprintf(path, sizeof path, "%s/public.sock.new", socket_dir);
    CHECK(lstat(path, &st) && errno == ENOENT); /* nothing left in the private directory */
    if (fd >= 0) close(fd);
    unlink(other);
    snprintf(path, sizeof path, "%s/victim", socket_dir);
    unlink(path);
}

static unsigned reports;

static size_t fake_report(char *buffer, size_t size) {
    ++reports;
    return (size_t)snprintf(buffer, size, "protocol=1\nstate=no-phone\n");
}

/* Clients that got their reply; the run loop is not run here. */
static unsigned answered(const int *fd, unsigned count) {
    unsigned n = 0;
    for (unsigned i = 0; i < count; ++i) {
        struct pollfd p = {.fd = fd[i], .events = POLLIN};
        if (poll(&p, 1, 0) > 0) ++n;
    }
    return n;
}

static void test_status_socket(void) {
    snprintf(status_path, sizeof status_path, "%s/status.sock", socket_dir);
    CHECK(status_serve(socket_dir, status_path, fake_report));
    struct stat st;
    CHECK(!stat(status_path, &st) && (st.st_mode & 0777) == 0666);

    /* A flood waits its turn: one batch per event, one report per batch. */
    enum { CLIENTS = STATUS_ACCEPT_BATCH + 3 };
    int fd[CLIENTS];
    for (unsigned i = 0; i < CLIENTS; ++i) fd[i] = connect_to(status_path);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
    CHECK(answered(fd, CLIENTS) == STATUS_ACCEPT_BATCH && reports == 1);
    for (int i = 0; i < 20 && answered(fd, CLIENTS) < CLIENTS; ++i)
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
    CHECK(answered(fd, CLIENTS) == CLIENTS && reports == 2);
    char reply[64];
    ssize_t n = read(fd[CLIENTS - 1], reply, sizeof reply - 1);
    CHECK(n > 0 && !strncmp(reply, "protocol=1\n", 11));
    for (unsigned i = 0; i < CLIENTS; ++i) close(fd[i]);
    unlink(status_path);
}

static bool fake_set(uid_t uid, const char *name, const char *value, char *why, size_t why_size) {
    ++set_calls;
    set_uid = uid;
    strlcpy(set_name, name, sizeof set_name);
    strlcpy(set_value, value, sizeof set_value);
    if (!strcmp(value, "maybe")) {
        snprintf(why, why_size, "%s must be yes or no", name);
        return false;
    }
    return true;
}

static int admin_connect(void) {
    return connect_to(admin_path);
}

/* Runs the daemon's run loop until the server closes the connection; the reply. */
static const char *admin_reply(int fd, char *reply, size_t size) {
    size_t used = 0;
    for (CFAbsoluteTime give_up = CFAbsoluteTimeGetCurrent() + 4; CFAbsoluteTimeGetCurrent() < give_up;) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 0) <= 0) continue;
        ssize_t n = read(fd, reply + used, size - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    reply[used] = 0;
    return reply;
}

static const char *admin_ask(const char *request, char *reply, size_t size) {
    int fd = admin_connect();
    CHECK(write(fd, request, strlen(request)) == (ssize_t)strlen(request));
    return admin_reply(fd, reply, size);
}

static void test_admin_socket(void) {
    /* nobody (-2) and admin (80) have fixed ids on macOS; getpwnam's records are not
     * aligned under Guard Malloc's exact-size allocations. */
    CHECK(admin_allowed(0, getgid()) && admin_allowed(getuid(), getgid()));
    CHECK(!admin_allowed((uid_t)-2, 80));

    snprintf(admin_path, sizeof admin_path, "%s/admin.sock", socket_dir);
    int old = open(admin_path, O_WRONLY | O_CREAT, 0644); /* a stale file at the name is replaced */
    CHECK(old >= 0);
    if (old >= 0) close(old);
    CHECK(admin_serve(socket_dir, admin_path, getgid(), fake_set));
    struct stat st;
    CHECK(!stat(admin_path, &st) && (st.st_mode & 0777) == 0660 && st.st_gid == getgid());

    char reply[512];
    CHECK(!strcmp(admin_ask("set prefer-phone no\n", reply, sizeof reply), "ok\n"));
    CHECK(set_calls == 1 && set_uid == getuid() && !strcmp(set_name, "prefer-phone") && !strcmp(set_value, "no"));
    CHECK(!strcmp(admin_ask("set verbose maybe\n", reply, sizeof reply), "error: verbose must be yes or no\n"));
    CHECK(!strncmp(admin_ask("get verbose\n", reply, sizeof reply), "error: expected", 15));
    CHECK(!strncmp(admin_ask("set verbose yes now\n", reply, sizeof reply), "error: expected", 15));
    CHECK(set_calls == 2);

    /* A line in pieces is put together; a line that never ends is refused. */
    int fd = admin_connect();
    CHECK(write(fd, "set verb", 8) == 8);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
    CHECK(write(fd, "ose yes\n", 8) == 8);
    CHECK(!strcmp(admin_reply(fd, reply, sizeof reply), "ok\n") && !strcmp(set_name, "verbose"));
    char endless[400];
    memset(endless, 'x', sizeof endless);
    endless[sizeof endless - 1] = 0;
    CHECK(!strcmp(admin_ask(endless, reply, sizeof reply), "error: request too long\n"));

    /* A client that leaves without a whole line, or says nothing: the next one is still served. */
    fd = admin_connect();
    CHECK(write(fd, "set ipv6", 8) == 8);
    shutdown(fd, SHUT_WR);
    CHECK(!strcmp(admin_reply(fd, reply, sizeof reply), ""));
    fd = admin_connect();
    CHECK(!strcmp(admin_reply(fd, reply, sizeof reply), "")); /* closed after the two-second timeout */
    CHECK(!strcmp(admin_ask("set prefer-phone yes\n", reply, sizeof reply), "ok\n") && set_calls == 4);
    unlink(admin_path);
    CHECK(!rmdir(socket_dir)); /* nothing else was left there */
}

int main(void) {
    test_tx_batching();
    test_tx_transfer_limit();
    test_rx_delivery();
    test_rx_abort_storm();
    test_reset_during_batch_flush();
    test_reset_filter_restore();
    test_keepalive();
    test_reset_limits();
    test_status_format();
    test_status_choose();
    test_runtime();
    test_status_socket();
    test_admin_socket();
    datapath_close(&data);
    close(macos);
    printf("sessiontest: %u checks, %u failures\n", tests, failures);
    return failures ? 1 : 0;
}
