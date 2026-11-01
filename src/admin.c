#include "admin.h"
#include "clock.h"
#include "runtime.h"

#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <membership.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUEST_MAX 256u
#define REQUEST_TIMEOUT_S 2.0 /* for a client to send its line */
#define DENIED_REPLY ADMIN_REPLY_ERROR ADMIN_DENIED_REASON "\n"

/* One connection at a time: accepting pauses while a request is being read. */
typedef struct {
    int listener;
    gid_t gid;
    AdminSet set;
    dispatch_source_t accepting, reading;
    CFRunLoopTimerRef timeout;
    int fd;
    uid_t uid;
    char request[REQUEST_MAX];
    size_t used;
} Server;

static Server a;

bool admin_allowed(uid_t uid, gid_t gid) {
    uuid_t user, group;
    int member = 0;
    return uid == 0 || (!mbr_uid_to_uuid(uid, user) && !mbr_gid_to_uuid(gid, group) &&
                        !mbr_check_membership(user, group, &member) && member);
}

static void close_connection(void *context) {
    close((int)(intptr_t)context);
}

/* The reply fits the socket buffer, so the write never blocks. */
static void finish(const char *reply) {
    timer_disarm(a.timeout);
    if (reply) (void)write(a.fd, reply, strlen(reply));
    dispatch_source_cancel(a.reading); /* its cancel handler closes the connection */
    dispatch_release(a.reading);
    a.reading = NULL;
    dispatch_resume(a.accepting);
}

static void answer(void) {
    char verb[8], name[64], value[64], extra, why[200], reply[300];
    if (sscanf(a.request, "%7s %63s %63s %c", verb, name, value, &extra) != 3 || strcmp(verb, ADMIN_VERB_SET))
        strlcpy(reply, ADMIN_REPLY_ERROR "expected \"set <name> <value>\"\n", sizeof reply);
    else if (!a.set(a.uid, name, value, why, sizeof why))
        snprintf(reply, sizeof reply, ADMIN_REPLY_ERROR "%s\n", why);
    else
        strlcpy(reply, ADMIN_REPLY_OK, sizeof reply);
    finish(reply);
}

static void readable(void *context) {
    (void)context;
    ssize_t n = read(a.fd, a.request + a.used, sizeof a.request - 1 - a.used);
    if (n < 0 && errno == EAGAIN) return;
    if (n <= 0) { /* gone without a whole line */
        finish(NULL);
        return;
    }
    a.used += (size_t)n;
    a.request[a.used] = 0;
    char *end = strchr(a.request, '\n');
    if (end) {
        *end = 0;
        answer();
    } else if (a.used == sizeof a.request - 1) {
        finish(ADMIN_REPLY_ERROR "request too long\n");
    }
}

static void timed_out(CFRunLoopTimerRef timer, void *info) {
    (void)timer;
    (void)info;
    if (a.reading) finish(NULL);
}

static void accept_one(void *context) {
    (void)context;
    int fd = accept(a.listener, NULL, NULL);
    if (fd < 0) return;
    int one = 1;
    gid_t group;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    if (getpeereid(fd, &a.uid, &group) || !admin_allowed(a.uid, a.gid)) {
        (void)write(fd, DENIED_REPLY, sizeof DENIED_REPLY - 1);
        close(fd);
        return;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK)) {
        close(fd);
        return;
    }
    a.reading = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, dispatch_get_main_queue());
    if (!a.reading) {
        close(fd);
        return;
    }
    a.fd = fd;
    a.used = 0;
    dispatch_set_context(a.reading, (void *)(intptr_t)fd);
    dispatch_source_set_event_handler_f(a.reading, readable);
    dispatch_source_set_cancel_handler_f(a.reading, close_connection);
    dispatch_suspend(a.accepting);
    dispatch_resume(a.reading);
    timer_set(a.timeout, REQUEST_TIMEOUT_S);
}

bool admin_serve(const char *dir, const char *path, gid_t gid, AdminSet set) {
    int fd = runtime_listen(dir, path, gid, 0660);
    if (fd < 0) return false;
    a = (Server){.listener = fd, .gid = gid, .set = set, .fd = -1};
    a.timeout = timer_new(timed_out, NULL, 0, 0.1);
    a.accepting = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, dispatch_get_main_queue());
    if (!a.timeout || !a.accepting) {
        close(fd);
        unlink(path);
        return false;
    }
    dispatch_source_set_event_handler_f(a.accepting, accept_one);
    dispatch_resume(a.accepting);
    return true;
}
