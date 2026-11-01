/* The daemon's answer to `rndis-tether status`: "name=value" lines on a UNIX socket
 * (STATUS_SOCKET, root's, mode 0666). The daemon writes one reply per connection and
 * never reads; cli.c turns the lines into words, other programs may read them too (README).
 */
#ifndef STATUS_H
#define STATUS_H

#include "session.h"

/* The first line, protocol=N: bumped when a field changes its meaning or goes away.
 * New fields do not bump it; readers skip names they do not know. */
#define STATUS_PROTOCOL 1
#define STATUS_ACCEPT_BATCH 8u /* connections served per run-loop event */
#define STATUS_TEXT_SIZE 2048 /* a whole status reply, terminator included */

/* Values of state= in the public status protocol (README). */
#define STATUS_STATE_PAUSED "paused"
#define STATUS_STATE_NO_PHONE "no-phone"
#define STATUS_STATE_UNSUPPORTED "unsupported"
#define STATUS_STATE_SLEEPING "sleeping"
#define STATUS_STATE_RETRYING "retrying"
#define STATUS_STATE_CONNECTING "connecting"
#define STATUS_STATE_ONLINE "online"

typedef struct {
    const char *state;            /* one of STATUS_STATE_* */
    bool prefer_phone, paused;
    const char *phone;            /* NULL without a phone */
    const char *problem;          /* why the last attempt failed, or NULL */
    const char *settings_problem; /* a bad line in the settings file, or NULL */
    const SessionStatus *session; /* NULL without a session */
} StatusReport;

/* What the daemon knows, before it is turned into a report. */
typedef struct {
    const char *phone;            /* NULL without a phone */
    bool rejected; /* the phone in hand is refused (state=unsupported) */
    bool sleeping; /* the Mac is going to sleep or asleep */
    bool paused;   /* rndis-tether disconnect; runtime only */
    const char *last_failure;     /* why the last attempt failed; "" when it did not */
    const SessionStatus *session; /* NULL without a session */
} StatusFacts;

/* Sets state, paused, phone, problem and session of r. Paused comes before every other
 * state and shows neither a problem nor a session: the teardown follows just after. */
void status_choose(const StatusFacts *f, StatusReport *r);
/* Never more than size - 1 bytes; always terminated. */
size_t status_format(const StatusReport *r, char *buffer, size_t size);
/* Answers every connection at path with report(); the socket is prepared in dir
 * (runtime.h). False if it cannot be set up. */
bool status_serve(const char *dir, const char *path, size_t (*report)(char *buffer, size_t size));

#endif
