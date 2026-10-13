/* The daemon's answer to `rndis-tether status`: "name=value" lines on a UNIX socket
 * (STATUS_SOCKET, mode 0666). The daemon writes one reply per connection and never
 * reads; cli.c turns the lines into words, other programs may read them too (README).
 */
#ifndef STATUS_H
#define STATUS_H

#include "session.h"

/* The first line, protocol=N: bumped when a field changes its meaning or goes away.
 * New fields do not bump it; readers skip names they do not know. */
#define STATUS_PROTOCOL 1

typedef struct {
    const char *state;            /* no-phone, unsupported, sleeping, retrying, connecting, online */
    bool prefer_phone;
    const char *phone;            /* NULL without a phone */
    const char *problem;          /* why the last attempt failed, or NULL */
    const char *settings_problem; /* a bad line in the settings file, or NULL */
    const SessionStatus *session; /* NULL without a session */
} StatusReport;

/* Never more than size - 1 bytes; always terminated. */
size_t status_format(const StatusReport *r, char *buffer, size_t size);
/* Answers every connection with report(); false if the socket cannot be set up. */
bool status_serve(size_t (*report)(char *buffer, size_t size));

#endif
