/* Keeping the phone's RNDIS function alive: KEEPALIVE after silence, and the soft
 * RESET that clears a stuck function without losing the interface or the lease.
 *
 * RESET waits until every bulk OUT write has finished, sends RESET_MSG, restores the
 * packet filter if the phone asks for it, then lets traffic flow again. A second need
 * for RESET within 30 seconds, or three unanswered KEEPALIVEs, end the session.
 */
#ifndef HEALTH_H
#define HEALTH_H

#include "control.h"
#include "datapath.h"

typedef struct {
    Control *control;
    Datapath *data;
    void (*failed)(const char *reason, IOReturn status);
    uint32_t packet_filter;
    uint64_t last_heard_ms, last_reset_ms;
    bool keepalive_outstanding, resetting, reset_queued, reset_attempted, stopped;
    unsigned keepalive_failures, resets;
} Health;

void health_start(Health *h, Control *c, Datapath *d, uint32_t packet_filter,
                  void (*failed)(const char *reason, IOReturn status));
/* The phone sent something: no KEEPALIVE needed for a while. */
void health_heard(Health *h);
/* About once a second: KEEPALIVE when due, and the RESET drain deadline. */
void health_tick(Health *h);
void health_reset(Health *h, const char *reason);
/* The data path reports that bulk OUT drained while held. */
void health_drained(Health *h);
void health_stop(Health *h);

#endif
