/* Keeping the phone's RNDIS function alive: KEEPALIVE after silence, and the soft
 * RESET that clears a stuck function without losing the interface or the lease.
 *
 * RESET waits until every bulk OUT write has finished, sends RESET_MSG, restores the
 * packet filter if the phone asks for it, then lets traffic flow again. A second need
 * for RESET within RNDIS_RESET_WINDOW_S, or RNDIS_KEEPALIVE_MISSES unanswered
 * KEEPALIVEs in a row, end the session (rndis.h).
 */
#ifndef HEALTH_H
#define HEALTH_H

#include "control.h"
#include "datapath.h"

/* Where a soft RESET stands. Traffic is held in every step but the first. */
typedef enum {
    RESET_IDLE,     /* no RESET under way: traffic flows */
    RESET_DRAINING, /* waiting for the bulk OUT writes in flight */
    RESET_SENT,     /* RESET_MSG is queued or awaits its completion */
    RESET_FILTER,   /* the phone reset its addressing: the packet filter is being set again */
} ResetStep;

typedef struct {
    Control *control;
    Datapath *data;
    void (*failed)(const char *reason, IOReturn status);
    uint32_t packet_filter;
    uint64_t last_heard_ms, last_reset_ms;
    ResetStep reset;
    bool keepalive_outstanding, stopped;
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
