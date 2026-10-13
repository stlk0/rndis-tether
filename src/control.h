/* The RNDIS control channel: encapsulated commands and responses on pipe 0, and the
 * interrupt IN endpoint on which the phone announces that a response is waiting.
 *
 * Bring-up is synchronous (control_exchange). Once the session runs (control_run),
 * one pump serializes all pipe-0 traffic: queued requests, polls for their
 * completions and drains of unsolicited messages (status indications, the phone's
 * own KEEPALIVE). Nothing else submits pipe-0 I/O, so no two exchanges interleave.
 */
#ifndef CONTROL_H
#define CONTROL_H

#include "rndis.h"
#include "usb.h"

#define CONTROL_QUEUE 8u

typedef enum { CONTROL_SUCCESS, CONTROL_DEVICE_STATUS, CONTROL_TIMEOUT, CONTROL_USB_ERROR,
               CONTROL_INVALID, CONTROL_SKIPPED } ControlResult;
typedef void (*ControlDone)(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset);

typedef struct {
    void (*message)(const uint8_t *message, size_t length); /* unsolicited: indication, device KEEPALIVE */
    void (*heard)(void);                                    /* the phone answered something */
    void (*failed)(const char *reason, IOReturn status);    /* the session cannot go on */
} ControlEvents;

typedef struct {
    uint8_t bytes[32];
    size_t length;
    uint32_t type, id;              /* type 0: SEND only, e.g. our reply to a device KEEPALIVE */
    bool (*wanted)(void *context);  /* asked just before sending; false: done(CONTROL_SKIPPED) */
    ControlDone done;
    void *context;
} ControlMessage;

typedef enum { CONTROL_IDLE, CONTROL_SEND, CONTROL_WAIT, CONTROL_GET } ControlState;

typedef struct {
    UsbLink *usb;
    const ControlEvents *events;
    bool running, stopped;
    CFRunLoopTimerRef timer;

    ControlMessage queue[CONTROL_QUEUE], current;
    unsigned count;
    ControlState state;
    bool busy, pending, notified;
    uint64_t deadline, poll_at;
    UsbTransfer transfer;
    uint8_t response[RNDIS_CONTROL_CAP];

    UsbTransfer notify_transfer;
    uint8_t notify[8];
    bool notify_pending;
    unsigned notify_errors_row;
    uint64_t usb_errors;
} Control;

/* RNDIS RequestId for a new request; never reused soon, also across sessions. */
uint32_t control_next_id(void);

void control_open(Control *c, UsbLink *u, const ControlEvents *events);
/* Synchronous request: SEND, then poll for the matching completion for up to 3 s.
 * Unrelated messages met on the way, also in the same reply, go to events->message. NULL or a reason; *status
 * is the USB status of a failed transfer. */
const char *control_exchange(Control *c, const uint8_t *request, size_t request_size, uint32_t type,
                             uint32_t id, uint8_t *response, size_t *response_size, IOReturn *status);
/* From bring-up to the running session: notifications and the pump start. */
void control_run(Control *c);
/* Queues a request (urgent: in front). Before control_run only SEND-only messages
 * are possible, and they are sent at once. False when the request was refused. */
bool control_send(Control *c, const ControlMessage *m, bool urgent);
/* Runs the pump now. Its timer and the completions call it; so do the tests. */
void control_kick(Control *c);
/* No further requests or callbacks; completions still in flight are absorbed. */
void control_stop(Control *c);
void control_close(Control *c);

#endif
