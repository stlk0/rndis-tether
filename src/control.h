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

#define CONTROL_QUEUE 8u /* requests waiting behind the current one */
#define CONTROL_SEND_TIMEOUT_MS 1000u /* one SEND_ENCAPSULATED_COMMAND on pipe 0 */
#define CONTROL_GET_TIMEOUT_MS   500u /* one GET_ENCAPSULATED_RESPONSE */
#define CONTROL_GET_RETRIES 3u /* GETs again after failed ones in a row: a response may still wait */

typedef enum { CONTROL_SUCCESS, CONTROL_DEVICE_STATUS, CONTROL_TIMEOUT, CONTROL_USB_ERROR,
               CONTROL_INVALID, CONTROL_SKIPPED } ControlResult;
typedef void (*ControlDone)(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset);

typedef struct {
    void (*message)(const uint8_t *message, size_t length); /* unsolicited: indication, device KEEPALIVE */
    void (*heard)(void);                                    /* the phone answered something */
    void (*failed)(const char *reason, IOReturn status);    /* the session cannot go on */
} ControlEvents;

typedef struct {
    uint8_t bytes[RNDIS_REQUEST_MAX];
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
    bool busy, pending;
    bool response_waiting; /* a response may be waiting: notification, or the last GET had data */
    unsigned get_errors_row; /* GETs failed in a row; up to CONTROL_GET_RETRIES are tried again */
    uint64_t deadline, poll_at;
    UsbTransfer transfer;
    uint8_t response[RNDIS_CONTROL_CAP];

    UsbTransfer notify_transfer;
    uint8_t notify[8]; /* RESPONSE_AVAILABLE notification */
    bool notify_pending;
    unsigned notify_errors_row;
    uint64_t usb_errors;
} Control;

/* RNDIS RequestId for a new request; never reused soon, also across sessions. */
uint32_t control_next_id(void);

void control_open(Control *c, UsbLink *u, const ControlEvents *events);
/* Synchronous request: SEND, then poll for the matching completion for up to EXCHANGE_TIMEOUT_MS (control.c).
 * Unrelated messages met on the way, also in the same reply before or after it, go to events->message. NULL
 * or a reason; *status is the USB status of a failed transfer. */
const char *control_exchange(Control *c, const uint8_t *request, size_t request_size, uint32_t type,
                             uint32_t id, uint8_t *response, size_t *response_size, IOReturn *status);
/* From bring-up to the running session: notifications and the pump start. */
void control_run(Control *c);
/* Queues a request (urgent: in front). Before control_run only SEND-only messages
 * are possible, and they are sent at once. False when the request was refused. */
bool control_send(Control *c, const ControlMessage *m, bool urgent);
/* Runs the pump now. Its timer and the completions call it; so do the tests. */
void control_kick(Control *c);
/* The running pump takes no further requests and makes no further callbacks, except
 * one: a USB failure that stops it through events->failed still finishes the request
 * it cut off (done with CONTROL_USB_ERROR). Completions still in flight are absorbed.
 * control_exchange, the synchronous bring-up path, does not look at it. */
void control_stop(Control *c);
void control_close(Control *c);

#endif
