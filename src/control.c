#include "control.h"
#include "clock.h"
#include "log.h"

#include <string.h>

#define EXCHANGE_TIMEOUT_MS 3000u /* synchronous bring-up request */
#define REQUEST_TIMEOUT_MS 5000u  /* queued request, from SEND to its completion */
#define SEND_POLL_DELAY_MS 250u   /* first GET after SEND when no notification arrives */
#define GET_RETRY_MS 20u          /* "not ready yet" */

static uint32_t last_id;

uint32_t control_next_id(void) {
    if (++last_id == 0) last_id = 1;
    return last_id;
}

static void timer_fired(CFRunLoopTimerRef timer, void *info);

void control_open(Control *c, UsbLink *u, const ControlEvents *events) {
    *c = (Control){.usb = u, .events = events};
    c->timer = timer_new(timer_fired, c, 0, 0);
}

void control_stop(Control *c) {
    c->stopped = true;
    if (c->timer) timer_disarm(c->timer);
}

void control_close(Control *c) {
    control_stop(c);
    if (c->timer) {
        CFRunLoopTimerInvalidate(c->timer);
        CFRelease(c->timer);
        c->timer = NULL;
    }
}

/* A reply usually holds one message but may hold several: true and the length of the
 * one at offset at; false at the end or at a malformed one. */
static bool next_message(const uint8_t *b, size_t n, size_t at, size_t *length) {
    if (at >= n) return false;
    if (!rndis_control_type(b + at, n - at)) {
        logdebug("ignored malformed control response (%zu bytes)", n - at);
        return false;
    }
    *length = rndis_le32(b + at + 4);
    return true;
}

const char *control_exchange(Control *c, const uint8_t *request, size_t request_size, uint32_t type,
                             uint32_t id, uint8_t *response, size_t *response_size, IOReturn *status) {
    *status = usb_send_encapsulated(c->usb, request, (uint16_t)request_size, 1000);
    if (*status) return "control command was not accepted";
    uint64_t deadline = now_ms() + EXCHANGE_TIMEOUT_MS;
    while (now_ms() < deadline) {
        uint32_t got = 0;
        IOReturn r = usb_get_encapsulated(c->usb, response, RNDIS_CONTROL_CAP, &got, 500);
        if (r && usb_fatal(r)) {
            *status = r;
            return "control response failed";
        }
        /* An empty reply, a single zero byte or a control-pipe stall all mean "not ready yet". */
        if (r == kIOReturnSuccess && got && !(got == 1 && response[0] == 0)) {
            c->events->heard();
            size_t length = 0;
            for (size_t at = 0; next_message(response, got, at, &length); at += length) {
                if (rndis_completion_matches(response + at, length, type, id)) {
                    memmove(response, response + at, length);
                    *response_size = length;
                    return NULL;
                }
                c->events->message(response + at, length);
            }
            continue;
        }
        sleep_ms(GET_RETRY_MS);
    }
    return "device did not answer a control request";
}

/* ------------------------------------------------------------ the running pump */

static void finish(Control *c, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    ControlMessage m = c->current;
    c->busy = false;
    c->state = CONTROL_IDLE;
    if (m.done) m.done(m.context, result, status, addressing_reset);
}

bool control_send(Control *c, const ControlMessage *m, bool urgent) {
    if (c->stopped) return false;
    if (!c->running) { /* bring-up: only replies, sent at once */
        if (m->type) return false;
        IOReturn r = usb_send_encapsulated(c->usb, m->bytes, (uint16_t)m->length, 1000);
        if (r && usb_fatal(r)) c->events->failed("control reply failed", r);
        if (m->done) m->done(m->context, r ? CONTROL_USB_ERROR : CONTROL_SUCCESS, (uint32_t)r, 0);
        return !r;
    }
    if (m->length > sizeof c->current.bytes || c->count == CONTROL_QUEUE) {
        if (m->done) m->done(m->context, CONTROL_USB_ERROR, (uint32_t)kIOReturnNoResources, 0);
        c->events->failed("control queue overflow", kIOReturnNoResources);
        return false;
    }
    unsigned at = urgent ? 0 : c->count;
    if (urgent) memmove(c->queue + 1, c->queue, c->count * sizeof *c->queue);
    c->queue[at] = *m;
    ++c->count;
    timer_set(c->timer, 0.001);
    return true;
}

static void dispatch(Control *c, const uint8_t *b, size_t n) {
    if (c->busy && rndis_completion_matches(b, n, c->current.type, c->current.id)) {
        uint32_t status = 0, addressing_reset = 0;
        const char *e = c->current.type == RNDIS_RESET_MSG ?
            rndis_parse_reset_cmplt(b, n, &status, &addressing_reset) :
            rndis_parse_status_cmplt(b, n, c->current.type, c->current.id, &status);
        if (e) {
            logdebug("invalid control response: %s", e);
            finish(c, CONTROL_INVALID, 0, 0);
        } else {
            finish(c, status ? CONTROL_DEVICE_STATUS : CONTROL_SUCCESS, status, addressing_reset);
        }
    } else {
        c->events->message(b, n);
    }
}

static void transfer_done(UsbTransfer *t, IOReturn status, size_t n) {
    Control *c = USB_OWNER(t, Control, transfer);
    bool sending = c->state == CONTROL_SEND;
    c->pending = false;
    if (c->stopped) return;
    if (!status && (n > t->request.wLength || (sending && n != c->current.length)))
        status = n > t->request.wLength ? kIOReturnOverrun : kIOReturnUnderrun;
    if (usb_fatal(status)) {
        c->events->failed("control endpoint failed", status);
        if (c->busy) finish(c, CONTROL_USB_ERROR, (uint32_t)status, 0);
        return;
    }
    uint64_t now = now_ms();
    bool expired = c->busy && now >= c->deadline;
    if (expired) finish(c, CONTROL_TIMEOUT, 0, 0);
    if (status && !(!sending && status == kIOUSBPipeStalled)) {
        ++c->usb_errors;
        if (c->busy) finish(c, CONTROL_USB_ERROR, (uint32_t)status, 0);
        else logdebug("idle control GET failed: 0x%08x", status);
    } else if (sending) {
        if (!expired) {
            if (!c->current.type) finish(c, CONTROL_SUCCESS, 0, 0);
            else c->poll_at = now + SEND_POLL_DELAY_MS; /* devices without notifications still make progress */
        }
    } else if (!status && n && !(n == 1 && c->response[0] == 0)) {
        c->events->heard();
        size_t length = 0;
        for (size_t at = 0; !c->stopped && next_message(c->response, n, at, &length); at += length)
            dispatch(c, c->response + at, length);
        c->notified = true; /* drain what follows, including unsolicited messages while idle */
    } else {
        c->poll_at = now + GET_RETRY_MS; /* empty reply, single zero, or stall: not ready yet */
    }
    c->state = c->busy ? CONTROL_WAIT : CONTROL_IDLE;
    control_kick(c);
}

static void submit(Control *c, bool in, uint64_t now) {
    uint32_t timeout = in ? 500 : 1000;
    if (c->busy && c->deadline - now < timeout) timeout = (uint32_t)(c->deadline - now);
    c->state = in ? CONTROL_GET : CONTROL_SEND;
    if (in) c->notified = false;
    c->transfer.done = transfer_done;
    IOReturn r = in ? usb_control(c->usb, &c->transfer, true, c->response, sizeof c->response, timeout) :
                      usb_control(c->usb, &c->transfer, false, c->current.bytes, (uint16_t)c->current.length, timeout);
    if (r) {
        ++c->usb_errors;
        if (usb_fatal(r)) c->events->failed("cannot queue control request", r);
        if (c->busy) finish(c, CONTROL_USB_ERROR, (uint32_t)r, 0);
        c->state = CONTROL_IDLE;
        if (!c->stopped) timer_set(c->timer, GET_RETRY_MS / 1000.0);
        return;
    }
    c->pending = true;
}

/* Callbacks and the timer return here; it alone decides what goes on pipe 0 next. */
void control_kick(Control *c) {
    if (!c->running || c->stopped || c->pending) return;
    timer_disarm(c->timer);
    uint64_t now = now_ms();
    if (c->busy && now >= c->deadline) finish(c, CONTROL_TIMEOUT, 0, 0);
    if (c->stopped) return;
    if (!c->busy && c->count) {
        c->current = c->queue[0];
        --c->count;
        memmove(c->queue, c->queue + 1, c->count * sizeof *c->queue);
        c->busy = true;
        if (c->current.wanted && !c->current.wanted(c->current.context)) {
            finish(c, CONTROL_SKIPPED, 0, 0);
            if (!c->stopped) timer_set(c->timer, 0.001);
            return;
        }
        c->deadline = now + REQUEST_TIMEOUT_MS;
        submit(c, false, now);
    } else if (c->notified || (c->busy && now >= c->poll_at)) {
        submit(c, true, now);
    } else if (c->busy) {
        uint64_t wake = c->poll_at < c->deadline ? c->poll_at : c->deadline;
        timer_set(c->timer, (double)(wake - now) / 1000.0);
    }
}

static void timer_fired(CFRunLoopTimerRef timer, void *info) {
    (void)timer;
    control_kick(info);
}

/* ------------------------------------------------------- interrupt IN endpoint */

static void notify_arm(Control *c);

static void notify_done(UsbTransfer *t, IOReturn status, size_t n) {
    Control *c = USB_OWNER(t, Control, notify_transfer);
    c->notify_pending = false;
    if (c->stopped) return;
    if (status == kIOReturnSuccess) {
        c->notify_errors_row = 0;
        if (n) {
            c->notified = true; /* RESPONSE_AVAILABLE may arrive before SEND completes */
            control_kick(c);
        }
    } else { /* nothing of ours aborts this pipe while the session runs */
        if (usb_fatal(status)) {
            c->events->failed("notification endpoint failed", status);
            return;
        }
        ++c->usb_errors;
        if (status == kIOUSBPipeStalled || status == kIOUSBTransactionTimeout) usb_clear_stall(c->usb, USB_NOTIFY);
        if (++c->notify_errors_row > USB_ERROR_BURST) {
            c->events->failed("notification endpoint keeps failing", status);
            return;
        }
    }
    if (!c->stopped) notify_arm(c);
}

static void notify_arm(Control *c) {
    if (c->notify_pending) return;
    c->notify_transfer.done = notify_done;
    IOReturn r = usb_read(c->usb, USB_NOTIFY, &c->notify_transfer, c->notify, sizeof c->notify);
    if (r) {
        c->events->failed("cannot read notification endpoint", r);
        return;
    }
    c->notify_pending = true;
}

void control_run(Control *c) {
    if (c->stopped) return;
    c->running = true;
    notify_arm(c);
}
