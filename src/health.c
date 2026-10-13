#include "health.h"
#include "clock.h"
#include "log.h"

#define RESET_DRAIN_MS 5000u /* bulk OUT must finish this soon after RESET is decided */

void health_start(Health *h, Control *c, Datapath *d, uint32_t packet_filter,
                  void (*failed)(const char *reason, IOReturn status)) {
    *h = (Health){.control = c, .data = d, .failed = failed, .packet_filter = packet_filter,
                  .last_heard_ms = now_ms()};
}

void health_stop(Health *h) {
    h->stopped = true;
}

void health_heard(Health *h) {
    h->last_heard_ms = now_ms();
}

/* --------------------------------------------------------------------- RESET */

static void filter_restored(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    (void)addressing_reset;
    Health *h = context;
    if (h->stopped) return;
    if (result != CONTROL_SUCCESS) {
        if (result == CONTROL_DEVICE_STATUS) logmsg("reset filter rejected: 0x%08x", status);
        h->failed("cannot restore packet filter after RESET", result == CONTROL_USB_ERROR ? (IOReturn)status : 0);
        return;
    }
    h->resetting = false;
    logmsg("soft RESET completed; resuming transmission");
    datapath_hold(h->data, false);
}

static void reset_done(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    Health *h = context;
    if (h->stopped) return;
    if (result != CONTROL_SUCCESS) {
        if (result == CONTROL_DEVICE_STATUS) logmsg("RESET rejected: 0x%08x", status);
        h->failed("soft RESET failed", result == CONTROL_USB_ERROR ? (IOReturn)status : 0);
        return;
    }
    if (!addressing_reset) {
        filter_restored(h, CONTROL_SUCCESS, 0, 0);
        return;
    }
    ControlMessage m = {.type = RNDIS_SET_MSG, .id = control_next_id(), .done = filter_restored, .context = h};
    m.length = rndis_build_set_u32(m.bytes, m.id, OID_GEN_CURRENT_PACKET_FILTER, h->packet_filter);
    (void)control_send(h->control, &m, false);
}

/* RESET goes out only after every bulk OUT write already submitted has finished. */
static void queue_reset(Health *h) {
    if (h->stopped || !h->resetting || h->reset_queued || !datapath_drained(h->data)) return;
    ControlMessage m = {.type = RNDIS_RESET_MSG, .done = reset_done, .context = h};
    m.length = rndis_build_reset(m.bytes);
    h->reset_queued = true;
    (void)control_send(h->control, &m, false);
}

void health_reset(Health *h, const char *reason) {
    if (h->stopped) return;
    uint64_t now = now_ms();
    RndisHealthAction action = rndis_reset_decision(now, h->last_reset_ms, h->reset_attempted, h->resetting);
    if (action == RNDIS_HEALTH_OK) return;
    if (action == RNDIS_HEALTH_RESTART) {
        h->failed("another RESET needed within 30 seconds", kIOReturnSuccess);
        return;
    }
    h->reset_attempted = h->resetting = true;
    h->reset_queued = false;
    h->last_reset_ms = now;
    ++h->resets;
    logmsg("soft RESET: %s", reason);
    datapath_hold(h->data, true);
    queue_reset(h);
}

void health_drained(Health *h) {
    queue_reset(h);
}

/* ----------------------------------------------------------------- KEEPALIVE */

/* Traffic may have resumed while KEEPALIVE waited behind another request. */
static bool keepalive_wanted(void *context) {
    Health *h = context;
    return !h->resetting && rndis_keepalive_due(now_ms(), h->last_heard_ms, false);
}

static void keepalive_done(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    (void)addressing_reset;
    Health *h = context;
    h->keepalive_outstanding = false;
    if (h->stopped || result == CONTROL_SKIPPED) return;
    RndisHealthAction action = rndis_keepalive_result(&h->keepalive_failures,
        result == CONTROL_SUCCESS || result == CONTROL_DEVICE_STATUS, status);
    if (action == RNDIS_HEALTH_RESET) health_reset(h, "phone rejected KEEPALIVE");
    else if (action == RNDIS_HEALTH_RESTART) h->failed("phone stopped responding to keepalive", kIOReturnSuccess);
    else if (result != CONTROL_SUCCESS) logdebug("keepalive failed (%u/3)", h->keepalive_failures);
    else logdebug("keepalive answered");
}

void health_tick(Health *h) {
    if (h->stopped) return;
    uint64_t now = now_ms();
    if (!h->resetting && rndis_keepalive_due(now, h->last_heard_ms, h->keepalive_outstanding)) {
        ControlMessage m = {.type = RNDIS_KEEPALIVE_MSG, .id = control_next_id(), .wanted = keepalive_wanted,
                            .done = keepalive_done, .context = h};
        m.length = rndis_build_keepalive(m.bytes, m.id);
        h->keepalive_outstanding = true;
        (void)control_send(h->control, &m, false);
    }
    if (h->resetting && !h->reset_queued && now - h->last_reset_ms >= RESET_DRAIN_MS)
        h->failed("bulk OUT did not drain before RESET", kIOReturnSuccess);
}
