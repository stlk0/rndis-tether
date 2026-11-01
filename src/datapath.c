#include "datapath.h"
#include "log.h"
#include "netif.h"

#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOGGED_ERRORS 5u /* per session and kind; the rest only go to the statistics */
#define TRACE_FRAMES 20u /* verbose: the first frames in each direction, one line each */
#define IPV4_HEADER_MIN 20u /* without options */
#define ARP_IPV4_LENGTH 28u /* ARP over Ethernet for IPv4 */

static RxSlot rx_slots[RX_SLOTS];
static TxSlot tx_slots[TX_SLOTS];
static uint8_t bpf_buffer[BPF_BUFFER];

/* The first LOGGED_ERRORS of a kind per session, or all with --verbose; count is how many came before. */
static bool error_is_logged(uint64_t count) {
    return count < LOGGED_ERRORS || log_verbose;
}

/* BPF is read when a burst fits into free TX slots; with the link down every frame is
 * dropped anyway, so reads go on to drain macOS's queue. Never while held (RESET). */
static bool bpf_reads_allowed(const Datapath *d) {
    return !d->held && (d->link_down || d->free_count >= TX_READ_MIN);
}

static void trace_frame(const char *direction, unsigned *count, const uint8_t *f, size_t n) {
    if (!log_verbose || *count >= TRACE_FRAMES || n < ETH_HEADER) return;
    ++*count;
    char detail[96] = "";
    unsigned type = (unsigned)f[12] << 8 | f[13];
    if (type == ETHERTYPE_IP && n >= ETH_HEADER + IPV4_HEADER_MIN) {
        const uint8_t *ip = f + ETH_HEADER;
        size_t ihl = (size_t)(ip[0] & 15u) * 4;
        int used = snprintf(detail, sizeof detail, " IPv4 %u.%u.%u.%u -> %u.%u.%u.%u proto %u",
                            ip[12], ip[13], ip[14], ip[15], ip[16], ip[17], ip[18], ip[19], ip[9]);
        if ((ip[9] == IPPROTO_UDP || ip[9] == IPPROTO_TCP) && n >= ETH_HEADER + ihl + 4 && used > 0)
            snprintf(detail + used, sizeof detail - (size_t)used, " ports %u -> %u",
                     (unsigned)ip[ihl] << 8 | ip[ihl + 1], (unsigned)ip[ihl + 2] << 8 | ip[ihl + 3]);
    } else if (type == ETHERTYPE_ARP && n >= ETH_HEADER + ARP_IPV4_LENGTH) {
        const uint8_t *a = f + ETH_HEADER;
        snprintf(detail, sizeof detail, " ARP op %u %u.%u.%u.%u -> %u.%u.%u.%u", a[7],
                 a[14], a[15], a[16], a[17], a[24], a[25], a[26], a[27]);
    }
    logdebug("%s %zu bytes %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x type 0x%04x%s",
             direction, n, f[6], f[7], f[8], f[9], f[10], f[11], f[0], f[1], f[2], f[3], f[4], f[5], type, detail);
}

/* The phone's MTU plus the Ethernet header and an optional VLAN tag. */
static bool frame_too_long(const Datapath *d, size_t n) {
    return n > ETH_HEADER + d->limits.mtu + ETH_VLAN_TAG;
}

static void suspend_bpf_reads(Datapath *d) {
    if (!d->bpf_suspended && d->source) { d->bpf_suspended = true; dispatch_suspend(d->source); }
}

static void resume_bpf_reads(Datapath *d) {
    if (d->bpf_suspended && d->source) { d->bpf_suspended = false; dispatch_resume(d->source); }
}

/* A failed transfer, counted towards a burst: half a burst asks for RESET, a full one ends the session. */
static void transfer_error(Datapath *d, unsigned *row, const char *burst, const char *fatal, IOReturn status) {
    ++d->stats.usb_errors;
    if (++*row >= USB_ERROR_BURST) d->events->failed(fatal, status);
    else if (*row == USB_ERROR_BURST / 2) d->events->errors(burst);
}

/* --------------------------------------------------------------- phone -> Mac */

static void bpf_deliver(Datapath *d, const uint8_t *data, size_t n, unsigned frames, size_t bytes) {
    if (write(d->bpf, data, n) == (ssize_t)n) {
        d->stats.rx_frames += frames;
        d->stats.rx_bytes += bytes;
        return;
    }
    int error = errno;
    d->stats.bpf_errors += frames;
    if (error_is_logged(d->bpf_failed_writes)) logmsg("BPF write failed: %s", strerror(error));
    ++d->bpf_failed_writes;
    if (d->bpf_batch && error == EINVAL) { /* this kernel does not take our records after all */
        d->bpf_batch = !bpf_set_batch_write(d->bpf, false);
        logmsg("BPF batch write rejected; delivering frames one by one");
    }
}

/* Every frame of one USB transfer reaches macOS in one write() when the kernel allows
 * batches; a write per frame was the daemon's largest cost at 10k frames/s. */
static void deliver(Datapath *d, const uint8_t *buffer, size_t n) {
    static uint8_t batch[RNDIS_RX_TRANSFER]; /* a BPF record is smaller than an RNDIS message */
    size_t used = 0, batch_bytes = 0;
    unsigned batch_frames = 0;
    RndisCursor cursor = {buffer, n};
    const uint8_t *frame = NULL;
    size_t length = 0;
    const char *why = NULL;
    RndisFrameResult r;
    while ((r = rndis_next_frame(&cursor, &frame, &length, &why)) != RNDIS_FRAMES_END) {
        if (r == RNDIS_FRAMES_MALFORMED) {
            if (error_is_logged(d->stats.rx_malformed)) logmsg("dropped malformed data from phone: %s", why);
            ++d->stats.rx_malformed;
            break;
        }
        if (r == RNDIS_FRAME_SKIPPED || frame_too_long(d, length)) { ++d->stats.rx_dropped; continue; }
        trace_frame("phone->Mac", &d->traced_rx, frame, length);
        size_t added = d->bpf_batch ? bpf_put(batch, used, sizeof batch, frame, length) : 0;
        if (added) {
            used += added;
            ++batch_frames;
            batch_bytes += length;
        } else {
            bpf_deliver(d, frame, length, 1, length);
        }
    }
    if (used) bpf_deliver(d, batch, used, batch_frames, batch_bytes);
}

static IOReturn rx_arm(RxSlot *slot);

static void rx_done(UsbTransfer *t, IOReturn status, size_t n) {
    RxSlot *slot = USB_OWNER(t, RxSlot, usb);
    Datapath *d = slot->owner;
    if (d->stopped) return;
    if (status == kIOReturnSuccess) {
        d->rx_errors_row = d->rx_aborted_row = 0;
        if (n) {
            ++d->stats.rx_transfers;
            d->events->heard();
        }
        if (n <= sizeof slot->buffer) deliver(d, slot->buffer, n);
    } else if (status == kIOReturnAborted) {
        /* Our own stall recovery aborts the other reads: at most RX_SLOTS - 1 per counted
         * error. More than that without data means the pipe is stuck and would spin here. */
        if (++d->rx_aborted_row > RX_SLOTS * USB_ERROR_BURST) {
            d->events->failed("bulk IN reads keep being aborted", status);
            return;
        }
    } else {
        if (usb_fatal(status)) {
            d->events->failed("phone stopped sending (bulk IN)", status);
            return;
        }
        if (error_is_logged(d->stats.usb_errors)) logmsg("bulk IN error 0x%08x, recovering", status);
        if (usb_needs_clear(status)) usb_clear_stall(d->usb, USB_BULK_IN);
        transfer_error(d, &d->rx_errors_row, "bulk IN error burst", "bulk IN keeps failing", status);
    }
    if (d->stopped) return;
    IOReturn r = rx_arm(slot);
    if (r) d->events->failed("cannot queue bulk IN read", r);
}

static IOReturn rx_arm(RxSlot *slot) {
    slot->usb.done = rx_done;
    return usb_read(slot->owner->usb, USB_BULK_IN, &slot->usb, slot->buffer, sizeof slot->buffer);
}

/* --------------------------------------------------------------- Mac -> phone */

static void tx_release(Datapath *d, TxSlot *slot) {
    d->free_tx[d->free_count++] = slot;
}

static TxSlot *tx_take(Datapath *d) { /* NULL when every slot is in flight */
    if (!d->free_count) return NULL;
    TxSlot *slot = d->free_tx[--d->free_count];
    slot->used = slot->frame_bytes = 0;
    slot->packets = 0;
    return slot;
}

static void tx_done(UsbTransfer *t, IOReturn status, size_t n) {
    (void)n;
    TxSlot *slot = USB_OWNER(t, TxSlot, usb);
    Datapath *d = slot->owner;
    if (d->stopped) return;
    tx_release(d, slot);
    if (status == kIOReturnSuccess) {
        d->tx_errors_row = 0;
        ++d->stats.tx_transfers;
        d->stats.tx_frames += slot->packets;
        d->stats.tx_bytes += slot->frame_bytes;
    } else {
        d->stats.tx_dropped += slot->packets;
        if (status != kIOReturnAborted) {
            if (usb_fatal(status)) {
                d->events->failed("phone stopped receiving (bulk OUT)", status);
                return;
            }
            if (error_is_logged(d->stats.usb_errors)) logmsg("bulk OUT error 0x%08x, recovering", status);
            if (usb_needs_clear(status)) usb_clear_stall(d->usb, USB_BULK_OUT);
            transfer_error(d, &d->tx_errors_row, "bulk OUT error burst", "bulk OUT keeps failing", status);
        }
    }
    if (d->stopped) return;
    if (d->held) {
        if (datapath_drained(d)) d->events->drained();
    } else if (bpf_reads_allowed(d)) {
        resume_bpf_reads(d);
    }
}

void datapath_flush(Datapath *d) {
    TxSlot *slot = d->filling;
    if (!slot) return;
    d->filling = NULL;
    size_t length = rndis_finish_transfer(slot->buffer, slot->used, sizeof slot->buffer, d->usb->out_packet_size);
    slot->usb.done = tx_done;
    IOReturn r = usb_write(d->usb, &slot->usb, slot->buffer, (uint32_t)length);
    if (!r) return;
    tx_release(d, slot);
    d->stats.tx_dropped += slot->packets;
    if (usb_fatal(r)) d->events->failed("cannot queue bulk OUT write", r);
    else transfer_error(d, &d->tx_errors_row, "bulk OUT submission error burst", "bulk OUT keeps failing", r);
}

void datapath_send(Datapath *d, const uint8_t *frame, size_t n) {
    if (d->stopped || d->link_down || d->held) { ++d->stats.tx_dropped; return; }
    trace_frame("Mac->phone", &d->traced_tx, frame, n);
    if (n < ETH_HEADER || frame_too_long(d, n)) { ++d->stats.tx_dropped; return; }
    for (int attempt = 0; attempt < 2; ++attempt) {
        /* A failing flush can end the session or start RESET in the middle of a batch. */
        if (d->stopped || d->held) { ++d->stats.tx_dropped; return; }
        if (!d->filling) {
            d->filling = tx_take(d);
            if (!d->filling) { ++d->stats.tx_dropped; return; }
        }
        TxSlot *slot = d->filling;
        size_t added = rndis_append_packet(slot->buffer, slot->used, d->tx_limit, frame, n,
                                           d->limits.alignment_shift);
        if (added) {
            slot->used += added;
            slot->frame_bytes += n;
            if (++slot->packets >= d->limits.batch_limit) datapath_flush(d);
            return;
        }
        if (!slot->packets) { /* larger than the phone accepts in one transfer */
            tx_release(d, slot);
            d->filling = NULL;
            ++d->stats.tx_dropped;
            return;
        }
        datapath_flush(d); /* transfer full; the frame goes into a fresh one */
    }
}

/* One read per event: the source fires again while BPF still holds frames, and a
 * second read in a loop would mostly return EAGAIN, one wasted syscall per wakeup. */
static void bpf_readable(void *context) {
    Datapath *d = context;
    if (d->stopped) return;
    /* Resumed by tx_done, by the end of RESET (datapath_hold) or when the link goes down (datapath_set_link). */
    if (!bpf_reads_allowed(d)) { suspend_bpf_reads(d); return; }
    ssize_t n = read(d->bpf, bpf_buffer, d->bpf_size);
    if (n < 0) {
        if (errno != EAGAIN && errno != EINTR) d->events->failed("reading frames from macOS failed", kIOReturnSuccess);
        return;
    }
    BpfCursor cursor = {bpf_buffer, (size_t)n};
    const uint8_t *frame = NULL;
    size_t length = 0;
    bool truncated = false;
    while (bpf_next(&cursor, &frame, &length, &truncated)) {
        if (truncated) ++d->stats.tx_dropped;
        else datapath_send(d, frame, length);
    }
    datapath_flush(d);
}

static void bpf_cancelled(void *context) {
    close((int)(intptr_t)context);
}

/* ------------------------------------------------------------------- control */

const char *datapath_start(Datapath *d, UsbLink *u, int bpf, unsigned bpf_size, const DatapathLimits *limits,
                           const DatapathEvents *events) {
    *d = (Datapath){.usb = u, .events = events, .limits = *limits, .bpf = bpf,
                    .bpf_size = bpf_size < BPF_BUFFER ? bpf_size : BPF_BUFFER};
    d->tx_limit = rndis_transfer_limit(limits->max_transfer, TX_BUFFER, u->out_packet_size);
    d->bpf_batch = bpf_set_batch_write(bpf, true);
    for (unsigned i = 0; i < TX_SLOTS; ++i) {
        tx_slots[i].owner = d;
        tx_release(d, &tx_slots[i]);
    }
    for (unsigned i = 0; i < RX_SLOTS; ++i) {
        rx_slots[i].owner = d;
        if (rx_arm(&rx_slots[i])) return "cannot queue bulk IN read";
    }
    d->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)bpf, 0, dispatch_get_main_queue());
    if (!d->source) return "cannot watch BPF";
    dispatch_set_context(d->source, d);
    dispatch_source_set_event_handler_f(d->source, bpf_readable);
    dispatch_source_set_cancel_handler_f(d->source, bpf_cancelled);
    dispatch_resume(d->source);
    return NULL;
}

void datapath_hold(Datapath *d, bool hold) {
    d->held = hold;
    if (hold) suspend_bpf_reads(d);
    else if (bpf_reads_allowed(d)) resume_bpf_reads(d);
}

bool datapath_drained(const Datapath *d) {
    return d->free_count == TX_SLOTS;
}

void datapath_set_link(Datapath *d, bool up) {
    d->link_down = !up;
    if (!up && bpf_reads_allowed(d)) resume_bpf_reads(d);
}

void datapath_stop(Datapath *d) {
    d->stopped = true;
}

void datapath_close(Datapath *d) {
    d->stopped = true;
    if (d->source) {
        /* The cancel handler closes the descriptor once the source is idle; a suspended
         * source must be resumed before it can be cancelled and released. */
        dispatch_set_context(d->source, (void *)(intptr_t)d->bpf);
        resume_bpf_reads(d);
        dispatch_source_cancel(d->source);
        dispatch_release(d->source);
        d->source = NULL;
    } else if (d->bpf >= 0) {
        close(d->bpf);
    }
    d->bpf = -1;
}
