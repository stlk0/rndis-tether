/* Ethernet frames between the phone (RNDIS over bulk USB) and macOS (BPF on the
 * peer side of the feth pair).
 *
 *   phone -> Mac: RX_SLOTS bulk IN reads stay in flight; every frame of one transfer
 *                 reaches macOS in one write() to BPF where the kernel allows batches.
 *   Mac -> phone: one BPF read yields a burst of frames; they are packed into as few
 *                 bulk OUT transfers as the phone accepts, sent at the end of the read.
 *                 Nothing waits for more frames to fill a transfer.
 */
#ifndef DATAPATH_H
#define DATAPATH_H

#include "rndis.h"
#include "usb.h"

#include <dispatch/dispatch.h>

#define RX_SLOTS 4u         /* bulk IN reads kept in flight */
#define TX_SLOTS 128u       /* bulk OUT writes that may be in flight */
#define TX_READ_MIN 48u     /* read macOS frames only with this many free slots */
#define TX_BUFFER 16384u         /* one bulk OUT transfer; tx_limit stays below it */
#define BPF_BUFFER (32u * 1024u) /* largest BPF read buffer we ask for */

typedef struct {
    uint64_t rx_frames, rx_bytes, tx_frames, tx_bytes, rx_transfers, tx_transfers;
    uint64_t rx_dropped, tx_dropped; /* frames */
    uint64_t rx_malformed;           /* bulk IN transfers cut short by a malformed message */
    uint64_t usb_errors;             /* failed bulk transfers */
    uint64_t bpf_errors;             /* frames lost in failed BPF writes */
} DataStats;

typedef struct {
    void (*heard)(void);                                 /* the phone sent data */
    void (*errors)(const char *reason);                  /* an error burst: a soft RESET may help */
    void (*drained)(void);                               /* held, and no bulk OUT write is in flight */
    void (*failed)(const char *reason, IOReturn status); /* the session cannot go on */
} DatapathEvents;

typedef struct {
    unsigned mtu;         /* the phone's, at most ETHERMTU */
    unsigned batch_limit; /* packets per bulk OUT transfer */
    uint32_t max_transfer, alignment_shift; /* from REMOTE_NDIS_INITIALIZE_CMPLT */
} DatapathLimits;

typedef struct Datapath Datapath;

typedef struct {
    UsbTransfer usb;
    Datapath *owner;
    uint8_t buffer[RNDIS_RX_TRANSFER];
} RxSlot;

typedef struct {
    UsbTransfer usb;
    Datapath *owner;
    size_t used;        /* bytes in buffer: RNDIS messages and their padding */
    size_t frame_bytes; /* the Ethernet frames among them, for the statistics */
    unsigned packets;
    uint8_t buffer[TX_BUFFER];
} TxSlot;

struct Datapath {
    UsbLink *usb;
    const DatapathEvents *events;
    DatapathLimits limits;
    size_t tx_limit; /* RNDIS message bytes from rndis_transfer_limit; leaves room for the terminating zero byte */
    bool stopped, link_down, held;

    int bpf;
    unsigned bpf_size;
    bool bpf_batch; /* several frames per write() to BPF */
    unsigned bpf_failed_writes; /* one per failed write(), however many frames it carried */
    dispatch_source_t source;
    bool bpf_suspended; /* the BPF read source (not the data path) is suspended */

    TxSlot *free_tx[TX_SLOTS];
    unsigned free_count;
    TxSlot *filling;
    unsigned rx_errors_row, rx_aborted_row, tx_errors_row;
    unsigned traced_rx, traced_tx;
    DataStats stats;
};

/* Takes over the BPF descriptor (bound to the feth peer, bpf_size from bpf_open_bound)
 * and starts both directions. NULL or a reason. */
const char *datapath_start(Datapath *d, UsbLink *u, int bpf, unsigned bpf_size, const DatapathLimits *limits,
                           const DatapathEvents *events);
/* One frame from macOS to the phone; datapath_flush sends what is batched. */
void datapath_send(Datapath *d, const uint8_t *frame, size_t n);
void datapath_flush(Datapath *d);
/* Soft RESET: stop taking frames from macOS until released; drained reports when
 * every bulk OUT write has finished. */
void datapath_hold(Datapath *d, bool hold);
bool datapath_drained(const Datapath *d);
void datapath_set_link(Datapath *d, bool up);
/* No further transfers or events; completions still in flight are absorbed. */
void datapath_stop(Datapath *d);
/* Closes the BPF descriptor. */
void datapath_close(Datapath *d);

#endif
