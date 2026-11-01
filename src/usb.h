/* IOKit user-client access to an RNDIS function: one control interface
 * (class e0/01/03 or 02/02/ff, interrupt IN) and its CDC data interface (class 0a,
 * bulk IN + bulk OUT). Interfaces are opened normally: no seize, reset,
 * re-enumeration or configuration change, so ADB on other interfaces keeps working.
 *
 * This is the only file that talks to IOKit's USB interface API.
 */
#ifndef USB_H
#define USB_H

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef IOUSBInterfaceInterface220 **UsbIface;

typedef struct {
    io_service_t control_service, data_service;
    UsbIface control, data;
    bool control_open, data_open;
    UInt8 control_number;
    unsigned out_packet_size;
    UInt8 notify_pipe, in_pipe, out_pipe;
    CFRunLoopSourceRef control_source, data_source;
    uint32_t generation; /* completions of an earlier open are dropped */
} UsbLink;

/* Matching dictionary for RNDIS control interfaces (consumed by IOKit calls). */
typedef enum {
    USB_MATCH_RNDIS,    /* e0/01/03 */
    USB_MATCH_CDC,      /* the Android variant 02/02/ff */
    USB_MATCHING_KINDS
} UsbMatching;
CFMutableDictionaryRef usb_create_matching(UsbMatching kind);
/* For an interface found with usb_create_matching: false if it cannot be RNDIS. *cdc is
 * true for the 02/02/ff variant; only that one is inspected, through a user client on
 * IOKit's cached descriptors without opening the interface, and rejected when its CDC
 * descriptors are invalid or announce ACM (a modem). */
bool usb_rndis_candidate(io_service_t service, bool *cdc);

/* Human-readable "name vid:pid" of the device owning an interface, for logs and status;
 * the name the device reports is reduced to printable ASCII. */
#define USB_DESCRIPTION_SIZE 160
void usb_describe(io_service_t interface, char *out, size_t size);
/* False once the interface has left the registry (unplugged, or the phone re-enumerated). */
bool usb_attached(io_service_t interface);

#define USB_REASON_BUSY "already open by another program" /* cli.c matches these for advice */
#define USB_REASON_NO_DATA "data interface not found"

/* Opens both interfaces and attaches their async event sources to the main run loop.
 * Returns NULL or a reason; on failure everything opened so far is closed. */
const char *usb_open(UsbLink *u, io_service_t control_service);
/* Ends all I/O: no completion of this link is delivered afterwards. */
void usb_close(UsbLink *u);

/* Synchronous encapsulated command and response on pipe 0 (bring-up, HALT). */
IOReturn usb_send_encapsulated(UsbLink *u, const uint8_t *b, uint16_t n, uint32_t timeout_ms);
IOReturn usb_get_encapsulated(UsbLink *u, uint8_t *b, uint16_t capacity, uint32_t *done,
                              uint32_t timeout_ms);

/* Asynchronous transfers. The caller owns the transfer and its buffer until done runs
 * on the main run loop; length is the byte count actually moved. Embed the transfer
 * in the caller's own state and recover that with USB_OWNER. */
typedef struct UsbTransfer UsbTransfer;
typedef void (*UsbDone)(UsbTransfer *t, IOReturn status, size_t length);
struct UsbTransfer {
    UsbDone done;
    UsbLink *link;
    uint32_t generation;
    IOUSBDevRequestTO request; /* control transfers */
};
#define USB_OWNER(transfer, type, member) ((type *)(void *)((char *)(transfer) - offsetof(type, member)))

typedef enum { USB_NOTIFY, USB_BULK_IN, USB_BULK_OUT } UsbPipe;

#define USB_ERROR_BURST 32u /* consecutive failed transfers on one pipe before giving up */

IOReturn usb_read(UsbLink *u, UsbPipe pipe, UsbTransfer *t, void *buffer, uint32_t size);
/* A bulk OUT write completes, or fails, within this time: a phone that stops reading
 * must not hold a transfer slot for long. */
#define USB_WRITE_TIMEOUT_MS 5000u
IOReturn usb_write(UsbLink *u, UsbTransfer *t, const void *buffer, uint32_t size);
/* SEND_ENCAPSULATED_COMMAND (in = false) or GET_ENCAPSULATED_RESPONSE (in = true). */
IOReturn usb_control(UsbLink *u, UsbTransfer *t, bool in, void *buffer, uint16_t size, uint32_t timeout_ms);
void usb_clear_stall(UsbLink *u, UsbPipe pipe);
/* Aborts the interrupt and bulk pipes; pipe 0 cannot be aborted. */
void usb_abort(UsbLink *u);

/* Statuses after which the pipe must be cleared (usb_clear_stall) before it is used again. */
static inline bool usb_needs_clear(IOReturn r) {
    return r == kIOUSBPipeStalled || r == kIOUSBTransactionTimeout;
}

/* Statuses after which the session cannot continue on this interface. */
static inline bool usb_fatal(IOReturn r) {
    return r == kIOReturnNoDevice || r == kIOReturnNotAttached || r == kIOReturnNotResponding ||
           r == kIOReturnNotOpen || r == kIOReturnExclusiveAccess || r == kIOReturnNotPermitted ||
           r == kIOReturnNotPrivileged || r == kIOReturnOffline || r == kIOReturnNotReady ||
           r == kIOUSBUnknownPipeErr; /* the pipe went away with its interface */
}

#endif
