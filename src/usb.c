#include "usb.h"
#include "log.h"
#include "rndis.h"

#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/USB.h>
#include <stdio.h>
#include <string.h>

#define RNDIS_CONTROL_CLASS    0xe0u
#define RNDIS_CONTROL_SUBCLASS 0x01u
#define RNDIS_CONTROL_PROTOCOL 0x03u
#define CDC_CONTROL_CLASS      0x02u /* with the Android variant's subclass and protocol */
#define CDC_ACM_SUBCLASS       0x02u
#define VENDOR_PROTOCOL        0xffu
#define CDC_DATA_CLASS         0x0au

/* CDC class requests to the control interface (USB CDC 1.1, class-specific request codes). */
#define CDC_SEND_ENCAPSULATED_COMMAND 0x00u
#define CDC_GET_ENCAPSULATED_RESPONSE 0x01u
#define BULK_OUT_NO_DATA_TIMEOUT_MS 2000u /* no progress at all on the pipe */
#define DESCRIPTOR_WALK_MAX 256u /* ends a walk over a looping descriptor list */
#define DEVICE_DEPTH_MAX 16u /* service-plane levels searched above an interface for its device */

static void set_number(CFMutableDictionaryRef d, CFStringRef key, int32_t value) {
    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &value);
    if (n) { CFDictionarySetValue(d, key, n); CFRelease(n); }
}

/* values: class, then optionally subclass and protocol, in the order of keys[].
 * IOPropertyMatch is honoured by every IOService, independent of USB family matching rules. */
static CFMutableDictionaryRef create_interface_matching(const int32_t *values, unsigned count) {
    static const CFStringRef keys[] = {CFSTR(kUSBInterfaceClass), CFSTR(kUSBInterfaceSubClass),
                                       CFSTR(kUSBInterfaceProtocol)};
    CFMutableDictionaryRef d = IOServiceMatching(kIOUSBHostInterfaceClassName);
    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!d || !properties) {
        if (d) CFRelease(d);
        if (properties) CFRelease(properties);
        return NULL;
    }
    for (unsigned i = 0; i < count; ++i) set_number(properties, keys[i], values[i]);
    CFDictionarySetValue(d, CFSTR(kIOPropertyMatchKey), properties);
    CFRelease(properties);
    return d;
}

CFMutableDictionaryRef usb_create_matching(UsbMatching kind) {
    static const int32_t values[USB_MATCHING_KINDS][3] = {
        [USB_MATCH_RNDIS] = {RNDIS_CONTROL_CLASS, RNDIS_CONTROL_SUBCLASS, RNDIS_CONTROL_PROTOCOL},
        [USB_MATCH_CDC] = {CDC_CONTROL_CLASS, CDC_ACM_SUBCLASS, VENDOR_PROTOCOL},
    };
    /* Any other kind matches RNDIS. */
    unsigned row = kind == USB_MATCH_CDC ? USB_MATCH_CDC : USB_MATCH_RNDIS;
    return create_interface_matching(values[row], sizeof values[row] / sizeof values[row][0]);
}

static bool property_u32(io_registry_entry_t entry, CFStringRef key, uint32_t *out) {
    CFTypeRef p = IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0);
    int64_t n = 0;
    bool ok = p && CFGetTypeID(p) == CFNumberGetTypeID() &&
              CFNumberGetValue((CFNumberRef)p, kCFNumberSInt64Type, &n) && n >= 0 && n <= UINT32_MAX;
    if (p) CFRelease(p);
    if (ok) *out = (uint32_t)n;
    return ok;
}

/* bInterfaceNumber is one byte on the wire. */
static bool interface_number(io_service_t service, uint32_t *out) {
    return property_u32(service, CFSTR(kUSBInterfaceNumber), out) && *out <= UINT8_MAX;
}

static io_registry_entry_t device_ancestor(io_service_t interface) {
    io_registry_entry_t current = interface;
    IOObjectRetain(current);
    for (unsigned depth = 0; depth < DEVICE_DEPTH_MAX; ++depth) {
        if (IOObjectConformsTo(current, kIOUSBHostDeviceClassName)) return current;
        io_registry_entry_t parent = IO_OBJECT_NULL;
        kern_return_t r = IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent);
        IOObjectRelease(current);
        if (r != KERN_SUCCESS) return IO_OBJECT_NULL;
        current = parent;
    }
    IOObjectRelease(current);
    return IO_OBJECT_NULL;
}

void usb_describe(io_service_t interface, char *out, size_t size) {
    snprintf(out, size, "unknown device");
    io_registry_entry_t device = device_ancestor(interface);
    if (!device) return;
    uint32_t vid = 0, pid = 0;
    (void)property_u32(device, CFSTR(kUSBVendorID), &vid);
    (void)property_u32(device, CFSTR(kUSBProductID), &pid);
    char name[128] = "USB device";
    CFTypeRef p = IORegistryEntryCreateCFProperty(device, CFSTR(kUSBProductString), kCFAllocatorDefault, 0);
    if (p && CFGetTypeID(p) == CFStringGetTypeID())
        (void)CFStringGetCString((CFStringRef)p, name, sizeof name, kCFStringEncodingUTF8);
    if (p) CFRelease(p);
    make_printable(name); /* the phone chooses it: no line breaks or terminal escapes */
    snprintf(out, size, "%s %04x:%04x", name, vid, pid);
    IOObjectRelease(device);
}

bool usb_attached(io_service_t interface) {
    return IORegistryEntryInPlane(interface, kIOServicePlane);
}

static bool is_data_interface(io_service_t entry, uint64_t device_id, unsigned data_number) {
    uint32_t n = 0, alt = 0;
    uint64_t id = 0;
    io_registry_entry_t device = device_ancestor(entry);
    bool same = device && IORegistryEntryGetRegistryEntryID(device, &id) == KERN_SUCCESS && id == device_id &&
                property_u32(entry, CFSTR(kUSBInterfaceNumber), &n) && n == data_number &&
                (!property_u32(entry, CFSTR(kUSBAlternateSetting), &alt) || alt == 0);
    if (device) IOObjectRelease(device);
    return same;
}

/* Union descriptors can point past other functions; only search on this USB device. */
static io_service_t find_data_interface(io_service_t control, unsigned data_number) {
    uint64_t device_id = 0;
    io_registry_entry_t device = device_ancestor(control);
    bool ok = device && data_number <= UINT8_MAX &&
              IORegistryEntryGetRegistryEntryID(device, &device_id) == KERN_SUCCESS;
    if (device) IOObjectRelease(device);
    if (!ok) return IO_OBJECT_NULL;

    static const int32_t cdc_data[] = {CDC_DATA_CLASS};
    CFMutableDictionaryRef match = create_interface_matching(cdc_data, sizeof cdc_data / sizeof *cdc_data);
    if (!match) return IO_OBJECT_NULL;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) != KERN_SUCCESS) return IO_OBJECT_NULL;
    io_service_t found = IO_OBJECT_NULL, entry;
    unsigned matches = 0;
    while ((entry = IOIteratorNext(it))) {
        if (is_data_interface(entry, device_id, data_number)) {
            ++matches;
            if (!found) { found = entry; continue; }
        }
        IOObjectRelease(entry);
    }
    IOObjectRelease(it);
    if (matches > 1) { /* more than one candidate: ambiguous, use neither */
        IOObjectRelease(found);
        found = IO_OBJECT_NULL;
    }
    return found;
}

static const char *create_interface(io_service_t service, UsbIface *out) {
    IOCFPlugInInterface **plugin = NULL;
    SInt32 score = 0;
    IOReturn r = IOCreatePlugInInterfaceForService(service, kIOUSBInterfaceUserClientTypeID,
                                                   kIOCFPlugInInterfaceID, &plugin, &score);
    if (r != kIOReturnSuccess || !plugin) {
        if (plugin) (*plugin)->Release(plugin);
        return "cannot create interface user client";
    }
    HRESULT h = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID220),
                                          (LPVOID *)out);
    (*plugin)->Release(plugin); /* never IODestroyPlugInInterface: it can stop the service */
    if (h || !*out) { *out = NULL; return "interface API unavailable"; }
    return NULL;
}

static const char *open_interface(UsbIface a, bool *opened) {
    IOReturn r = (*a)->USBInterfaceOpen(a);
    if (r == kIOReturnExclusiveAccess) return "interface is " USB_REASON_BUSY " (old bridge, HoRNDIS?)";
    if (r != kIOReturnSuccess) return "cannot open interface";
    *opened = true;
    return NULL;
}

/* IOKit owns the descriptor storage. Copy bounded CS records so the walker itself
 * is independent of IOKit and can be exercised with hostile inputs offline. */
static bool read_cdc(UsbIface a, UInt8 number, RndisCdcInfo *info) {
    uint8_t bytes[4096];
    size_t used = 0;
    const IOUSBDescriptorHeader *previous = NULL;
    for (unsigned i = 0; i < DESCRIPTOR_WALK_MAX; ++i) {
        const IOUSBDescriptorHeader *d = (*a)->FindNextAssociatedDescriptor(a, previous, USB_CS_INTERFACE);
        if (!d) return rndis_parse_cdc(bytes, used, number, info);
        if (d == previous || d->bLength < 3 /* length, type, subtype */ || d->bLength > sizeof bytes - used) return false;
        memcpy(bytes + used, d, d->bLength);
        used += d->bLength;
        previous = d;
    }
    return false;
}

/* A 02/02/ff function that announces ACM capabilities is a modem, not RNDIS. */
static const char *inspect_control(UsbIface a, UInt8 number, uint32_t cls, RndisCdcInfo *info) {
    if (!read_cdc(a, number, info)) return "invalid CDC descriptors";
    if (cls == CDC_CONTROL_CLASS && info->acm_capabilities) return "CDC ACM modem, not RNDIS";
    return NULL;
}

bool usb_rndis_candidate(io_service_t service, bool *cdc) {
    uint32_t cls = 0, number = 0;
    if (!property_u32(service, CFSTR(kUSBInterfaceClass), &cls)) return false;
    *cdc = cls == CDC_CONTROL_CLASS;
    if (!*cdc) return cls == RNDIS_CONTROL_CLASS;
    UsbIface a = NULL;
    RndisCdcInfo info;
    bool ok = interface_number(service, &number) && !create_interface(service, &a) &&
              !inspect_control(a, (UInt8)number, cls, &info);
    if (a) (*a)->Release(a);
    return ok;
}

/* Pipe properties may include a SuperSpeed burst. The endpoint descriptor gives
 * the actual packet size needed to decide whether a transfer ends in a short packet. */
static unsigned bulk_out_packet_size(UsbIface a, UInt8 pipe) {
    UInt8 direction = 0, number = 0, type = 0, interval = 0;
    UInt16 packet = 0;
    if ((*a)->GetPipeProperties(a, pipe, &direction, &number, &type, &packet, &interval)) return USB_PACKET_FALLBACK;
    const IOUSBDescriptorHeader *previous = NULL;
    for (unsigned i = 0; i < DESCRIPTOR_WALK_MAX; ++i) {
        const IOUSBDescriptorHeader *d = (*a)->FindNextAssociatedDescriptor(a, previous, kUSBEndpointDesc);
        if (!d || d == previous || d->bLength < 2 /* length, type */) break;
        unsigned size = rndis_bulk_packet_size((const uint8_t *)d, d->bLength, number);
        if (size) return size;
        previous = d;
    }
    return USB_PACKET_FALLBACK;
}

static bool find_pipes(UsbIface a, UInt8 *interrupt_in, UInt8 *bulk_in, UInt8 *bulk_out) {
    UInt8 count = 0;
    if ((*a)->GetNumEndpoints(a, &count)) return false;
    for (unsigned index = 1; index <= count; ++index) {
        UInt8 pipe = (UInt8)index;
        UInt8 direction = 0, number = 0, type = 0, interval = 0;
        UInt16 packet = 0;
        if ((*a)->GetPipeProperties(a, pipe, &direction, &number, &type, &packet, &interval)) return false;
        if (interrupt_in && type == kUSBInterrupt && direction == kUSBIn && !*interrupt_in) *interrupt_in = pipe;
        if (bulk_in && type == kUSBBulk && direction == kUSBIn) {
            if (*bulk_in) return false;
            *bulk_in = pipe;
        }
        if (bulk_out && type == kUSBBulk && direction == kUSBOut) {
            if (*bulk_out) return false;
            *bulk_out = pipe;
        }
    }
    return true;
}

static const char *attach_source(UsbIface a, CFRunLoopSourceRef *source) {
    if ((*a)->CreateInterfaceAsyncEventSource(a, source) != kIOReturnSuccess || !*source)
        return "cannot create async event source";
    CFRunLoopAddSource(CFRunLoopGetMain(), *source, kCFRunLoopDefaultMode);
    return NULL;
}

static uint32_t last_generation;

const char *usb_open(UsbLink *u, io_service_t control_service) {
    memset(u, 0, sizeof *u);
    u->generation = ++last_generation;
    IOObjectRetain(control_service);
    u->control_service = control_service;
    uint32_t number = 0, cls = 0;
    RndisCdcInfo info = {0};
    const char *e = create_interface(control_service, &u->control);
    if (!e && (!interface_number(control_service, &number) ||
               !property_u32(control_service, CFSTR(kUSBInterfaceClass), &cls))) e = "missing interface properties";
    u->control_number = (UInt8)number;
    if (!e) e = inspect_control(u->control, u->control_number, cls, &info);
    if (!e) {
        /* Without a union descriptor the data interface follows the control interface. */
        u->data_service = find_data_interface(control_service, info.has_union ? info.union_slave : number + 1);
        if (!u->data_service) e = USB_REASON_NO_DATA " (yet)";
    }
    if (!e) e = create_interface(u->data_service, &u->data);
    if (!e) e = open_interface(u->control, &u->control_open);
    if (!e) e = open_interface(u->data, &u->data_open);
    if (!e && (!find_pipes(u->control, &u->notify_pipe, NULL, NULL) || !u->notify_pipe))
        e = "control interface has no interrupt IN endpoint";
    if (!e && (!find_pipes(u->data, NULL, &u->in_pipe, &u->out_pipe) || !u->in_pipe || !u->out_pipe))
        e = "data interface lacks bulk IN/OUT endpoints";
    if (!e) u->out_packet_size = bulk_out_packet_size(u->data, u->out_pipe);
    if (!e) e = attach_source(u->control, &u->control_source);
    if (!e) e = attach_source(u->data, &u->data_source);
    if (e) usb_close(u);
    return e;
}

static void close_one(UsbIface *a, bool *opened, CFRunLoopSourceRef *source, io_service_t *service) {
    if (*source) {
        CFRunLoopRemoveSource(CFRunLoopGetMain(), *source, kCFRunLoopDefaultMode);
        CFRelease(*source);
        *source = NULL;
    }
    if (*a) {
        if (*opened) (void)(**a)->USBInterfaceClose(*a);
        (**a)->Release(*a);
        *a = NULL;
    }
    *opened = false;
    if (*service) { IOObjectRelease(*service); *service = IO_OBJECT_NULL; }
}

void usb_close(UsbLink *u) {
    close_one(&u->data, &u->data_open, &u->data_source, &u->data_service);
    close_one(&u->control, &u->control_open, &u->control_source, &u->control_service);
    u->generation = 0;
}

static IOUSBDevRequestTO encapsulated(const UsbLink *u, bool in, void *b, uint16_t n, uint32_t timeout_ms) {
    UInt8 direction = in ? kIOUSBDeviceRequestDirectionIn : kIOUSBDeviceRequestDirectionOut;
    return (IOUSBDevRequestTO){
        .bmRequestType = direction | kIOUSBDeviceRequestTypeClass | kIOUSBDeviceRequestRecipientInterface,
        .bRequest = in ? CDC_GET_ENCAPSULATED_RESPONSE : CDC_SEND_ENCAPSULATED_COMMAND,
        .wIndex = u->control_number,
        .wLength = n,
        .pData = b,
        .noDataTimeout = timeout_ms,
        .completionTimeout = timeout_ms,
    };
}

static IOReturn control_request(UsbLink *u, bool in, uint8_t *b, uint16_t n, uint32_t *done,
                                uint32_t timeout_ms) {
    if (!u->control_open) return kIOReturnNotOpen;
    IOUSBDevRequestTO r = encapsulated(u, in, b, n, timeout_ms);
    IOReturn status = (*u->control)->ControlRequestTO(u->control, 0, &r);
    *done = r.wLenDone;
    return status;
}

IOReturn usb_send_encapsulated(UsbLink *u, const uint8_t *b, uint16_t n, uint32_t timeout_ms) {
    uint32_t done = 0;
    IOReturn r = control_request(u, false, (uint8_t *)b, n, &done, timeout_ms);
    if (r == kIOReturnSuccess && done != n) return kIOReturnUnderrun;
    return r;
}

IOReturn usb_get_encapsulated(UsbLink *u, uint8_t *b, uint16_t capacity, uint32_t *done,
                              uint32_t timeout_ms) {
    *done = 0;
    IOReturn r = control_request(u, true, b, capacity, done, timeout_ms);
    if (*done > capacity) return kIOReturnOverrun;
    return r;
}

/* IOKit's async API reports the byte count in arg0. */
static void finished(void *refcon, IOReturn status, void *arg0) {
    UsbTransfer *t = refcon;
    if (!t->link || t->generation != t->link->generation) return; /* from a closed link */
    t->done(t, status, (size_t)(uintptr_t)arg0);
}

/* Ties a transfer to this open of the link, so finished() can drop it after usb_close. */
static void bind_transfer(UsbLink *u, UsbTransfer *t) {
    t->link = u;
    t->generation = u->generation;
}

static UsbIface pipe_interface(const UsbLink *u, UsbPipe pipe, UInt8 *number) {
    switch (pipe) {
    case USB_NOTIFY:   *number = u->notify_pipe; return u->control;
    case USB_BULK_IN:  *number = u->in_pipe;     return u->data;
    case USB_BULK_OUT: *number = u->out_pipe;    return u->data;
    }
    return NULL;
}

IOReturn usb_read(UsbLink *u, UsbPipe pipe, UsbTransfer *t, void *buffer, uint32_t size) {
    UInt8 number = 0;
    UsbIface a = pipe_interface(u, pipe, &number);
    if (!a || pipe == USB_BULK_OUT) return kIOReturnNotOpen; /* bulk OUT is written, not read */
    bind_transfer(u, t);
    return (*a)->ReadPipeAsync(a, number, buffer, size, finished, t);
}

IOReturn usb_write(UsbLink *u, UsbTransfer *t, const void *buffer, uint32_t size) {
    if (!u->data) return kIOReturnNotOpen;
    bind_transfer(u, t);
    return (*u->data)->WritePipeAsyncTO(u->data, u->out_pipe, (void *)buffer, size, BULK_OUT_NO_DATA_TIMEOUT_MS,
                                      USB_WRITE_TIMEOUT_MS, finished, t);
}

IOReturn usb_control(UsbLink *u, UsbTransfer *t, bool in, void *buffer, uint16_t size, uint32_t timeout_ms) {
    if (!u->control_open) return kIOReturnNotOpen;
    bind_transfer(u, t);
    t->request = encapsulated(u, in, buffer, size, timeout_ms);
    return (*u->control)->ControlRequestAsyncTO(u->control, 0, &t->request, finished, t);
}

void usb_clear_stall(UsbLink *u, UsbPipe pipe) {
    UInt8 number = 0;
    UsbIface a = pipe_interface(u, pipe, &number);
    if (a) (void)(*a)->ClearPipeStallBothEnds(a, number);
}

void usb_abort(UsbLink *u) {
    if (u->data_open) {
        (void)(*u->data)->AbortPipe(u->data, u->in_pipe);
        (void)(*u->data)->AbortPipe(u->data, u->out_pipe);
    }
    if (u->control_open) (void)(*u->control)->AbortPipe(u->control, u->notify_pipe);
}
