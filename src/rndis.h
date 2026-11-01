/* RNDIS host-side message encoding and parsing.
 * Pure functions: no IOKit, no I/O, so everything here is covered by selftest.c.
 * All multi-byte RNDIS fields are little-endian.
 */
#ifndef RNDIS_H
#define RNDIS_H

#include <net/ethernet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RNDIS_PACKET_MSG          0x00000001u
#define RNDIS_INITIALIZE_MSG      0x00000002u
#define RNDIS_HALT_MSG            0x00000003u
#define RNDIS_QUERY_MSG           0x00000004u
#define RNDIS_SET_MSG             0x00000005u
#define RNDIS_RESET_MSG           0x00000006u
#define RNDIS_INDICATE_STATUS_MSG 0x00000007u
#define RNDIS_KEEPALIVE_MSG       0x00000008u
#define RNDIS_COMPLETION          0x80000000u

#define RNDIS_MAJOR_VERSION       1u
#define RNDIS_DF_CONNECTIONLESS   1u
#define RNDIS_MEDIUM_802_3        0u
#define RNDIS_ALIGNMENT_SHIFT_MAX 7u /* messages align to at most 128 bytes */

#define RNDIS_STATUS_SUCCESS          0x00000000u
#define RNDIS_STATUS_MEDIA_CONNECT    0x4001000bu
#define RNDIS_STATUS_MEDIA_DISCONNECT 0x4001000cu

#define OID_GEN_MAXIMUM_FRAME_SIZE    0x00010106u
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010eu
#define OID_GEN_MEDIA_CONNECT_STATUS  0x00010114u
#define OID_802_3_PERMANENT_ADDRESS   0x01010101u
#define RNDIS_MEDIA_CONNECTED 0u /* OID_GEN_MEDIA_CONNECT_STATUS: NdisMediaStateConnected */

#define NDIS_PACKET_TYPE_DIRECTED      0x01u
#define NDIS_PACKET_TYPE_ALL_MULTICAST 0x04u
#define NDIS_PACKET_TYPE_BROADCAST     0x08u

#define RNDIS_CONTROL_CAP   4096u  /* GET_ENCAPSULATED_RESPONSE buffer */
#define RNDIS_RX_TRANSFER  16384u  /* MaxTransferSize we advertise for device->host */
#define RNDIS_PACKET_HEADER   44u
#define ETH_HEADER            14u
#define ETH_VLAN_TAG           4u  /* optional 802.1Q tag */
#define ETH_FRAME_MAX (ETH_HEADER + ETHERMTU + ETH_VLAN_TAG) /* 1518 */
#define USB_PACKET_FALLBACK  512u  /* bulk packet size when the endpoint descriptor gives none */

/* Descriptor codes rndis_parse_cdc and rndis_bulk_packet_size look for. */
#define USB_CS_INTERFACE        0x24u /* class-specific interface descriptor */
#define CDC_ACM_DESCRIPTOR      0x02u /* functional descriptor subtypes */
#define CDC_UNION_DESCRIPTOR    0x06u
#define USB_ENDPOINT_DESCRIPTOR 0x05u
#define USB_ENDPOINT_BULK       0x02u /* transfer type in bmAttributes */
#define USB_ENDPOINT_DESCRIPTOR_SIZE 7u
#define USB_ENDPOINT_DIR_IN    0x80u /* bEndpointAddress */
#define USB_ENDPOINT_TYPE_MASK 0x03u /* bmAttributes */

/* Health policy (rndis_keepalive_due, rndis_keepalive_result, rndis_reset_decision). */
#define RNDIS_KEEPALIVE_IDLE_MS 5000u /* silence from the phone before a KEEPALIVE */
#define RNDIS_KEEPALIVE_MISSES     3u /* unanswered KEEPALIVEs in a row that end the session */
#define RNDIS_RESET_WINDOW_S      30  /* no u suffix: NUMBER_TEXT puts it into a failure reason */
#define RNDIS_RESET_WINDOW_MS (RNDIS_RESET_WINDOW_S * 1000u)

typedef struct {
    uint32_t max_packets_per_transfer; /* what the phone accepts per host->device transfer: our TX */
    uint32_t max_transfer_size;
    uint32_t alignment_shift;          /* PacketAlignmentFactor: messages align to 1<<shift */
} RndisInitInfo;

uint32_t rndis_le32(const uint8_t *p);
void rndis_put32(uint8_t *p, uint32_t v);

#define RNDIS_INIT_LENGTH          24u
#define RNDIS_QUERY_LENGTH         28u /* empty input buffer */
#define RNDIS_SET_U32_LENGTH       32u
#define RNDIS_HALT_LENGTH          12u
#define RNDIS_KEEPALIVE_LENGTH     12u
#define RNDIS_RESET_LENGTH         12u
#define RNDIS_STATUS_CMPLT_LENGTH  16u /* SET, KEEPALIVE and RESET completions */
#define RNDIS_REQUEST_MAX RNDIS_SET_U32_LENGTH /* longest message a builder writes */

/* Builders return the message length written to b. */
size_t rndis_build_init(uint8_t *b, uint32_t id, uint32_t max_transfer);
size_t rndis_build_query(uint8_t *b, uint32_t id, uint32_t oid);
size_t rndis_build_set_u32(uint8_t *b, uint32_t id, uint32_t oid, uint32_t value);
size_t rndis_build_halt(uint8_t *b, uint32_t id);
size_t rndis_build_keepalive(uint8_t *b, uint32_t id);
size_t rndis_build_reset(uint8_t *b);
size_t rndis_build_keepalive_cmplt(uint8_t *b, uint32_t id);

/* Type of one control message, or 0 when the length header is unusable. */
uint32_t rndis_control_type(const uint8_t *b, size_t n);
/* MessageLength of a control message; b holds at least 8 bytes. */
uint32_t rndis_control_length(const uint8_t *b);
/* RequestId of INITIALIZE, HALT, QUERY, SET, KEEPALIVE and their completions; 0 for
 * other messages or when it is missing. */
uint32_t rndis_control_id(const uint8_t *b, size_t n);

/* Parsers return NULL on success or a short static reason. */
const char *rndis_parse_init_cmplt(const uint8_t *b, size_t n, uint32_t id, RndisInitInfo *info);
const char *rndis_parse_query_cmplt(const uint8_t *b, size_t n, uint32_t id,
                                    const uint8_t **data, uint32_t *length);
const char *rndis_parse_set_cmplt(const uint8_t *b, size_t n, uint32_t id);
const char *rndis_parse_indicate(const uint8_t *b, size_t n, uint32_t *status);
const char *rndis_parse_mac(const uint8_t *data, uint32_t length, uint8_t mac[ETHER_ADDR_LEN]);
const char *rndis_parse_keepalive(const uint8_t *b, size_t n, uint32_t *id);
/* These validate the envelope but return device failure statuses to the caller. */
const char *rndis_parse_status_cmplt(const uint8_t *b, size_t n, uint32_t type,
                                    uint32_t id, uint32_t *status);
const char *rndis_parse_reset_cmplt(const uint8_t *b, size_t n, uint32_t *status,
                                   uint32_t *addressing_reset);
bool rndis_completion_matches(const uint8_t *b, size_t n, uint32_t type, uint32_t id);

typedef struct {
    uint8_t acm_capabilities, union_slave;
    bool has_union;
} RndisCdcInfo;
/* Walk a bounded descriptor stream. Only unions for this control interface apply. */
bool rndis_parse_cdc(const uint8_t *b, size_t n, uint8_t control_number, RndisCdcInfo *info);
/* wMaxPacketSize of the bulk OUT endpoint descriptor for out_endpoint; 0 when b is not
 * that descriptor or the size is not a legal bulk size. */
unsigned rndis_bulk_packet_size(const uint8_t *b, size_t n, uint8_t out_endpoint);

typedef enum { RNDIS_HEALTH_OK, RNDIS_HEALTH_RESET, RNDIS_HEALTH_RESTART } RndisHealthAction;
bool rndis_keepalive_due(uint64_t now, uint64_t last_rx, bool outstanding);
RndisHealthAction rndis_keepalive_result(unsigned *failures, bool answered, uint32_t status);
RndisHealthAction rndis_reset_decision(uint64_t now, uint64_t last_reset, bool attempted, bool in_progress);

/* Iterates Ethernet frames inside one bulk-IN transfer. */
typedef struct { const uint8_t *next; size_t left; } RndisCursor; /* next message, bytes left in the transfer */
typedef enum {
    RNDIS_FRAMES_END,       /* nothing more in this transfer */
    RNDIS_FRAME,            /* *frame and *length are set */
    RNDIS_FRAME_SKIPPED,    /* frame size out of range: *why is set; the next message follows */
    RNDIS_FRAMES_MALFORMED, /* *why is set; the caller drops the rest, the session keeps running */
} RndisFrameResult;
RndisFrameResult rndis_next_frame(RndisCursor *c, const uint8_t **frame, size_t *length, const char **why);

/* Appends one frame as RNDIS_PACKET_MSG at offset used. The message is padded to
 * the device alignment so a following message starts aligned; a message that fits
 * only without its padding is appended unpadded and closes the transfer. Returns the
 * bytes appended, or 0 when it does not fit into limit. */
size_t rndis_append_packet(uint8_t *buf, size_t used, size_t limit,
                           const uint8_t *frame, size_t n, uint32_t alignment_shift);
/* Bytes of RNDIS messages per bulk OUT transfer so the zero byte rndis_finish_transfer
 * adds after whole USB packets still fits max_transfer and capacity. */
size_t rndis_transfer_limit(uint32_t max_transfer, size_t capacity, unsigned packet_size);
/* A bulk transfer whose length is a multiple of the USB packet size would not end
 * with a short packet; add the conventional single zero byte (as Linux usbnet does). */
size_t rndis_finish_transfer(uint8_t *buf, size_t used, size_t capacity, unsigned packet_size);

#endif
