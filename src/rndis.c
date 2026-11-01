#include "rndis.h"

#include <string.h>

/* Bounds checks subtract from trusted sizes instead of adding device-controlled values. */

#define MESSAGE_HEADER 8u /* MessageType and MessageLength */
#define OFFSET_BASE MESSAGE_HEADER /* RNDIS offsets count from after MessageType and MessageLength */
#define PACKET_DATA_OFFSET (RNDIS_PACKET_HEADER - OFFSET_BASE) /* data follows the header */
#define SET_HEADER 28u
#define QUERY_CMPLT_HEADER 24u
#define INIT_CMPLT_LENGTH 52u
#define REQUEST_ID_END 12u /* MessageType, MessageLength, RequestId */
#define INDICATE_HEADER 20u /* the fixed INDICATE_STATUS header */

uint32_t rndis_le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void rndis_put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (i * 8));
}

size_t rndis_build_init(uint8_t *b, uint32_t id, uint32_t max_transfer) {
    memset(b, 0, RNDIS_INIT_LENGTH);
    rndis_put32(b, RNDIS_INITIALIZE_MSG);
    rndis_put32(b + 4, RNDIS_INIT_LENGTH);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, RNDIS_MAJOR_VERSION);
    rndis_put32(b + 16, 0); /* MinorVersion */
    rndis_put32(b + 20, max_transfer);
    return RNDIS_INIT_LENGTH;
}

size_t rndis_build_query(uint8_t *b, uint32_t id, uint32_t oid) {
    memset(b, 0, RNDIS_QUERY_LENGTH);
    rndis_put32(b, RNDIS_QUERY_MSG);
    rndis_put32(b + 4, RNDIS_QUERY_LENGTH);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, oid);
    return RNDIS_QUERY_LENGTH; /* empty input buffer: length 0, offset 0, reserved 0 */
}

size_t rndis_build_set_u32(uint8_t *b, uint32_t id, uint32_t oid, uint32_t value) {
    memset(b, 0, RNDIS_SET_U32_LENGTH);
    rndis_put32(b, RNDIS_SET_MSG);
    rndis_put32(b + 4, RNDIS_SET_U32_LENGTH);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, oid);
    rndis_put32(b + 16, (uint32_t)sizeof(uint32_t)); /* InformationBufferLength */
    rndis_put32(b + 20, SET_HEADER - OFFSET_BASE); /* InformationBufferOffset */
    rndis_put32(b + SET_HEADER, value);
    return RNDIS_SET_U32_LENGTH;
}

size_t rndis_build_halt(uint8_t *b, uint32_t id) {
    memset(b, 0, RNDIS_HALT_LENGTH);
    rndis_put32(b, RNDIS_HALT_MSG);
    rndis_put32(b + 4, RNDIS_HALT_LENGTH);
    rndis_put32(b + 8, id);
    return RNDIS_HALT_LENGTH;
}

size_t rndis_build_keepalive_cmplt(uint8_t *b, uint32_t id) {
    memset(b, 0, RNDIS_STATUS_CMPLT_LENGTH);
    rndis_put32(b, RNDIS_KEEPALIVE_MSG | RNDIS_COMPLETION);
    rndis_put32(b + 4, RNDIS_STATUS_CMPLT_LENGTH);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, RNDIS_STATUS_SUCCESS);
    return RNDIS_STATUS_CMPLT_LENGTH;
}

size_t rndis_build_keepalive(uint8_t *b, uint32_t id) {
    rndis_put32(b, RNDIS_KEEPALIVE_MSG);
    rndis_put32(b + 4, RNDIS_KEEPALIVE_LENGTH);
    rndis_put32(b + 8, id);
    return RNDIS_KEEPALIVE_LENGTH;
}

size_t rndis_build_reset(uint8_t *b) {
    rndis_put32(b, RNDIS_RESET_MSG);
    rndis_put32(b + 4, RNDIS_RESET_LENGTH);
    rndis_put32(b + 8, 0); /* Reserved, not RequestId. */
    return RNDIS_RESET_LENGTH;
}

uint32_t rndis_control_type(const uint8_t *b, size_t n) {
    if (n < MESSAGE_HEADER) return 0;
    uint32_t l = rndis_le32(b + 4);
    if (l < MESSAGE_HEADER || l > n) return 0;
    return rndis_le32(b);
}

uint32_t rndis_control_length(const uint8_t *b) {
    return rndis_le32(b + 4);
}

/* RESET, PACKET and INDICATE_STATUS have other fields where a RequestId would be. */
static bool has_request_id(uint32_t type) {
    switch (type & ~RNDIS_COMPLETION) {
    case RNDIS_INITIALIZE_MSG:
    case RNDIS_HALT_MSG:
    case RNDIS_QUERY_MSG:
    case RNDIS_SET_MSG:
    case RNDIS_KEEPALIVE_MSG:
        return true;
    default:
        return false;
    }
}

uint32_t rndis_control_id(const uint8_t *b, size_t n) {
    if (!has_request_id(rndis_control_type(b, n)) || rndis_control_length(b) < REQUEST_ID_END) return 0;
    return rndis_le32(b + 8);
}

bool rndis_completion_matches(const uint8_t *b, size_t n, uint32_t type, uint32_t id) {
    if (rndis_control_type(b, n) != (type | RNDIS_COMPLETION)) return false;
    return type == RNDIS_RESET_MSG || (rndis_control_length(b) >= REQUEST_ID_END && rndis_le32(b + 8) == id);
}

const char *rndis_parse_keepalive(const uint8_t *b, size_t n, uint32_t *id) {
    if (rndis_control_type(b, n) != RNDIS_KEEPALIVE_MSG || rndis_control_length(b) < REQUEST_ID_END)
        return "invalid keepalive";
    *id = rndis_le32(b + 8);
    return NULL;
}

const char *rndis_parse_status_cmplt(const uint8_t *b, size_t n, uint32_t type,
                                    uint32_t id, uint32_t *status) {
    if ((type != RNDIS_KEEPALIVE_MSG && type != RNDIS_SET_MSG) ||
        !rndis_completion_matches(b, n, type, id) || rndis_control_length(b) < RNDIS_STATUS_CMPLT_LENGTH)
        return "invalid status completion";
    *status = rndis_le32(b + 12);
    return NULL;
}

const char *rndis_parse_reset_cmplt(const uint8_t *b, size_t n, uint32_t *status,
                                   uint32_t *addressing_reset) {
    if (!rndis_completion_matches(b, n, RNDIS_RESET_MSG, 0) || rndis_control_length(b) < RNDIS_STATUS_CMPLT_LENGTH)
        return "invalid reset completion";
    *status = rndis_le32(b + 8);
    *addressing_reset = rndis_le32(b + 12);
    return NULL;
}

bool rndis_parse_cdc(const uint8_t *b, size_t n, uint8_t control_number, RndisCdcInfo *info) {
    RndisCdcInfo found = {0};
    while (n) {
        if (n < 2 || b[0] < 2 || b[0] > n) return false;
        size_t length = b[0];
        if (b[1] == USB_CS_INTERFACE) {
            if (length < 3) return false;
            if (b[2] == CDC_ACM_DESCRIPTOR) {
                if (length < 4) return false;
                found.acm_capabilities |= b[3];
            } else if (b[2] == CDC_UNION_DESCRIPTOR) {
                if (length < 5) return false;
                if (b[3] == control_number) {
                    if (b[4] == control_number || (found.has_union && found.union_slave != b[4])) return false;
                    found.has_union = true;
                    found.union_slave = b[4];
                }
            }
        }
        b += length;
        n -= length;
    }
    *info = found;
    return true;
}

unsigned rndis_bulk_packet_size(const uint8_t *b, size_t n, uint8_t out_endpoint) {
    if (n < USB_ENDPOINT_DESCRIPTOR_SIZE || b[0] < USB_ENDPOINT_DESCRIPTOR_SIZE || b[0] > n ||
        b[1] != USB_ENDPOINT_DESCRIPTOR || b[2] != out_endpoint || (out_endpoint & USB_ENDPOINT_DIR_IN) ||
        (b[3] & USB_ENDPOINT_TYPE_MASK) != USB_ENDPOINT_BULK) return 0;
    unsigned packet = (unsigned)b[4] | (unsigned)b[5] << 8;
    /* Legal bulk sizes: 8-64 full speed, 512 high speed, 1024 SuperSpeed. */
    return packet == 8 || packet == 16 || packet == 32 || packet == 64 ||
           packet == 512 || packet == 1024 ? packet : 0;
}

bool rndis_keepalive_due(uint64_t now, uint64_t last_rx, bool outstanding) {
    return !outstanding && now >= last_rx && now - last_rx >= RNDIS_KEEPALIVE_IDLE_MS;
}

RndisHealthAction rndis_keepalive_result(unsigned *failures, bool answered, uint32_t status) {
    if (answered) { /* a refusal is an answer too: the run of misses ends */
        *failures = 0;
        return status == RNDIS_STATUS_SUCCESS ? RNDIS_HEALTH_OK : RNDIS_HEALTH_RESET;
    }
    if (*failures < RNDIS_KEEPALIVE_MISSES) ++*failures;
    return *failures >= RNDIS_KEEPALIVE_MISSES ? RNDIS_HEALTH_RESTART : RNDIS_HEALTH_OK;
}

RndisHealthAction rndis_reset_decision(uint64_t now, uint64_t last_reset, bool attempted, bool in_progress) {
    if (in_progress) return RNDIS_HEALTH_OK;
    if (attempted && (now < last_reset || now - last_reset < RNDIS_RESET_WINDOW_MS)) return RNDIS_HEALTH_RESTART;
    return RNDIS_HEALTH_RESET;
}

/* A completion of type with this id, at least minimum bytes, Status success. */
static const char *check_completion(const uint8_t *b, size_t n, uint32_t type, uint32_t id,
                                    size_t minimum, size_t *length) {
    if (n < minimum) return "short response";
    if (rndis_le32(b) != (type | RNDIS_COMPLETION)) return "unexpected message type";
    uint32_t l = rndis_le32(b + 4);
    if (l < minimum || l > n) return "invalid message length";
    if (rndis_le32(b + 8) != id) return "request id mismatch";
    if (rndis_le32(b + 12) != RNDIS_STATUS_SUCCESS) return "device reported failure status";
    *length = l;
    return NULL;
}

const char *rndis_parse_init_cmplt(const uint8_t *b, size_t n, uint32_t id, RndisInitInfo *info) {
    size_t l = 0;
    const char *e = check_completion(b, n, RNDIS_INITIALIZE_MSG, id, INIT_CMPLT_LENGTH, &l);
    if (e) return e;
    if (rndis_le32(b + 16) != RNDIS_MAJOR_VERSION) return "unsupported RNDIS major version";
    if (rndis_le32(b + 24) != RNDIS_DF_CONNECTIONLESS) return "device is not connectionless";
    if (rndis_le32(b + 28) != RNDIS_MEDIUM_802_3) return "medium is not 802.3";
    uint32_t packets = rndis_le32(b + 32), transfer = rndis_le32(b + 36), shift = rndis_le32(b + 40);
    if (!packets) return "MaxPacketsPerTransfer is zero";
    if (transfer < RNDIS_PACKET_HEADER + ETH_HEADER) return "MaxTransferSize too small";
    if (shift > RNDIS_ALIGNMENT_SHIFT_MAX) return "PacketAlignmentFactor too large";
    info->max_packets_per_transfer = packets;
    info->max_transfer_size = transfer;
    info->alignment_shift = shift;
    return NULL;
}

const char *rndis_parse_query_cmplt(const uint8_t *b, size_t n, uint32_t id,
                                    const uint8_t **data, uint32_t *length) {
    size_t l = 0;
    const char *e = check_completion(b, n, RNDIS_QUERY_MSG, id, QUERY_CMPLT_HEADER, &l);
    if (e) return e;
    uint32_t count = rndis_le32(b + 16), offset = rndis_le32(b + 20);
    if (!count) { *data = NULL; *length = 0; return NULL; }
    if (offset < QUERY_CMPLT_HEADER - OFFSET_BASE || offset > l - OFFSET_BASE) return "query offset outside message";
    size_t start = OFFSET_BASE + (size_t)offset;
    if (count > l - start) return "query data outside message";
    *data = b + start;
    *length = count;
    return NULL;
}

const char *rndis_parse_set_cmplt(const uint8_t *b, size_t n, uint32_t id) {
    size_t l = 0;
    return check_completion(b, n, RNDIS_SET_MSG, id, RNDIS_STATUS_CMPLT_LENGTH, &l);
}

const char *rndis_parse_indicate(const uint8_t *b, size_t n, uint32_t *status) {
    if (n < INDICATE_HEADER || rndis_le32(b) != RNDIS_INDICATE_STATUS_MSG) return "not an indication";
    uint32_t l = rndis_control_length(b);
    if (l < INDICATE_HEADER || l > n) return "invalid indication length";
    *status = rndis_le32(b + 8);
    return NULL;
}

const char *rndis_parse_mac(const uint8_t *data, uint32_t length, uint8_t mac[ETHER_ADDR_LEN]) {
    if (!data || length != ETHER_ADDR_LEN) return "MAC length is not 6";
    unsigned any = 0;
    for (unsigned i = 0; i < ETHER_ADDR_LEN; ++i) any |= data[i];
    if (!any || (data[0] & 1)) return "MAC is not a unicast address";
    memcpy(mac, data, ETHER_ADDR_LEN);
    return NULL;
}

static bool all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return false;
    return true;
}

static RndisFrameResult malformed(RndisCursor *c, const char **why, const char *reason) {
    *why = reason;
    c->left = 0; /* the caller drops the rest of the transfer */
    return RNDIS_FRAMES_MALFORMED;
}

RndisFrameResult rndis_next_frame(RndisCursor *c, const uint8_t **frame, size_t *length, const char **why) {
    *why = NULL;
    if (!c->left) return RNDIS_FRAMES_END;
    /* Devices may pad a transfer with zeros (including the one-byte short-packet pad). */
    if (c->left < MESSAGE_HEADER || rndis_le32(c->next) == 0) {
        if (all_zero(c->next, c->left)) { c->left = 0; return RNDIS_FRAMES_END; }
        return malformed(c, why, c->left < MESSAGE_HEADER ? "short trailing bytes" : "garbage after messages");
    }
    if (c->left < RNDIS_PACKET_HEADER) return malformed(c, why, "short packet header");
    if (rndis_le32(c->next) != RNDIS_PACKET_MSG) return malformed(c, why, "unexpected message type");
    size_t l = rndis_le32(c->next + 4), offset = rndis_le32(c->next + OFFSET_BASE), count = rndis_le32(c->next + 12);
    if (l < RNDIS_PACKET_HEADER || l > c->left) return malformed(c, why, "invalid message length");
    if (offset < PACKET_DATA_OFFSET || offset > l - OFFSET_BASE || count > l - OFFSET_BASE - offset)
        return malformed(c, why, "data outside message");
    const uint8_t *data = c->next + OFFSET_BASE + offset;
    c->next += l;
    c->left -= l;
    /* Out-of-band and per-packet-info fields are not needed and are ignored. */
    if (count < ETH_HEADER || count > ETH_FRAME_MAX) { *why = "frame size out of range"; return RNDIS_FRAME_SKIPPED; }
    *frame = data;
    *length = count;
    return RNDIS_FRAME;
}

size_t rndis_append_packet(uint8_t *buf, size_t used, size_t limit,
                           const uint8_t *frame, size_t n, uint32_t alignment_shift) {
    if (n < ETH_HEADER || n > ETH_FRAME_MAX || alignment_shift > RNDIS_ALIGNMENT_SHIFT_MAX) return 0;
    size_t message = RNDIS_PACKET_HEADER + n;
    size_t align = (size_t)1 << alignment_shift;
    size_t padded = (message + align - 1) & ~(align - 1);
    /* An unaligned end means the previous message went out unpadded: it was the last. */
    if (used > limit || used & (align - 1) || message > limit - used) return 0;
    /* Padding only places the next message; the last one may end without it. */
    if (padded > limit - used) padded = message;
    uint8_t *m = buf + used;
    memset(m, 0, RNDIS_PACKET_HEADER);
    rndis_put32(m, RNDIS_PACKET_MSG);
    rndis_put32(m + 4, (uint32_t)padded);
    rndis_put32(m + 8, PACKET_DATA_OFFSET);
    rndis_put32(m + 12, (uint32_t)n);
    memcpy(m + RNDIS_PACKET_HEADER, frame, n);
    memset(m + message, 0, padded - message);
    return padded;
}

/* Plan transfers with the endpoint's packet size, or the fallback when it gave none. */
static unsigned usb_packet_or_fallback(unsigned packet_size) {
    return packet_size ? packet_size : USB_PACKET_FALLBACK;
}

size_t rndis_transfer_limit(uint32_t max_transfer, size_t capacity, unsigned packet_size) {
    packet_size = usb_packet_or_fallback(packet_size);
    size_t limit = max_transfer < capacity - 1 ? max_transfer : capacity - 1;
    return limit && !(limit % packet_size) ? limit - 1 : limit;
}

size_t rndis_finish_transfer(uint8_t *buf, size_t used, size_t capacity, unsigned packet_size) {
    packet_size = usb_packet_or_fallback(packet_size);
    if (used && used % packet_size == 0 && used < capacity) {
        buf[used] = 0;
        return used + 1;
    }
    return used;
}
