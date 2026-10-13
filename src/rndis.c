#include "rndis.h"

#include <string.h>

uint32_t rndis_le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void rndis_put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (i * 8));
}

size_t rndis_build_init(uint8_t *b, uint32_t id, uint32_t max_transfer) {
    memset(b, 0, 24);
    rndis_put32(b, RNDIS_INITIALIZE_MSG);
    rndis_put32(b + 4, 24);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, 1); /* MajorVersion */
    rndis_put32(b + 16, 0); /* MinorVersion */
    rndis_put32(b + 20, max_transfer);
    return 24;
}

size_t rndis_build_query(uint8_t *b, uint32_t id, uint32_t oid) {
    memset(b, 0, 28);
    rndis_put32(b, RNDIS_QUERY_MSG);
    rndis_put32(b + 4, 28);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, oid);
    return 28; /* empty input buffer: length 0, offset 0, reserved 0 */
}

size_t rndis_build_set_u32(uint8_t *b, uint32_t id, uint32_t oid, uint32_t value) {
    memset(b, 0, 32);
    rndis_put32(b, RNDIS_SET_MSG);
    rndis_put32(b + 4, 32);
    rndis_put32(b + 8, id);
    rndis_put32(b + 12, oid);
    rndis_put32(b + 16, 4);  /* InformationBufferLength */
    rndis_put32(b + 20, 20); /* InformationBufferOffset, relative to RequestId */
    rndis_put32(b + 28, value);
    return 32;
}

size_t rndis_build_halt(uint8_t *b, uint32_t id) {
    memset(b, 0, 12);
    rndis_put32(b, RNDIS_HALT_MSG);
    rndis_put32(b + 4, 12);
    rndis_put32(b + 8, id);
    return 12;
}

size_t rndis_build_keepalive_cmplt(uint8_t *b, uint32_t id) {
    memset(b, 0, 16);
    rndis_put32(b, RNDIS_KEEPALIVE_MSG | RNDIS_COMPLETION);
    rndis_put32(b + 4, 16);
    rndis_put32(b + 8, id);
    return 16; /* Status 0 = success */
}

size_t rndis_build_keepalive(uint8_t *b, uint32_t id) {
    rndis_put32(b, RNDIS_KEEPALIVE_MSG);
    rndis_put32(b + 4, 12);
    rndis_put32(b + 8, id);
    return 12;
}

size_t rndis_build_reset(uint8_t *b) {
    rndis_put32(b, RNDIS_RESET_MSG);
    rndis_put32(b + 4, 12);
    rndis_put32(b + 8, 0); /* Reserved, not RequestId. */
    return 12;
}

uint32_t rndis_control_type(const uint8_t *b, size_t n) {
    if (n < 8) return 0;
    uint32_t l = rndis_le32(b + 4);
    if (l < 8 || l > n) return 0;
    return rndis_le32(b);
}

uint32_t rndis_control_id(const uint8_t *b, size_t n) {
    uint32_t type = rndis_control_type(b, n);
    return type && type != (RNDIS_RESET_MSG | RNDIS_COMPLETION) &&
           type != RNDIS_RESET_MSG && n >= 12 && rndis_le32(b + 4) >= 12 ? rndis_le32(b + 8) : 0;
}

bool rndis_completion_matches(const uint8_t *b, size_t n, uint32_t type, uint32_t id) {
    if (rndis_control_type(b, n) != (type | RNDIS_COMPLETION)) return false;
    if (type == RNDIS_RESET_MSG) return true;
    return n >= 12 && rndis_le32(b + 4) >= 12 && rndis_le32(b + 8) == id;
}

const char *rndis_parse_keepalive(const uint8_t *b, size_t n, uint32_t *id) {
    if (rndis_control_type(b, n) != RNDIS_KEEPALIVE_MSG || rndis_le32(b + 4) < 12)
        return "invalid keepalive";
    *id = rndis_le32(b + 8);
    return NULL;
}

const char *rndis_parse_status_cmplt(const uint8_t *b, size_t n, uint32_t type,
                                    uint32_t id, uint32_t *status) {
    if ((type != RNDIS_KEEPALIVE_MSG && type != RNDIS_SET_MSG) ||
        !rndis_completion_matches(b, n, type, id) || rndis_le32(b + 4) < 16)
        return "invalid status completion";
    *status = rndis_le32(b + 12);
    return NULL;
}

const char *rndis_parse_reset_cmplt(const uint8_t *b, size_t n, uint32_t *status,
                                   uint32_t *addressing_reset) {
    if (!rndis_completion_matches(b, n, RNDIS_RESET_MSG, 0) || rndis_le32(b + 4) < 16)
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
        if (b[1] == 0x24) {
            if (length < 3) return false;
            if (b[2] == 0x02) {
                if (length < 4) return false;
                found.acm_capabilities |= b[3];
            } else if (b[2] == 0x06) {
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
    if (n < 7 || b[0] < 7 || b[0] > n || b[1] != 5 || b[2] != out_endpoint ||
        (out_endpoint & 0x80) || (b[3] & 3) != 2) return 0;
    unsigned packet = (unsigned)b[4] | (unsigned)b[5] << 8;
    return packet == 8 || packet == 16 || packet == 32 || packet == 64 ||
           packet == 512 || packet == 1024 ? packet : 0;
}

bool rndis_keepalive_due(uint64_t now, uint64_t last_rx, bool outstanding) {
    return !outstanding && now >= last_rx && now - last_rx >= 5000;
}

RndisHealthAction rndis_keepalive_result(unsigned *failures, bool exchanged, uint32_t status) {
    if (exchanged) {
        if (status) return RNDIS_HEALTH_RESET;
        *failures = 0;
        return RNDIS_HEALTH_OK;
    }
    if (*failures < 3) ++*failures;
    return *failures >= 3 ? RNDIS_HEALTH_RESTART : RNDIS_HEALTH_OK;
}

RndisHealthAction rndis_reset_decision(uint64_t now, uint64_t last_reset, bool attempted, bool in_progress) {
    if (in_progress) return RNDIS_HEALTH_OK;
    if (attempted && (now < last_reset || now - last_reset < 30000)) return RNDIS_HEALTH_RESTART;
    return RNDIS_HEALTH_RESET;
}

/* Bounds checks subtract from trusted sizes instead of adding device-controlled values. */
static const char *completion(const uint8_t *b, size_t n, uint32_t type, uint32_t id,
                              size_t minimum, size_t *length) {
    if (n < minimum) return "short response";
    if (rndis_le32(b) != (type | RNDIS_COMPLETION)) return "unexpected message type";
    uint32_t l = rndis_le32(b + 4);
    if (l < minimum || l > n) return "invalid message length";
    if (rndis_le32(b + 8) != id) return "request id mismatch";
    if (rndis_le32(b + 12) != 0) return "device reported failure status";
    *length = l;
    return NULL;
}

const char *rndis_parse_init_cmplt(const uint8_t *b, size_t n, uint32_t id, RndisInitInfo *info) {
    size_t l = 0;
    const char *e = completion(b, n, RNDIS_INITIALIZE_MSG, id, 52, &l);
    if (e) return e;
    if (rndis_le32(b + 16) != 1) return "unsupported RNDIS major version";
    if (rndis_le32(b + 24) != 1) return "device is not connectionless";
    if (rndis_le32(b + 28) != 0) return "medium is not 802.3";
    uint32_t packets = rndis_le32(b + 32), transfer = rndis_le32(b + 36), shift = rndis_le32(b + 40);
    if (!packets) return "MaxPacketsPerTransfer is zero";
    if (transfer < RNDIS_PACKET_HEADER + ETH_HEADER) return "MaxTransferSize too small";
    if (shift > 7) return "PacketAlignmentFactor too large";
    info->max_packets_per_transfer = packets;
    info->max_transfer_size = transfer;
    info->alignment_shift = shift;
    return NULL;
}

const char *rndis_parse_query_cmplt(const uint8_t *b, size_t n, uint32_t id,
                                    const uint8_t **data, uint32_t *length) {
    size_t l = 0;
    const char *e = completion(b, n, RNDIS_QUERY_MSG, id, 24, &l);
    if (e) return e;
    uint32_t count = rndis_le32(b + 16), offset = rndis_le32(b + 20);
    if (!count) { *data = NULL; *length = 0; return NULL; }
    /* InformationBufferOffset is relative to RequestId (byte 8). */
    if (offset < 16 || offset > l - 8) return "query offset outside message";
    size_t start = 8 + (size_t)offset;
    if (count > l - start) return "query data outside message";
    *data = b + start;
    *length = count;
    return NULL;
}

const char *rndis_parse_set_cmplt(const uint8_t *b, size_t n, uint32_t id) {
    size_t l = 0;
    return completion(b, n, RNDIS_SET_MSG, id, 16, &l);
}

const char *rndis_parse_indicate(const uint8_t *b, size_t n, uint32_t *status) {
    if (n < 20 || rndis_le32(b) != RNDIS_INDICATE_STATUS_MSG) return "not an indication";
    uint32_t l = rndis_le32(b + 4);
    if (l < 20 || l > n) return "invalid indication length";
    *status = rndis_le32(b + 8);
    return NULL;
}

const char *rndis_parse_mac(const uint8_t *data, uint32_t length, uint8_t mac[6]) {
    if (!data || length != 6) return "MAC length is not 6";
    unsigned any = 0;
    for (unsigned i = 0; i < 6; ++i) any |= data[i];
    if (!any || (data[0] & 1)) return "MAC is not a unicast address";
    memcpy(mac, data, 6);
    return NULL;
}

static bool all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return false;
    return true;
}

int rndis_next_frame(RndisCursor *c, const uint8_t **frame, size_t *length, const char **why) {
    *why = NULL;
    while (c->n) {
        /* Devices may pad a transfer with zeros (including the one-byte short-packet pad). */
        if (c->n < 8 || rndis_le32(c->p) == 0) {
            if (all_zero(c->p, c->n)) { c->n = 0; return 0; }
            *why = c->n < 8 ? "short trailing bytes" : "garbage after messages";
            c->n = 0;
            return -1;
        }
        if (c->n < RNDIS_PACKET_HEADER) { *why = "short packet header"; c->n = 0; return -1; }
        if (rndis_le32(c->p) != RNDIS_PACKET_MSG) { *why = "unexpected message type"; c->n = 0; return -1; }
        size_t l = rndis_le32(c->p + 4), offset = rndis_le32(c->p + 8), count = rndis_le32(c->p + 12);
        if (l < RNDIS_PACKET_HEADER || l > c->n) { *why = "invalid message length"; c->n = 0; return -1; }
        if (offset < 36 || offset > l - 8 || count > l - 8 - offset) {
            *why = "data outside message"; c->n = 0; return -1;
        }
        const uint8_t *data = c->p + 8 + offset;
        c->p += l;
        c->n -= l;
        /* Out-of-band and per-packet-info fields are not needed and are ignored. */
        if (count < ETH_HEADER || count > ETH_FRAME_MAX) { *why = "frame size out of range"; return 2; }
        *frame = data;
        *length = count;
        return 1;
    }
    return 0;
}

size_t rndis_append_packet(uint8_t *buf, size_t used, size_t limit,
                           const uint8_t *frame, size_t n, uint32_t alignment_shift) {
    if (n < ETH_HEADER || n > ETH_FRAME_MAX || alignment_shift > 7) return 0;
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
    rndis_put32(m + 8, 36); /* DataOffset relative to byte 8: data starts at byte 44 */
    rndis_put32(m + 12, (uint32_t)n);
    memcpy(m + RNDIS_PACKET_HEADER, frame, n);
    memset(m + message, 0, padded - message);
    return padded;
}

size_t rndis_finish_transfer(uint8_t *buf, size_t used, size_t capacity, unsigned packet_size) {
    if (!packet_size) packet_size = 512; /* Unknown endpoint: retain the old fallback. */
    if (used && used % packet_size == 0 && used < capacity) {
        buf[used] = 0;
        return used + 1;
    }
    return used;
}
