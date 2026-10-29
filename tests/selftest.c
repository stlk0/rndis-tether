/* Offline tests for rndis.c, the BPF record parser, the settings file, the interface
 * marker, device text and the status in words (cli.c). No USB, network or root.
 * Built with UBSan + Guard Malloc by `make check`. */
#include "cli.h"
#include "config.h"
#include "log.h"
#include "netif.h"
#include "rndis.h"
#include "runtime.h"

#include <fcntl.h>
#include <net/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned tests, failures;
#define CHECK(x) do { ++tests; if (!(x)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

static uint32_t seed = 0x52444e53u;
static uint32_t rnd(void) { seed = seed * 1664525u + 1013904223u; return seed; }

static size_t make_init_cmplt(uint8_t *b, uint32_t id) {
    memset(b, 0, 52);
    rndis_put32(b, RNDIS_INITIALIZE_MSG | RNDIS_COMPLETION);
    rndis_put32(b + 4, 52);
    rndis_put32(b + 8, id);
    rndis_put32(b + 16, 1);    /* major */
    rndis_put32(b + 24, 1);    /* connectionless */
    rndis_put32(b + 32, 1);    /* max packets per transfer */
    rndis_put32(b + 36, 1580); /* Linux gadget value */
    return 52;
}

static size_t make_query_cmplt(uint8_t *b, uint32_t id, const uint8_t *data, uint32_t n) {
    memset(b, 0, 24 + n);
    rndis_put32(b, RNDIS_QUERY_MSG | RNDIS_COMPLETION);
    rndis_put32(b + 4, 24 + n);
    rndis_put32(b + 8, id);
    rndis_put32(b + 16, n);
    rndis_put32(b + 20, 16);
    memcpy(b + 24, data, n);
    return 24 + n;
}

static void test_builders(void) {
    uint8_t b[64];
    CHECK(rndis_build_init(b, 7, RNDIS_RX_TRANSFER) == 24);
    CHECK(rndis_le32(b) == RNDIS_INITIALIZE_MSG && rndis_le32(b + 4) == 24 && rndis_le32(b + 8) == 7);
    CHECK(rndis_le32(b + 12) == 1 && rndis_le32(b + 16) == 0 && rndis_le32(b + 20) == RNDIS_RX_TRANSFER);
    CHECK(rndis_build_query(b, 8, OID_802_3_PERMANENT_ADDRESS) == 28);
    CHECK(rndis_le32(b) == RNDIS_QUERY_MSG && rndis_le32(b + 12) == OID_802_3_PERMANENT_ADDRESS);
    CHECK(rndis_build_set_u32(b, 9, OID_GEN_CURRENT_PACKET_FILTER, 13) == 32);
    CHECK(rndis_le32(b + 16) == 4 && rndis_le32(b + 20) == 20 && rndis_le32(b + 28) == 13);
    /* InformationBufferOffset 20 is relative to byte 8, so the value sits at byte 28. */
    CHECK(8 + rndis_le32(b + 20) == 28);
    CHECK(rndis_build_halt(b, 10) == 12 && rndis_le32(b) == RNDIS_HALT_MSG && rndis_le32(b + 8) == 10);
    CHECK(rndis_build_keepalive_cmplt(b, 11) == 16);
    CHECK(rndis_le32(b) == (RNDIS_KEEPALIVE_MSG | RNDIS_COMPLETION) && rndis_le32(b + 8) == 11 && !rndis_le32(b + 12));
}

static void test_control_parsers(void) {
    uint8_t b[RNDIS_CONTROL_CAP];
    RndisInitInfo info;
    size_t n = make_init_cmplt(b, 1);
    CHECK(!rndis_parse_init_cmplt(b, n, 1, &info));
    CHECK(info.max_packets_per_transfer == 1 && info.max_transfer_size == 1580 && info.alignment_shift == 0);
    for (size_t k = 0; k < n; ++k) CHECK(rndis_parse_init_cmplt(b, k, 1, &info) != NULL);
    CHECK(rndis_parse_init_cmplt(b, n, 2, &info) != NULL);
    const struct { size_t offset; uint32_t value; } bad[] = {
        {0, RNDIS_INITIALIZE_MSG}, {4, 51}, {4, 53}, {12, 1}, {16, 2}, {24, 0}, {28, 1},
        {32, 0}, {36, 57}, {40, 8}, {4, UINT32_MAX}, {36, 0},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        make_init_cmplt(b, 1);
        rndis_put32(b + bad[i].offset, bad[i].value);
        CHECK(rndis_parse_init_cmplt(b, n, 1, &info) != NULL);
    }
    make_init_cmplt(b, 1);
    rndis_put32(b + 32, 8);
    rndis_put32(b + 36, 9000);
    rndis_put32(b + 40, 2);
    CHECK(!rndis_parse_init_cmplt(b, n, 1, &info) && info.max_packets_per_transfer == 8 && info.alignment_shift == 2);

    const uint8_t mac_bytes[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t *data = NULL;
    uint32_t length = 0;
    uint8_t mac[6];
    n = make_query_cmplt(b, 3, mac_bytes, 6);
    CHECK(!rndis_parse_query_cmplt(b, n, 3, &data, &length) && length == 6);
    CHECK(!rndis_parse_mac(data, length, mac) && !memcmp(mac, mac_bytes, 6));
    for (size_t k = 0; k < n; ++k) CHECK(rndis_parse_query_cmplt(b, k, 3, &data, &length) != NULL);
    rndis_put32(b + 20, 15);
    CHECK(rndis_parse_query_cmplt(b, n, 3, &data, &length) != NULL);
    rndis_put32(b + 20, 17); /* data would run past the message */
    CHECK(rndis_parse_query_cmplt(b, n, 3, &data, &length) != NULL);
    rndis_put32(b + 20, UINT32_MAX);
    CHECK(rndis_parse_query_cmplt(b, n, 3, &data, &length) != NULL);
    n = make_query_cmplt(b, 3, mac_bytes, 6);
    rndis_put32(b + 16, UINT32_MAX);
    CHECK(rndis_parse_query_cmplt(b, n, 3, &data, &length) != NULL);
    n = make_query_cmplt(b, 4, mac_bytes, 0);
    CHECK(!rndis_parse_query_cmplt(b, n, 4, &data, &length) && length == 0 && data == NULL);
    CHECK(rndis_parse_mac(NULL, 0, mac) != NULL);
    const uint8_t multicast[6] = {0x01, 0, 0x5e, 0, 0, 1}, zero[6] = {0};
    CHECK(rndis_parse_mac(multicast, 6, mac) != NULL);
    CHECK(rndis_parse_mac(zero, 6, mac) != NULL);
    CHECK(rndis_parse_mac(mac_bytes, 5, mac) != NULL);

    memset(b, 0, 16);
    rndis_put32(b, RNDIS_SET_MSG | RNDIS_COMPLETION);
    rndis_put32(b + 4, 16);
    rndis_put32(b + 8, 5);
    CHECK(!rndis_parse_set_cmplt(b, 16, 5));
    CHECK(rndis_parse_set_cmplt(b, 15, 5) != NULL);
    rndis_put32(b + 12, 0xc0000001u);
    CHECK(rndis_parse_set_cmplt(b, 16, 5) != NULL);

    uint32_t status = 0;
    memset(b, 0, 20);
    rndis_put32(b, RNDIS_INDICATE_STATUS_MSG);
    rndis_put32(b + 4, 20);
    rndis_put32(b + 8, RNDIS_STATUS_MEDIA_DISCONNECT);
    CHECK(!rndis_parse_indicate(b, 20, &status) && status == RNDIS_STATUS_MEDIA_DISCONNECT);
    CHECK(rndis_parse_indicate(b, 19, &status) != NULL);
    CHECK(rndis_control_type(b, 20) == RNDIS_INDICATE_STATUS_MSG);
    CHECK(rndis_control_type(b, 19) == 0);
    CHECK(rndis_control_type(b, 7) == 0);
    rndis_put32(b + 4, 4);
    CHECK(rndis_control_type(b, 20) == 0);
}

static void test_health_messages(void) {
    uint8_t b[32];
    uint32_t id = 0, status = 0, addressing = 0;
    CHECK(rndis_build_keepalive(b, 42) == 12);
    CHECK(rndis_le32(b) == RNDIS_KEEPALIVE_MSG && rndis_le32(b + 4) == 12);
    CHECK(!rndis_parse_keepalive(b, 12, &id) && id == 42);
    for (size_t k = 0; k < 12; ++k) CHECK(rndis_parse_keepalive(b, k, &id) != NULL);
    const uint32_t lengths[] = {0, 7, 8, 11, 13, UINT32_MAX};
    for (size_t k = 0; k < sizeof lengths / sizeof *lengths; ++k) {
        rndis_put32(b + 4, lengths[k]);
        CHECK(rndis_parse_keepalive(b, 12, &id) != NULL);
    }
    CHECK(rndis_build_reset(b) == 12 && rndis_le32(b) == RNDIS_RESET_MSG);
    CHECK(rndis_le32(b + 4) == 12 && rndis_le32(b + 8) == 0);
    CHECK(rndis_control_id(b, 12) == 0);

    const uint32_t types[] = {RNDIS_KEEPALIVE_MSG, RNDIS_SET_MSG, RNDIS_RESET_MSG};
    for (size_t t = 0; t < sizeof types / sizeof *types; ++t) {
        uint32_t type = types[t];
        rndis_build_keepalive_cmplt(b, 42);
        rndis_put32(b, type | RNDIS_COMPLETION);
        if (type == RNDIS_RESET_MSG) { rndis_put32(b + 8, 0); rndis_put32(b + 12, 1); }
        CHECK(rndis_completion_matches(b, 16, type, 42));
        CHECK(rndis_completion_matches(b, 16, type, 43) == (type == RNDIS_RESET_MSG));
        CHECK(!rndis_completion_matches(b, 16, RNDIS_QUERY_MSG, 42));
        for (size_t k = 0; k <= 16; ++k) {
            const char *e = type == RNDIS_RESET_MSG ? rndis_parse_reset_cmplt(b, k, &status, &addressing) :
                rndis_parse_status_cmplt(b, k, type, 42, &status);
            CHECK((e == NULL) == (k == 16));
        }
        CHECK(status == 0);
        if (type == RNDIS_RESET_MSG) CHECK(addressing == 1 && rndis_control_id(b, 16) == 0);
        /* Device rejection is a valid envelope; the health logic must see its status. */
        rndis_put32(b + (type == RNDIS_RESET_MSG ? 8 : 12), 0xc0000001u);
        CHECK(!(type == RNDIS_RESET_MSG ? rndis_parse_reset_cmplt(b, 16, &status, &addressing) :
                rndis_parse_status_cmplt(b, 16, type, 42, &status)) && status == 0xc0000001u);
        const uint32_t bad_lengths[] = {0, 8, 12, 15, 17, UINT32_MAX};
        for (size_t k = 0; k < sizeof bad_lengths / sizeof *bad_lengths; ++k) {
            rndis_put32(b + 4, bad_lengths[k]);
            CHECK((type == RNDIS_RESET_MSG ? rndis_parse_reset_cmplt(b, 16, &status, &addressing) :
                   rndis_parse_status_cmplt(b, 16, type, 42, &status)) != NULL);
        }
    }
    CHECK(rndis_parse_status_cmplt(b, 16, RNDIS_QUERY_MSG, 42, &status) != NULL);
}

static void test_descriptors(void) {
    uint8_t b[] = {5, 0x24, 0, 0x10, 1, 4, 0x24, 2, 0, 5, 0x24, 6, 3, 7};
    RndisCdcInfo info = {0};
    CHECK(rndis_parse_cdc(b, sizeof b, 3, &info) && info.has_union && info.union_slave == 7 && !info.acm_capabilities);
    CHECK(rndis_parse_cdc(b, sizeof b, 4, &info) && !info.has_union);
    for (size_t k = 0; k < sizeof b; ++k)
        CHECK(rndis_parse_cdc(b, k, 3, &info) == (k == 0 || k == 5 || k == 9));
    b[8] = 2;
    CHECK(rndis_parse_cdc(b, sizeof b, 3, &info) && info.acm_capabilities == 2);
    b[13] = 3;
    CHECK(!rndis_parse_cdc(b, sizeof b, 3, &info)); /* self-referencing union */
    b[13] = 7;
    for (unsigned length = 0; length <= 255; ++length) {
        uint8_t descriptor[] = {(uint8_t)length, 0x24, 6, 3, 7};
        CHECK(rndis_parse_cdc(descriptor, sizeof descriptor, 3, &info) == (length == 5));
    }
    const uint8_t short_acm[] = {3, 0x24, 2}, short_cs[] = {2, 0x24};
    CHECK(!rndis_parse_cdc(short_acm, sizeof short_acm, 3, &info));
    CHECK(!rndis_parse_cdc(short_cs, sizeof short_cs, 3, &info));
    const uint8_t duplicate[] = {5, 0x24, 6, 3, 7, 5, 0x24, 6, 3, 8};
    CHECK(!rndis_parse_cdc(duplicate, sizeof duplicate, 3, &info));
    const uint8_t unknown[] = {3, 0x24, 0xfe, 2, 0x30};
    CHECK(rndis_parse_cdc(unknown, sizeof unknown, 3, &info) && !info.has_union);

    uint8_t endpoint[] = {7, 5, 2, 2, 0, 4, 0};
    CHECK(rndis_bulk_packet_size(endpoint, sizeof endpoint, 2) == 1024);
    for (size_t k = 0; k < sizeof endpoint; ++k) CHECK(!rndis_bulk_packet_size(endpoint, k, 2));
    CHECK(!rndis_bulk_packet_size(endpoint, sizeof endpoint, 3));
    endpoint[2] = 0x82;
    CHECK(!rndis_bulk_packet_size(endpoint, sizeof endpoint, 0x82));
    endpoint[2] = 2;
    endpoint[3] = 3;
    CHECK(!rndis_bulk_packet_size(endpoint, sizeof endpoint, 2));
    endpoint[3] = 2;
    for (unsigned packet = 0; packet <= 2048; ++packet) {
        endpoint[4] = (uint8_t)packet;
        endpoint[5] = (uint8_t)(packet >> 8);
        bool valid = packet == 8 || packet == 16 || packet == 32 || packet == 64 || packet == 512 || packet == 1024;
        CHECK(rndis_bulk_packet_size(endpoint, sizeof endpoint, 2) == (valid ? packet : 0));
    }
    endpoint[0] = 255;
    CHECK(!rndis_bulk_packet_size(endpoint, sizeof endpoint, 2));
}

static void test_health_policy(void) {
    CHECK(!rndis_keepalive_due(5999, 1000, false));
    CHECK(rndis_keepalive_due(6000, 1000, false));
    CHECK(!rndis_keepalive_due(6000, 1000, true));
    CHECK(!rndis_keepalive_due(999, 1000, false));
    CHECK(rndis_keepalive_due(UINT64_MAX, UINT64_MAX - 5000, false));
    for (uint64_t now = 0; now < 60000; now += 1000) CHECK(!rndis_keepalive_due(now, now, false));
    unsigned failures = 0;
    CHECK(rndis_keepalive_result(&failures, false, 0) == RNDIS_HEALTH_OK && failures == 1);
    CHECK(rndis_keepalive_result(&failures, false, 0) == RNDIS_HEALTH_OK && failures == 2);
    CHECK(rndis_keepalive_result(&failures, true, 0) == RNDIS_HEALTH_OK && failures == 0);
    CHECK(rndis_keepalive_result(&failures, true, 1) == RNDIS_HEALTH_RESET && failures == 0);
    CHECK(rndis_keepalive_result(&failures, false, 0) == RNDIS_HEALTH_OK);
    CHECK(rndis_keepalive_result(&failures, false, 0) == RNDIS_HEALTH_OK);
    CHECK(rndis_keepalive_result(&failures, false, 0) == RNDIS_HEALTH_RESTART && failures == 3);
    CHECK(rndis_keepalive_result(&failures, false, 0) == RNDIS_HEALTH_RESTART && failures == 3);
    CHECK(rndis_reset_decision(0, 0, false, false) == RNDIS_HEALTH_RESET);
    CHECK(rndis_reset_decision(30000, 1, true, false) == RNDIS_HEALTH_RESTART);
    CHECK(rndis_reset_decision(30001, 1, true, false) == RNDIS_HEALTH_RESET);
    CHECK(rndis_reset_decision(100, 200, true, false) == RNDIS_HEALTH_RESTART);
    CHECK(rndis_reset_decision(UINT64_MAX, UINT64_MAX - 30000, true, false) == RNDIS_HEALTH_RESET);
    CHECK(rndis_reset_decision(30001, 1, true, true) == RNDIS_HEALTH_OK);
}

static void make_frame(uint8_t *f, size_t n, uint8_t tag) {
    for (size_t i = 0; i < n; ++i) f[i] = (uint8_t)(tag + i * 7);
}

static void test_data_path(void) {
    static uint8_t buffer[RNDIS_RX_TRANSFER + 64];
    uint8_t frames[5][ETH_FRAME_MAX];
    const size_t sizes[5] = {60, 1514, 14, 468, 1518};
    for (uint32_t shift = 0; shift <= 3; ++shift) {
        size_t used = 0;
        for (unsigned i = 0; i < 5; ++i) {
            make_frame(frames[i], sizes[i], (uint8_t)(i * 31 + shift));
            size_t added = rndis_append_packet(buffer, used, RNDIS_RX_TRANSFER, frames[i], sizes[i], shift);
            CHECK(added >= RNDIS_PACKET_HEADER + sizes[i] && added % ((size_t)1 << shift) == 0);
            used += added;
        }
        RndisCursor c = {buffer, used};
        const uint8_t *frame = NULL;
        size_t length = 0;
        const char *why = NULL;
        for (unsigned i = 0; i < 5; ++i) {
            CHECK(rndis_next_frame(&c, &frame, &length, &why) == 1);
            CHECK(length == sizes[i] && !memcmp(frame, frames[i], sizes[i]));
        }
        CHECK(rndis_next_frame(&c, &frame, &length, &why) == 0);
    }

    /* Size limits and invalid frames are refused by the builder. */
    uint8_t f[ETH_FRAME_MAX + 1];
    make_frame(f, sizeof f, 1);
    CHECK(rndis_append_packet(buffer, 0, 1580, f, 1514, 0) == 1558);
    CHECK(rndis_append_packet(buffer, 0, 1557, f, 1514, 0) == 0);
    CHECK(rndis_append_packet(buffer, 1000, 1580, f, 1514, 0) == 0);
    CHECK(rndis_append_packet(buffer, 2000, 1580, f, 60, 0) == 0);
    CHECK(rndis_append_packet(buffer, 0, 4096, f, 13, 0) == 0);
    CHECK(rndis_append_packet(buffer, 0, 4096, f, ETH_FRAME_MAX + 1, 0) == 0);
    CHECK(rndis_append_packet(buffer, 0, 4096, f, 60, 8) == 0);
    /* The last message of a transfer needs no padding: a 1514-byte frame fits a 1558-byte limit. */
    CHECK(rndis_append_packet(buffer, 0, 1558, f, 1514, 2) == 1558 && rndis_le32(buffer + 4) == 1558);
    CHECK(rndis_append_packet(buffer, 1558, 4096, f, 60, 2) == 0); /* ...and closes the transfer */
    CHECK(rndis_append_packet(buffer, 0, 1560, f, 1514, 2) == 1560 && rndis_le32(buffer + 4) == 1560);
    CHECK(rndis_append_packet(buffer, 1560, 4096, f, 60, 2) == 104);

    /* A transfer that is an exact multiple of the bulk packet size gets one zero pad byte. */
    size_t used = rndis_append_packet(buffer, 0, 4096, f, 468, 0); /* 44 + 468 = 512 */
    CHECK(used == 512);
    CHECK(rndis_finish_transfer(buffer, used, sizeof buffer, 512) == 513 && buffer[512] == 0);
    CHECK(rndis_finish_transfer(buffer, 100, sizeof buffer, 512) == 100);
    CHECK(rndis_finish_transfer(buffer, 512, 512, 512) == 512);
    CHECK(rndis_finish_transfer(buffer, 512, sizeof buffer, 1024) == 512);
    CHECK(rndis_finish_transfer(buffer, 1024, sizeof buffer, 1024) == 1025 && !buffer[1024]);
    uint8_t pad[128];
    CHECK(rndis_finish_transfer(pad, 64, sizeof pad, 64) == 65 && !pad[64]);
    CHECK(rndis_finish_transfer(buffer, 0, sizeof buffer, 0) == 0);
    CHECK(rndis_finish_transfer(buffer, 512, sizeof buffer, 0) == 513);
    CHECK(rndis_finish_transfer(buffer, SIZE_MAX, sizeof buffer, 1) == SIZE_MAX);
    /* ...which the receiving parser accepts as padding. */
    RndisCursor c = {buffer, 513};
    const uint8_t *frame = NULL;
    size_t length = 0;
    const char *why = NULL;
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 1 && length == 468);
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 0);

    /* Zero tail of any length after valid messages is padding. */
    used = rndis_append_packet(buffer, 0, 4096, f, 100, 0);
    memset(buffer + used, 0, 300);
    c = (RndisCursor){buffer, used + 300};
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 1);
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 0);

    /* Non-zero garbage after a message: frame is delivered, then the rest is refused. */
    buffer[used] = 0xff;
    c = (RndisCursor){buffer, used + 300};
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 1);
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == -1 && why);
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 0);

    /* A frame of unacceptable size is skipped (2) without losing the next message. */
    size_t first = rndis_append_packet(buffer, 0, 4096, f, 60, 0);
    rndis_put32(buffer + 12, 10); /* DataLength 10 < Ethernet header */
    used = first + rndis_append_packet(buffer, first, 4096, f, 70, 0);
    c = (RndisCursor){buffer, used};
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 2);
    CHECK(rndis_next_frame(&c, &frame, &length, &why) == 1 && length == 70);

    /* Header field corruption never reads outside the buffer. */
    const size_t offsets[] = {0, 4, 8, 12};
    const uint32_t values[] = {0, 2, 43, 45, 35, 1000, UINT32_MAX, 0x80000000u};
    for (size_t i = 0; i < sizeof offsets / sizeof *offsets; ++i) {
        for (size_t v = 0; v < sizeof values / sizeof *values; ++v) {
            used = rndis_append_packet(buffer, 0, 4096, f, 100, 0);
            rndis_put32(buffer + offsets[i], values[v]);
            c = (RndisCursor){buffer, used};
            int r;
            unsigned guard = 0;
            while ((r = rndis_next_frame(&c, &frame, &length, &why)) != 0 && guard++ < 4)
                if (r == 1) CHECK(frame >= buffer && frame + length <= buffer + used);
            CHECK(guard < 4);
        }
    }
    /* Every truncation of a valid message is refused or ends cleanly. */
    used = rndis_append_packet(buffer, 0, 4096, f, 100, 0);
    for (size_t k = 1; k < used; ++k) {
        c = (RndisCursor){buffer, k};
        CHECK(rndis_next_frame(&c, &frame, &length, &why) <= 0);
    }
}

/* Builds one record the way the kernel does: an 18-byte header (SIZEOF_BPF_HDR, not the
 * 20-byte padded struct), frame right after it, next record word-aligned. */
static size_t put_bpf_record(uint8_t *at, uint32_t caplen, uint32_t datalen, uint8_t fill) {
    uint8_t header[18] = {0};
    memcpy(header + 8, &caplen, 4);
    memcpy(header + 12, &datalen, 4);
    header[16] = 18;
    memcpy(at, header, sizeof header);
    memset(at + 18, fill, caplen);
    return BPF_WORDALIGN(18 + caplen);
}

static void test_bpf_batch_records(void) {
    /* What bpf_put writes for the kernel, bpf_next reads back: same layout as read(2). */
    uint8_t buffer[256], a[60], b[61];
    memset(a, 0xa1, sizeof a);
    memset(b, 0xb2, sizeof b);
    size_t used = bpf_put(buffer, 0, sizeof buffer, a, sizeof a);
    CHECK(used == BPF_WORDALIGN(sizeof(struct bpf_hdr) + sizeof a));
    size_t second = bpf_put(buffer, used, sizeof buffer, b, sizeof b);
    CHECK(second == BPF_WORDALIGN(sizeof(struct bpf_hdr) + sizeof b));
    used += second;
    BpfCursor cursor = {buffer, used};
    const uint8_t *frame = NULL;
    size_t length = 0;
    bool truncated = true;
    CHECK(bpf_next(&cursor, &frame, &length, &truncated) && !truncated && length == sizeof a && !memcmp(frame, a, sizeof a));
    CHECK(bpf_next(&cursor, &frame, &length, &truncated) && !truncated && length == sizeof b && !memcmp(frame, b, sizeof b));
    CHECK(!bpf_next(&cursor, &frame, &length, &truncated));
    CHECK(!bpf_put(buffer, used, used + sizeof(struct bpf_hdr) + 10, a, sizeof a)); /* does not fit */
    CHECK(!bpf_put(buffer, sizeof buffer + 1, sizeof buffer, a, sizeof a));
}

static void test_bpf_records(void) {
    _Alignas(8) uint8_t buffer[1024];
    memset(buffer, 0, sizeof buffer);
    size_t at = put_bpf_record(buffer, 60, 60, 0xa0);
    at += put_bpf_record(buffer + at, 99, 200, 0xa1); /* truncated capture */
    at += put_bpf_record(buffer + at, 14, 14, 0xa2);
    BpfCursor c = {buffer, at};
    const uint8_t *frame = NULL;
    size_t length = 0;
    bool truncated = false;
    CHECK(bpf_next(&c, &frame, &length, &truncated) && length == 60 && !truncated && frame[0] == 0xa0 && frame == buffer + 18);
    CHECK(bpf_next(&c, &frame, &length, &truncated) && length == 99 && truncated && frame[0] == 0xa1);
    CHECK(bpf_next(&c, &frame, &length, &truncated) && length == 14 && frame[13] == 0xa2);
    CHECK(!bpf_next(&c, &frame, &length, &truncated));

    /* Regression: header bytes of a real read on macOS 26 (feth61, 449-byte read). */
    static const uint8_t real[18] = {0xba, 0xfa, 0xcc, 0x6a, 0x30, 0x71, 0x0d, 0x00, 0xaf, 0x01,
                                     0x00, 0x00, 0xaf, 0x01, 0x00, 0x00, 0x12, 0x00};
    memset(buffer, 0x45, 449);
    memcpy(buffer, real, sizeof real);
    c = (BpfCursor){buffer, 449};
    CHECK(bpf_next(&c, &frame, &length, &truncated) && length == 431 && !truncated && frame == buffer + 18);
    CHECK(!bpf_next(&c, &frame, &length, &truncated));

    put_bpf_record(buffer, 1000, 1000, 0); /* claims more than the buffer holds */
    c = (BpfCursor){buffer, 100};
    CHECK(!bpf_next(&c, &frame, &length, &truncated));
    put_bpf_record(buffer, 10, 10, 0);
    buffer[16] = 2; /* header length shorter than the header itself */
    c = (BpfCursor){buffer, 100};
    CHECK(!bpf_next(&c, &frame, &length, &truncated));
    c = (BpfCursor){buffer, 17};
    CHECK(!bpf_next(&c, &frame, &length, &truncated));
}

static void fuzz(void) {
    static uint8_t buffer[RNDIS_RX_TRANSFER];
    unsigned inputs = 0;
    RndisInitInfo info;
    const uint8_t *data;
    uint32_t length32, status;
    uint8_t mac[6];
    for (unsigned i = 0; i < 200000; ++i) {
        size_t n = rnd() % 4096;
        for (size_t j = 0; j < n; ++j) buffer[j] = (uint8_t)(rnd() >> 24);
        if (i % 3 == 0 && n >= 16) { /* keep a plausible header to reach deeper branches */
            rndis_put32(buffer, i % 2 ? RNDIS_PACKET_MSG : (RNDIS_QUERY_MSG | RNDIS_COMPLETION));
            rndis_put32(buffer + 4, (uint32_t)(rnd() % (n + 8)));
            rndis_put32(buffer + 8, rnd() % 64);
            rndis_put32(buffer + 12, i % 2 ? rnd() % 2048 : 0);
        }
        if (i % 5 == 0 && n >= 16) {
            const uint32_t types[] = {RNDIS_KEEPALIVE_MSG, RNDIS_KEEPALIVE_MSG | RNDIS_COMPLETION,
                                      RNDIS_RESET_MSG | RNDIS_COMPLETION, RNDIS_SET_MSG | RNDIS_COMPLETION};
            rndis_put32(buffer, types[i % 4]);
            rndis_put32(buffer + 4, (uint32_t)(rnd() % (n + 8)));
        } else if (i % 7 == 0 && n >= 5) {
            buffer[0] = (uint8_t)(rnd() % 8);
            buffer[1] = 0x24;
            buffer[2] = i % 2 ? 2 : 6;
        } else if (i % 11 == 0 && n >= 7) {
            buffer[0] = 7; buffer[1] = 5; buffer[2] = (uint8_t)i; buffer[3] = 2;
        }
        uint8_t *copy = malloc(n ? n : 1); /* exact-size heap copy: Guard Malloc catches over-reads */
        memcpy(copy, buffer, n);
        (void)rndis_parse_init_cmplt(copy, n, 1, &info);
        if (!rndis_parse_query_cmplt(copy, n, rndis_control_id(copy, n), &data, &length32) && data) {
            CHECK(data >= copy && data + length32 <= copy + n);
            (void)rndis_parse_mac(data, length32, mac);
        }
        (void)rndis_parse_set_cmplt(copy, n, 1);
        (void)rndis_parse_indicate(copy, n, &status);
        (void)rndis_control_type(copy, n);
        uint32_t id, addressing;
        (void)rndis_parse_keepalive(copy, n, &id);
        (void)rndis_parse_status_cmplt(copy, n, RNDIS_KEEPALIVE_MSG, rndis_control_id(copy, n), &status);
        (void)rndis_parse_status_cmplt(copy, n, RNDIS_SET_MSG, rndis_control_id(copy, n), &status);
        (void)rndis_parse_reset_cmplt(copy, n, &status, &addressing);
        (void)rndis_completion_matches(copy, n, RNDIS_RESET_MSG, 0);
        RndisCdcInfo cdc;
        (void)rndis_parse_cdc(copy, n, (uint8_t)i, &cdc);
        (void)rndis_bulk_packet_size(copy, n, (uint8_t)i);
        uint8_t request[32];
        (void)rndis_build_keepalive(request, rnd());
        (void)rndis_parse_keepalive(request, 12, &id);
        (void)rndis_build_reset(request);
        (void)rndis_build_keepalive_cmplt(request, id);
        (void)rndis_parse_status_cmplt(request, 16, RNDIS_KEEPALIVE_MSG, id, &status);
        (void)rndis_finish_transfer(request, rnd() % 34, sizeof request, rnd() % 1025);
        uint64_t now = (uint64_t)rnd() << 32 | rnd(), last = (uint64_t)rnd() << 32 | rnd();
        (void)rndis_keepalive_due(now, last, i % 2 != 0);
        unsigned failed = rnd();
        (void)rndis_keepalive_result(&failed, i % 2 != 0, rnd());
        (void)rndis_reset_decision(now, last, i % 2 != 0, i % 3 == 0);
        RndisCursor c = {copy, n};
        const uint8_t *frame;
        size_t length;
        const char *why;
        int r;
        unsigned guard = 0;
        while ((r = rndis_next_frame(&c, &frame, &length, &why)) != 0 && guard++ < 1000)
            if (r == 1) { volatile uint8_t sink = frame[length - 1]; (void)sink; }
        CHECK(guard < 1000);
        BpfCursor b = {copy, n};
        bool truncated;
        guard = 0;
        while (bpf_next(&b, &frame, &length, &truncated) && guard++ < 1000)
            if (length) { volatile uint8_t sink = frame[length - 1]; (void)sink; }
        free(copy);
        ++inputs;
    }
    printf("fuzz: %u random inputs\n", inputs);
}

static bool load_text(Config *c, const char *text, char *why, size_t why_size) {
    char path[] = "/tmp/rndis-tether-selftest-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return false;
    bool written = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    close(fd);
    bool ok = written && config_load(c, path, why, why_size);
    unlink(path);
    return ok;
}

static void test_config(void) {
    Config c, d;
    char why[300];
    config_defaults(&c);
    CHECK(c.prefer_phone && !c.ipv6 && !c.verbose && !c.tx_batch);
    CHECK(!strcmp(c.host, "feth50") && !strcmp(c.peer, "feth51"));
    CHECK(config_load(&c, "/nonexistent/rndis-tether.conf", why, sizeof why) && c.prefer_phone);

    CHECK(load_text(&c, "# comment\n\n  prefer-phone = No   # trailing comment\ntx-batch=8\nipv6 = on\n"
                        "host-interface = feth60\npeer-interface = feth61\n", why, sizeof why));
    CHECK(!c.prefer_phone && c.ipv6 && c.tx_batch == 8 && !strcmp(c.host, "feth60") && !strcmp(c.peer, "feth61"));

    config_defaults(&c);
    /* A bad line is skipped, not the rest of the file; the first one is reported. */
    CHECK(!load_text(&c, "ipv6 = yes\nverbose\ntx-batch = typo\nhost-interface = feth60\npeer-interface = feth61\n",
                     why, sizeof why) && strstr(why, "line 2") && strstr(why, "name = value"));
    CHECK(c.ipv6 && !c.tx_batch && !strcmp(c.host, "feth60") && !strcmp(c.peer, "feth61"));
    CHECK(!load_text(&c, "colour = red\n", why, sizeof why) && strstr(why, "unknown setting"));
    CHECK(!load_text(&c, "tx-batch = 33\n", why, sizeof why) && strstr(why, "1 to 32"));
    CHECK(!load_text(&c, "host-interface = en0\n", why, sizeof why) && strstr(why, "fethN"));
    config_defaults(&c);
    CHECK(!load_text(&c, "ipv6 = yes\nhost-interface = feth51\n", why, sizeof why) && strstr(why, "must differ"));
    CHECK(c.ipv6 && !strcmp(c.host, "feth50") && !strcmp(c.peer, "feth51")); /* clashing names fall back */

    config_defaults(&c);
    CHECK(config_set(&c, "tx-batch", "AUTO", why, sizeof why) && !c.tx_batch);
    CHECK(config_live("prefer-phone") && config_live("verbose") && !config_live("ipv6") &&
          !config_live("tx-batch") && !config_live("host-interface") && !config_live("peer-interface"));
    CHECK(!config_set(&c, "tx-batch", "0", why, sizeof why) && !config_set(&c, "tx-batch", "8x", why, sizeof why));
    CHECK(!config_set(&c, "tx-batch", "", why, sizeof why) && !config_set(&c, "verbose", "", why, sizeof why));

    /* What config_save writes, config_load reads back unchanged. */
    char path[] = "/tmp/rndis-tether-selftest-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    config_defaults(&c);
    c.prefer_phone = false;
    c.verbose = true;
    c.tx_batch = 1;
    strlcpy(c.peer, "feth99", sizeof c.peer);
    config_defaults(&d);
    CHECK(config_save(&c, path, why, sizeof why) && config_load(&d, path, why, sizeof why));
    CHECK(!memcmp(&c, &d, sizeof c));
    unlink(path);

    /* The tail of an overlong line is not a setting; the next line keeps its number. */
    char text[1200];
    int used = snprintf(text, sizeof text, "# %0509d", 0);
    snprintf(text + used, sizeof text - (size_t)used, "ipv6 = yes # %0600d\ntx-batch = x\n", 0);
    config_defaults(&c);
    CHECK(!load_text(&c, text, why, sizeof why) && !c.ipv6 && strstr(why, "line 1: line is too long"));
    config_defaults(&c);
    used = snprintf(text, sizeof text, "# %0509d", 0); /* 511 characters fit exactly */
    snprintf(text + used, sizeof text - (size_t)used, "\nipv6 = yes\n");
    CHECK(load_text(&c, text, why, sizeof why) && c.ipv6);
    config_defaults(&c);
    snprintf(text, sizeof text, "ipv6 = yes # %0498d", 0); /* 511 characters, no newline at the end */
    CHECK(strlen(text) == 511 && load_text(&c, text, why, sizeof why) && c.ipv6);
    CHECK(!load_text(&c, "verbose = yes # long enough to need no newline\nipv6\n", why, sizeof why) &&
          strstr(why, "line 2"));
}

static void test_device_text(void) {
    char text[] = "A\nb=1\x1b[2J\x7f\xc2\x9b~ ", empty[] = "";
    printable(text);
    CHECK(!strcmp(text, "A?b=1?[2J???~ "));
    printable(empty);
    CHECK(!empty[0]);
}

static void test_interface_marker(void) {
    char path[] = "/tmp/rndis-tether-selftest-XXXXXX", host[IFNAMSIZ], peer[IFNAMSIZ];
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    CHECK(runtime_mark_interfaces(path, "feth50", "feth51") && runtime_marked_interfaces(path, host, peer));
    CHECK(!strcmp(host, "feth50") && !strcmp(peer, "feth51"));
    /* Only two different fethN are ever handed to `ifconfig destroy`. */
    static const char *const bad[] = {"", "feth50\n", "feth50 feth50\n", "feth50 en0\n", "feth50 feth51 x\n",
                                      "fethx feth51\n", "feth50 feth123456789012345\n", "-x feth51\n"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        fd = open(path, O_WRONLY | O_TRUNC);
        CHECK(fd >= 0 && write(fd, bad[i], strlen(bad[i])) == (ssize_t)strlen(bad[i]));
        if (fd >= 0) close(fd);
        CHECK(!runtime_marked_interfaces(path, host, peer));
    }
    CHECK(!runtime_mark_interfaces("/nonexistent/marker", "feth50", "feth51"));
    runtime_destroy_interfaces(path); /* names nothing valid: just removed */
    CHECK(access(path, F_OK) && !runtime_marked_interfaces(path, host, peer));
    /* A marker is never followed through a symlink. */
    CHECK(!symlink("/etc/hosts", path) && !runtime_mark_interfaces(path, "feth50", "feth51"));
    unlink(path);
}

/* cli_print_status's words for the daemon's lines, captured from stdout. */
static const char *status_words(const char *lines, char *out, size_t size) {
    char path[] = "/tmp/rndis-tether-selftest-XXXXXX";
    int fd = mkstemp(path), saved = dup(STDOUT_FILENO);
    CHECK(fd >= 0 && saved >= 0);
    fflush(stdout);
    dup2(fd, STDOUT_FILENO);
    cli_print_status(lines, -1, -1);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    ssize_t n = pread(fd, out, size - 1, 0);
    out[n > 0 ? n : 0] = 0;
    close(fd);
    unlink(path);
    return out;
}

static void test_status_words(void) {
    char text[1024];
    status_words("protocol=1\nversion=" VERSION "\nstate=paused\npaused=yes\nphone=Phone 04e8:6864\n", text,
                 sizeof text);
    CHECK(!strcmp(text, "Phone:    Phone 04e8:6864\nStatus:   disconnected (run: rndis-tether connect)\n"));
    status_words("protocol=1\nversion=" VERSION "\nstate=paused\npaused=yes\n", text, sizeof text);
    CHECK(!strcmp(text, "Status:   disconnected (run: rndis-tether connect)\n"));
    status_words("protocol=1\nversion=" VERSION "\nstate=no-phone\npaused=no\n", text, sizeof text);
    CHECK(!strncmp(text, "Status:   waiting for a phone\n", 30));
    status_words("protocol=1\nversion=1.0.1\nstate=no-phone\n", text, sizeof text);
    CHECK(strstr(text, "The service runs version 1.0.1, this program is " VERSION));
}

static void test_pause_messages(void) {
    int code = -1;
    const char *m = cli_pause_message("protocol=1\nversion=1.0.1\nstate=online\n", true, CLI_NOT_ASKED, "", &code);
    CHECK(m && code == 1 && strstr(m, "version 1.0.1, which cannot disconnect") &&
          strstr(m, "sudo rndis-tether install"));
    m = cli_pause_message("protocol=1\nversion=1.0.1\nstate=paused\n", false, CLI_NOT_ASKED, "", &code);
    CHECK(m && code == 1 && strstr(m, "which cannot connect"));
    const char *running = "protocol=1\nstate=online\npaused=no\nphone=Phone\n";
    const char *paused = "protocol=1\nstate=paused\npaused=yes\nphone=Phone\n";
    CHECK(!strcmp(cli_pause_message(running, false, CLI_NOT_ASKED, "", &code), "Already connected.\n") && !code);
    CHECK(!strcmp(cli_pause_message(paused, true, CLI_NOT_ASKED, "", &code), "Already disconnected.\n") && !code);
    CHECK(!cli_pause_message(running, true, CLI_NOT_ASKED, "", &code) && !code); /* send it */
    CHECK(!cli_pause_message(paused, false, CLI_NOT_ASKED, "", &code));

    m = cli_pause_message("", true, 0, CLI_PAUSE_DENIED, &code);
    CHECK(code == 1 &&
          !strcmp(m, "Not changed: only administrators of this Mac can disconnect or connect the phone.\n"));
    m = cli_pause_message("", false, 0, "paused must be yes or no, not \"x\"", &code);
    CHECK(code == 1 && !strcmp(m, "Not changed: paused must be yes or no, not \"x\".\n"));
    CHECK(strstr(cli_pause_message("", true, -1, "", &code), "did not answer") && code == 1);

    m = cli_pause_message(paused, true, 1, "", &code);
    CHECK(!code && !strncmp(m, "Disconnected; the phone can stay plugged in.", 44) &&
          strstr(m, "rndis-tether connect"));
    m = cli_pause_message("protocol=1\nstate=connecting\npaused=no\nphone=Phone\n", false, 1, "", &code);
    CHECK(!code && !strncmp(m, "Connecting to the phone;", 24));
    m = cli_pause_message("protocol=1\nstate=no-phone\npaused=no\n", false, 1, "", &code);
    CHECK(!code && strstr(m, "as soon as it is plugged in"));
    m = cli_pause_message("protocol=1\nstate=unsupported\npaused=no\nphone=Modem\n", false, 1, "", &code);
    CHECK(!code && !strncmp(m, "Connected again;", 16)); /* not "Connecting" to a device that cannot */
    m = cli_pause_message("", false, 1, "", &code); /* gone right after answering */
    CHECK(!code && !strncmp(m, "Connected again;", 16));
}

int main(void) {
    test_builders();
    test_control_parsers();
    test_health_messages();
    test_descriptors();
    test_health_policy();
    test_data_path();
    test_bpf_records();
    test_bpf_batch_records();
    test_config();
    test_device_text();
    test_interface_marker();
    test_status_words();
    test_pause_messages();
    fuzz();
    printf("selftest: %u checks, %u failures\n", tests, failures);
    return failures ? 1 : 0;
}
