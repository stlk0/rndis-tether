/* Offline scenarios for one connection (session.c): bring-up, the feth pair and
 * teardown. The real control, health, data path and RNDIS code run over a fake phone
 * that answers every request on pipe 0; the network (ifconfig, ipconfig, BPF,
 * SCDynamicStore) and the interface marker are fakes that record what was asked.
 */
#include "clock.h"
#include "netif.h"
#include "runtime.h"
#include "session.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned tests, failures;
#define CHECK(x) do { ++tests; if (!(x)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

static uint64_t test_now = 100000;
uint64_t now_ms(void) { return test_now; }
void sleep_ms(unsigned ms) { test_now += ms; }

/* ------------------------------------------------------------- the phone */

typedef struct {
    bool silent;            /* answers nothing at all */
    uint32_t major;         /* MajorVersion in INITIALIZE_CMPLT */
    uint32_t max_transfer;  /* MaxTransferSize in INITIALIZE_CMPLT */
    uint8_t reply[64];
    size_t reply_size;
    unsigned halts;
} FakePhone;

static FakePhone phone;

static size_t query_reply(uint8_t *b, uint32_t id, uint32_t oid) {
    uint8_t data[6] = {0};
    uint32_t n = 4;
    if (oid == OID_802_3_PERMANENT_ADDRESS) {
        static const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
        memcpy(data, mac, sizeof mac);
        n = 6;
    } else if (oid == OID_GEN_MAXIMUM_FRAME_SIZE) {
        rndis_put32(data, 1500);
    } /* OID_GEN_MEDIA_CONNECT_STATUS: 0, connected */
    memset(b, 0, 24 + n);
    rndis_put32(b, RNDIS_QUERY_MSG | RNDIS_COMPLETION);
    rndis_put32(b + 4, 24 + n);
    rndis_put32(b + 8, id);
    rndis_put32(b + 16, n);
    rndis_put32(b + 20, 16);
    memcpy(b + 24, data, n);
    return 24 + n;
}

IOReturn usb_send_encapsulated(UsbLink *u, const uint8_t *b, uint16_t n, uint32_t timeout_ms) {
    (void)u; (void)timeout_ms;
    uint32_t type = rndis_le32(b), id = n >= 12 ? rndis_le32(b + 8) : 0;
    uint8_t *r = phone.reply;
    phone.reply_size = 0;
    if (type == RNDIS_HALT_MSG) ++phone.halts;
    if (phone.silent) return kIOReturnSuccess;
    if (type == RNDIS_INITIALIZE_MSG) {
        memset(r, 0, 52);
        rndis_put32(r, RNDIS_INITIALIZE_MSG | RNDIS_COMPLETION);
        rndis_put32(r + 4, 52);
        rndis_put32(r + 8, id);
        rndis_put32(r + 16, phone.major);
        rndis_put32(r + 24, 1); /* connectionless */
        rndis_put32(r + 32, 10);
        rndis_put32(r + 36, phone.max_transfer);
        phone.reply_size = 52;
    } else if (type == RNDIS_QUERY_MSG) {
        phone.reply_size = query_reply(r, id, rndis_le32(b + 12));
    } else if (type == RNDIS_SET_MSG) {
        memset(r, 0, 16);
        rndis_put32(r, RNDIS_SET_MSG | RNDIS_COMPLETION);
        rndis_put32(r + 4, 16);
        rndis_put32(r + 8, id);
        phone.reply_size = 16;
    }
    return kIOReturnSuccess;
}

IOReturn usb_get_encapsulated(UsbLink *u, uint8_t *b, uint16_t capacity, uint32_t *done, uint32_t timeout_ms) {
    (void)u; (void)timeout_ms;
    *done = 0;
    if (phone.reply_size && phone.reply_size <= capacity) {
        memcpy(b, phone.reply, phone.reply_size);
        *done = (uint32_t)phone.reply_size;
        phone.reply_size = 0;
    }
    return kIOReturnSuccess;
}

const char *usb_open(UsbLink *u, io_service_t control_service) {
    (void)control_service;
    *u = (UsbLink){.control_open = true, .data_open = true, .out_packet_size = 512, .generation = 1};
    return NULL;
}

void usb_close(UsbLink *u) { u->control_open = u->data_open = false; }
void usb_abort(UsbLink *u) { (void)u; }
void usb_clear_stall(UsbLink *u, UsbPipe pipe) { (void)u; (void)pipe; }

IOReturn usb_read(UsbLink *u, UsbPipe pipe, UsbTransfer *t, void *buffer, uint32_t size) {
    (void)u; (void)pipe; (void)t; (void)buffer; (void)size;
    return kIOReturnSuccess;
}

IOReturn usb_write(UsbLink *u, UsbTransfer *t, const void *buffer, uint32_t size) {
    (void)u; (void)t; (void)buffer; (void)size;
    return kIOReturnSuccess;
}

IOReturn usb_control(UsbLink *u, UsbTransfer *t, bool in, void *buffer, uint16_t size, uint32_t timeout_ms) {
    (void)u; (void)t; (void)in; (void)buffer; (void)size; (void)timeout_ms;
    return kIOReturnSuccess;
}

/* --------------------------------------------------- the network and marker */

static char existing[4][IFNAMSIZ]; /* interfaces that exist, ours or another program's */
static bool marked;                /* the marker names feth50/feth51 */
static unsigned ipconfig_calls, created_mtu;
static char ipconfig_last[64];

static int find_interface(const char *name) {
    for (int i = 0; i < 4; ++i) if (!strcmp(existing[i], name)) return i;
    return -1;
}

static void add_interface(const char *name) {
    int free_slot = find_interface("");
    if (free_slot >= 0) strlcpy(existing[free_slot], name, IFNAMSIZ);
}

bool interface_exists(const char *name) { return find_interface(name) >= 0; }

void feth_destroy(const char *name) {
    int i = find_interface(name);
    if (i >= 0) existing[i][0] = 0;
}

bool feth_create_pair(const char *host, const char *peer, unsigned mtu) {
    add_interface(host);
    add_interface(peer);
    created_mtu = mtu;
    return true;
}

bool feth_sysctls_ok(char *why, size_t why_size) { (void)why; (void)why_size; return true; }

bool ipconfig_set(const char *ifname, const char *method) {
    ++ipconfig_calls;
    snprintf(ipconfig_last, sizeof ipconfig_last, "%s %s", ifname, method);
    return true;
}

static int bpf_pair[2] = {-1, -1};

int bpf_open_bound(const char *ifname, unsigned *buffer_size, char *why, size_t why_size) {
    (void)ifname; (void)buffer_size; (void)why; (void)why_size;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, bpf_pair)) return -1;
    return bpf_pair[0];
}

bool bpf_set_batch_write(int fd, bool on) { (void)fd; (void)on; return false; }
size_t bpf_put(uint8_t *buffer, size_t used, size_t capacity, const uint8_t *frame, size_t length) {
    (void)buffer; (void)used; (void)capacity; (void)frame; (void)length;
    return 0;
}
bool bpf_next(BpfCursor *c, const uint8_t **frame, size_t *length, bool *truncated) {
    (void)c; (void)frame; (void)length; (void)truncated;
    return false;
}

bool lease_get(const char *ifname, Lease *lease) {
    (void)ifname; (void)lease;
    return false;
}
bool service_rank_first(const char *service) { (void)service; return true; }
void service_rank_clear(const char *service) { (void)service; }
void primary_interface(char *out, size_t size) { if (size) out[0] = 0; }

bool runtime_mark_interfaces(const char *marker, const char *host, const char *peer) {
    (void)marker; (void)host; (void)peer;
    marked = true;
    return true;
}

void runtime_destroy_interfaces(const char *marker) {
    (void)marker;
    if (!marked) return;
    feth_destroy("feth50");
    feth_destroy("feth51");
    marked = false;
}

/* ------------------------------------------------------------------- tests */

static Config cfg;
static unsigned broke;
static void on_broke(void) { ++broke; }

static void fixture(void) {
    config_defaults(&cfg);
    cfg.ipv6 = true;
    memset(existing, 0, sizeof existing);
    marked = false;
    ipconfig_calls = created_mtu = broke = 0;
    ipconfig_last[0] = 0;
    phone = (FakePhone){.major = 1, .max_transfer = 1580};
}

static const char *start(bool *init_failed) {
    return session_start(IO_OBJECT_NULL, "test phone", &cfg, on_broke, init_failed);
}

/* Drops the BPF pair of a session that started; the run loop never runs here. */
static void close_bpf(void) {
    if (bpf_pair[1] >= 0) close(bpf_pair[1]);
    bpf_pair[0] = bpf_pair[1] = -1;
}

static void test_own_interfaces(void) {
    fixture();
    bool init_failed = true;
    CHECK(start(&init_failed) == NULL && !init_failed && session_active());
    CHECK(interface_exists("feth50") && interface_exists("feth51") && marked && created_mtu == 1500);
    CHECK(ipconfig_calls == 2 && !strcmp(ipconfig_last, "feth50 AUTOMATIC-V6"));
    session_stop("offline test", true);
    CHECK(!session_active() && phone.halts == 1);
    CHECK(ipconfig_calls == 4 && !strcmp(ipconfig_last, "feth50 NONE"));
    CHECK(!interface_exists("feth50") && !interface_exists("feth51") && !marked);
    close_bpf();
}

/* Another program's feth50 or feth51: refused, and its configuration is left alone. */
static void test_foreign_interface(void) {
    static const char *const names[] = {"feth50", "feth51"};
    for (unsigned i = 0; i < 2; ++i) {
        fixture();
        add_interface(names[i]);
        bool init_failed = true;
        const char *e = start(&init_failed);
        CHECK(e && strstr(e, names[i]) && strstr(e, "already exists") && !init_failed && !session_active());
        CHECK(ipconfig_calls == 0 && interface_exists(names[i]) && !marked);
    }
}

/* A phone that never answers INITIALIZE while another program's feth50 exists. */
static void test_silent_phone_next_to_foreign_interface(void) {
    fixture();
    add_interface("feth50");
    phone.silent = true;
    bool init_failed = false;
    const char *e = start(&init_failed);
    CHECK(e && init_failed && !session_active());
    CHECK(ipconfig_calls == 0 && interface_exists("feth50") && phone.halts == 0);
}

/* An answer that is not RNDIS 1.0 counts as a failed INITIALIZE, like no answer. */
static void test_init_reply_not_rndis(void) {
    fixture();
    phone.major = 2;
    bool init_failed = false;
    const char *e = start(&init_failed);
    CHECK(e && strstr(e, "major version") && init_failed && !session_active() && !ipconfig_calls);
}

int main(void) {
    test_own_interfaces();
    test_foreign_interface();
    test_silent_phone_next_to_foreign_interface();
    test_init_reply_not_rndis();
    printf("bringuptest: %u checks, %u failures\n", tests, failures);
    return failures ? 1 : 0;
}
