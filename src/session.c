#include "session.h"
#include "clock.h"
#include "control.h"
#include "health.h"
#include "log.h"
#include "netif.h"
#include "runtime.h"

#include <dispatch/dispatch.h>
#include <stdio.h>
#include <string.h>

#define STATS_INTERVAL_MS (60u * 60u * 1000u)
#define STATS_INTERVAL_VERBOSE_MS 15000u
#define TICK_INTERVAL_S 1.0 /* health_tick expects about once a second */
/* Every IPv4 host must accept a datagram this large; no suffix, it is stringified into a reason. */
#define IPV4_MTU_MIN 576
/* Directed + broadcast + all multicast: IPv4, ARP, and IPv6 neighbour discovery. */
#define PACKET_FILTER (NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_ALL_MULTICAST)

/* start resets it in one assignment, so nothing leaks from the previous session. */
typedef struct {
    bool active;      /* USB interfaces open: from usb_open to teardown */
    bool running;     /* bring-up done and the control pump on: events act */
    bool failing;     /* fail() ran; the daemon is about to stop us */
    bool usb_dead;    /* the phone is gone: no HALT, and the failure says so */
    bool initialized; /* INITIALIZE answered: HALT is owed on the way out */
    const char *fail_reason;
    IOReturn fail_status;
    const Config *cfg;
    void (*failed)(void);
    uint64_t started_ms, stats_logged_ms;

    UsbLink usb;
    Control control;
    Datapath data;
    Health health;
    RndisInitInfo init;
    unsigned mtu;
    bool link_down;
    bool keepalive_reply_queued; /* the phone's KEEPALIVEs get one reply in the queue at a time */
    bool created_interfaces;     /* the feth pair is ours to destroy */

    time_t connected_at;
    char address[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN];
    char service[SERVICE_ID_MAX]; /* the macOS network service ranked first for us */
    bool ranked;

    DataStats logged; /* what log_stats printed last: it skips a line that would repeat it */
    uint64_t logged_control_errors;
    unsigned logged_resets;
} Session;

static Session s;
static uint32_t generation; /* bumped per start and stop: a late failure report is dropped */
static CFRunLoopTimerRef tick_timer;

/* ------------------------------------------------------------------ failures */

static void report_failure(void *context) {
    if (s.active && (uint32_t)(uintptr_t)context == generation) s.failed();
}

/* Kept for the failure text; a fatal status means the phone is gone (no HALT). */
static void note_status(IOReturn status) {
    s.fail_status = status;
    if (usb_fatal(status)) s.usb_dead = true;
}

/* Control, data path and health stop together: no part runs on alone. */
static void stop_parts(void) {
    control_stop(&s.control);
    datapath_stop(&s.data);
    health_stop(&s.health);
}

/* From any callback: everything stops at once, the teardown runs after the callback returns. */
static void fail(const char *reason, IOReturn status) {
    if (!s.active || s.failing) return;
    s.failing = true;
    s.fail_reason = reason;
    note_status(status);
    stop_parts();
    dispatch_async_f(dispatch_get_main_queue(), (void *)(uintptr_t)generation, report_failure);
}

static const char *describe(const char *reason, IOReturn status) {
    static char text[SESSION_REASON_SIZE];
    /* Fatal USB statuses usually mean the cable is out before macOS says so. */
    if (s.usb_dead) reason = "phone stopped responding (unplugged, or USB tethering turned off?)";
    if (status) snprintf(text, sizeof text, "%s (status 0x%08x)", reason, status);
    else strlcpy(text, reason, sizeof text);
    return text;
}

const char *session_failure(void) {
    return describe(s.fail_reason ? s.fail_reason : "unknown failure", s.fail_status);
}

/* ------------------------------------------------------------ control events */

static void keepalive_reply_done(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    (void)context;
    (void)addressing_reset;
    s.keepalive_reply_queued = false;
    if (result != CONTROL_SUCCESS) logdebug("keepalive reply failed (0x%08x)", status);
}

static void on_status_indication(uint32_t status) {
    if (status == RNDIS_STATUS_MEDIA_DISCONNECT) {
        s.link_down = true;
        logmsg("phone reports link down");
        if (s.running) datapath_set_link(&s.data, false);
    } else if (status == RNDIS_STATUS_MEDIA_CONNECT) {
        bool was_down = s.link_down;
        s.link_down = false;
        logmsg("phone reports link up");
        if (!s.running) return;
        datapath_set_link(&s.data, true);
        /* Confirm the lease again; a changed gateway arrives through session_network_changed. */
        if (was_down && !ipconfig_set(s.cfg->host, "DHCP")) fail("cannot restart DHCP after link up", kIOReturnSuccess);
    } else {
        logdebug("phone status indication 0x%08x", status);
    }
}

static void on_message(const uint8_t *b, size_t n) {
    if (!s.active) return;
    uint32_t type = rndis_control_type(b, n), status = 0, id = 0;
    if (type == RNDIS_INDICATE_STATUS_MSG && !rndis_parse_indicate(b, n, &status)) {
        on_status_indication(status);
    } else if (type == RNDIS_KEEPALIVE_MSG && !rndis_parse_keepalive(b, n, &id)) {
        /* A burst of them would otherwise overflow the control queue and end the session. */
        if (s.keepalive_reply_queued) {
            logdebug("phone KEEPALIVE 0x%08x: a reply is already queued", id);
            return;
        }
        ControlMessage reply = {.id = id, .done = keepalive_reply_done};
        reply.length = rndis_build_keepalive_cmplt(reply.bytes, id);
        /* Before control_run the reply goes at once and is done already. */
        s.keepalive_reply_queued = control_send(&s.control, &reply, true) && s.control.running;
    } else {
        logdebug("ignored control message type 0x%08x", type);
    }
}

static void on_heard(void) {
    health_heard(&s.health);
}

static void on_errors(const char *reason) {
    health_reset(&s.health, reason);
}

static void on_drained(void) {
    health_drained(&s.health);
}

static const ControlEvents control_events = {.message = on_message, .heard = on_heard, .failed = fail};
static const DatapathEvents data_events = {.heard = on_heard, .errors = on_errors, .drained = on_drained,
                                          .failed = fail};

/* ------------------------------------------------------------------ bring-up */

static const char *exchange(const uint8_t *request, size_t n, uint32_t type, uint32_t id, uint8_t *response,
                            size_t *got) {
    IOReturn status = kIOReturnSuccess;
    const char *e = control_exchange(&s.control, request, n, type, id, response, got, &status);
    if (status) note_status(status);
    return e;
}

static const char *query(uint32_t oid, uint8_t *response, const uint8_t **data, uint32_t *length) {
    uint8_t request[RNDIS_QUERY_LENGTH];
    size_t n = 0;
    uint32_t id = control_next_id();
    const char *e = exchange(request, rndis_build_query(request, id, oid), RNDIS_QUERY_MSG, id, response, &n);
    return e ? e : rndis_parse_query_cmplt(response, n, id, data, length);
}

static const char *bring_up(bool *init_failed) {
    static uint8_t response[RNDIS_CONTROL_CAP];
    uint8_t request[RNDIS_REQUEST_MAX];
    size_t n = 0;
    const uint8_t *data = NULL;
    uint32_t length = 0, id = control_next_id();
    const char *e = exchange(request, rndis_build_init(request, id, RNDIS_RX_TRANSFER), RNDIS_INITIALIZE_MSG, id,
                             response, &n);
    if (!e) e = rndis_parse_init_cmplt(response, n, id, &s.init);
    if (e) {
        *init_failed = true;
        return e;
    }
    s.initialized = true;

    /* Queried as every RNDIS host does; feth keeps its own MAC (see feth_create_pair). */
    uint8_t mac[ETHER_ADDR_LEN];
    if ((e = query(OID_802_3_PERMANENT_ADDRESS, response, &data, &length))) return e;
    if ((e = rndis_parse_mac(data, length, mac))) return e;
    logdebug("phone-suggested host MAC %02x:%02x:%02x:%02x:%02x:%02x (unused)",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if ((e = query(OID_GEN_MAXIMUM_FRAME_SIZE, response, &data, &length))) return e;
    if (!data || length != sizeof(uint32_t)) return "unexpected maximum frame size reply";
    uint32_t mtu = rndis_le32(data);
    if (mtu < IPV4_MTU_MIN) return "device MTU is below " NUMBER_TEXT(IPV4_MTU_MIN);
    s.mtu = mtu > ETHERMTU ? ETHERMTU : mtu;

    e = query(OID_GEN_MEDIA_CONNECT_STATUS, response, &data, &length);
    if (!e && data && length == sizeof(uint32_t)) {
        s.link_down = rndis_le32(data) != RNDIS_MEDIA_CONNECTED;
        if (s.link_down) logmsg("initial media state: disconnected");
        else logdebug("initial media state: connected");
    } else {
        logmsg("media state query unavailable: %s", e ? e : "invalid reply");
    }
    if (s.usb_dead) return "device disappeared during media query";

    id = control_next_id();
    e = exchange(request, rndis_build_set_u32(request, id, OID_GEN_CURRENT_PACKET_FILTER, PACKET_FILTER),
                 RNDIS_SET_MSG, id, response, &n);
    return e ? e : rndis_parse_set_cmplt(response, n, id);
}

/* ------------------------------------------------------------------ teardown */

static void drop_rank(void) {
    if (!s.ranked) return;
    service_rank_clear(s.service);
    s.ranked = false;
}

static void teardown(void) {
    s.active = s.running = false; /* completions from here on start nothing */
    timer_disarm(tick_timer);
    stop_parts();

    drop_rank();
    if (s.created_interfaces && interface_exists(s.cfg->host)) { /* ours, and still there: never another program's */
        if (s.cfg->ipv6) (void)ipconfig_set(s.cfg->host, "NONE-V6");
        (void)ipconfig_set(s.cfg->host, "NONE");
    }
    datapath_close(&s.data);

    /* No nested run loop waits for completions here: it would let signals, device
     * notifications and the retry timer run inside a half-closed session. Bulk and
     * interrupt pipes are aborted; pipe 0 cannot be, so HALT queues behind a control
     * request still in flight, bounded by that request's timeout and CONTROL_SEND_TIMEOUT_MS. */
    usb_abort(&s.usb);
    if (!s.usb_dead && s.initialized && s.usb.control_open) {
        /* Tell the phone we are leaving, so it does not keep queueing frames for us. */
        uint8_t halt[RNDIS_HALT_LENGTH];
        (void)usb_send_encapsulated(&s.usb, halt, (uint16_t)rndis_build_halt(halt, control_next_id()),
                                    CONTROL_SEND_TIMEOUT_MS);
    }
    control_close(&s.control);
    usb_close(&s.usb);
    ++generation;
    if (s.created_interfaces) runtime_destroy_interfaces(INTERFACES_PATH);
}

/* A start that failed half-way: undo it without a "disconnecting" line. */
static const char *abandon(const char *reason) {
    const char *text = describe(reason, s.fail_status);
    teardown();
    return text;
}

/* Data and control pipes together, as the log and status report them. */
static uint64_t usb_errors_total(void) {
    return s.data.stats.usb_errors + s.control.usb_errors;
}

static void log_stats(const char *when) {
    const DataStats *stats = &s.data.stats;
    uint64_t usb_errors = usb_errors_total();
    if (!memcmp(stats, &s.logged, sizeof *stats) && s.control.usb_errors == s.logged_control_errors &&
        s.health.resets == s.logged_resets) return;
    s.logged = *stats;
    s.logged_control_errors = s.control.usb_errors;
    s.logged_resets = s.health.resets;
    logmsg("%s: phone->Mac %.1f MB in %llu frames, %llu USB transfers; Mac->phone %.1f MB in %llu frames, "
           "%llu USB transfers; dropped in/out %llu/%llu, malformed %llu, USB errors %llu, BPF errors %llu, "
           "resets %u", when, (double)stats->rx_bytes / 1e6, stats->rx_frames, stats->rx_transfers,
           (double)stats->tx_bytes / 1e6, stats->tx_frames, stats->tx_transfers, stats->rx_dropped, stats->tx_dropped,
           stats->rx_malformed, usb_errors, stats->bpf_errors, s.health.resets);
}

void session_stop(const char *reason, bool quiet) {
    if (!s.active) return;
    if (!quiet) logmsg("disconnecting: %s", reason);
    log_stats("session total");
    teardown();
}

void session_unplugged(void) {
    s.usb_dead = true;
}

/* ------------------------------------------------------------------- running */

static void tick(CFRunLoopTimerRef timer, void *info) {
    (void)timer;
    (void)info;
    if (!s.running || s.failing) return;
    health_tick(&s.health);
    uint64_t now = now_ms();
    uint64_t interval = log_verbose ? STATS_INTERVAL_VERBOSE_MS : STATS_INTERVAL_MS; /* verbose may change */
    if (now - s.stats_logged_ms >= interval) {
        s.stats_logged_ms = now;
        log_stats("traffic");
    }
}

/* prefer-phone ranks our service first while the setting is on. */
static void update_rank(const char *service) {
    if (!s.cfg->prefer_phone) { /* also when switched off while connected */
        if (s.ranked) logmsg("prefer-phone is off: macOS picks the main connection by its own order again");
        drop_rank();
        return;
    }
    if (s.ranked && !strcmp(service, s.service)) return;
    drop_rank();
    if (service_rank_first(service)) {
        strlcpy(s.service, service, sizeof s.service);
        s.ranked = true;
        logmsg("internet traffic now goes through the phone; local network and VPNs work as before");
    } else {
        logmsg("warning: cannot make the phone the main connection (network service %s)", service);
    }
}

/* Runs on every IPv4 state change macOS publishes, for any service: our lease
 * arriving, renewed or lost. */
void session_network_changed(void) {
    if (!s.running || s.failing) return;
    Lease lease;
    if (!lease_get(s.cfg->host, &lease)) {
        if (s.address[0]) {
            logmsg("%s lost its address from the phone; waiting for DHCP", s.cfg->host);
            s.address[0] = s.gateway[0] = 0;
            drop_rank();
        }
        return;
    }
    if (!s.address[0])
        logmsg("online: %s got %s from the phone, gateway %s", s.cfg->host, lease.address, lease.gateway);
    strlcpy(s.address, lease.address, sizeof s.address);
    strlcpy(s.gateway, lease.gateway, sizeof s.gateway);
    update_rank(lease.service);
}

/* Creates the feth pair and records it as ours. NULL, or why not (the text may be in why). */
static const char *create_interfaces(char *why, size_t why_size) {
    if (!feth_sysctls_ok(why, why_size)) return why;
    runtime_destroy_interfaces(INTERFACES_PATH); /* ours, left over; never another program's */
    const char *taken = NULL;
    if (interface_exists(s.cfg->host)) taken = s.cfg->host;
    else if (interface_exists(s.cfg->peer)) taken = s.cfg->peer;
    if (taken) {
        snprintf(why, why_size, "%s " SESSION_REASON_TAKEN " (made by another program?)", taken);
        return why;
    }
    if (!feth_create_pair(s.cfg->host, s.cfg->peer, s.mtu)) return "cannot create feth interfaces";
    if (!runtime_mark_interfaces(INTERFACES_PATH, s.cfg->host, s.cfg->peer)) {
        feth_destroy(s.cfg->host);
        feth_destroy(s.cfg->peer);
        return "cannot record the feth interfaces in " RUNTIME_DIR;
    }
    s.created_interfaces = true;
    return NULL;
}

/* Packets per bulk OUT transfer: the setting, bounded by the phone's limit. */
static unsigned tx_batch_limit(void) {
    unsigned batch = s.cfg->tx_batch ? s.cfg->tx_batch : TX_BATCH_MAX;
    return batch < s.init.max_packets_per_transfer ? batch : s.init.max_packets_per_transfer;
}

const char *session_start(io_service_t device, const char *phone_name, const Config *cfg, void (*failed)(void),
                          bool *init_failed) {
    *init_failed = false;
    ++generation;
    s = (Session){.cfg = cfg, .failed = failed, .data.bpf = -1};
    if (!tick_timer) tick_timer = timer_new(tick, NULL, TICK_INTERVAL_S, 0.1);

    const char *e = usb_open(&s.usb, device);
    if (e) return e;
    s.active = true;
    s.started_ms = now_ms();
    control_open(&s.control, &s.usb, &control_events);
    if ((e = bring_up(init_failed))) return abandon(e);

    char why[SESSION_REASON_SIZE];
    if ((e = create_interfaces(why, sizeof why))) return abandon(e);
    unsigned bpf_size = BPF_BUFFER;
    int bpf = bpf_open_bound(cfg->peer, &bpf_size, why, sizeof why);
    if (bpf < 0) return abandon(why);

    DatapathLimits limits = {
        .mtu = s.mtu,
        .batch_limit = tx_batch_limit(),
        .max_transfer = s.init.max_transfer_size,
        .alignment_shift = s.init.alignment_shift,
    };
    health_start(&s.health, &s.control, &s.data, PACKET_FILTER, fail);
    if ((e = datapath_start(&s.data, &s.usb, bpf, bpf_size, &limits, &data_events))) return abandon(e);
    if (s.link_down) datapath_set_link(&s.data, false);
    logmsg("RNDIS limits: MaxPacketsPerTransfer %u, MaxTransferSize %u, PacketAlignmentFactor %u, "
           "MTU %u, effective TX batch %u, bulk OUT packet %u, BPF batch write %s",
           s.init.max_packets_per_transfer, s.init.max_transfer_size, s.init.alignment_shift,
           s.mtu, limits.batch_limit, s.usb.out_packet_size, s.data.bpf_batch ? "on" : "off");
    control_run(&s.control);
    if (s.failing) return abandon(s.fail_reason);
    s.running = true;

    if (!ipconfig_set(cfg->host, "DHCP")) return abandon("cannot start DHCP on the phone's interface");
    if (cfg->ipv6 && !ipconfig_set(cfg->host, "AUTOMATIC-V6")) logmsg("warning: IPv6 autoconfiguration failed");
    s.stats_logged_ms = now_ms();
    timer_set(tick_timer, 0.5);
    s.connected_at = time(NULL);
    logmsg("connected to %s: %s <-> %s, MTU %u, up to %u packet(s) per transfer; waiting for DHCP",
           phone_name, cfg->host, cfg->peer, s.mtu, limits.batch_limit);
    return NULL;
}

bool session_active(void) {
    return s.active;
}

uint64_t session_age_ms(void) {
    return s.active ? now_ms() - s.started_ms : 0;
}

bool session_status(SessionStatus *out) {
    if (!s.active) return false;
    *out = (SessionStatus){.connected_at = s.connected_at, .data = s.data.stats, .resets = s.health.resets,
                           .usb_errors = usb_errors_total()};
    strlcpy(out->interface, s.cfg->host, sizeof out->interface);
    strlcpy(out->address, s.address, sizeof out->address);
    strlcpy(out->gateway, s.gateway, sizeof out->gateway);
    primary_interface(out->primary, sizeof out->primary);
    return true;
}
