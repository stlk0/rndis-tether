#include "netif.h"
#include "log.h"

#include <SystemConfiguration/SystemConfiguration.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHILD_POLL_US 5000u /* how often the exit status is checked while waiting */
#define IFCONFIG "/sbin/ifconfig" /* absolute: no PATH lookup as root */
#define IPCONFIG "/usr/sbin/ipconfig"

static bool spawn_and_wait(const char *const argv[], unsigned timeout_ms, bool quiet) {
    static char *const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_init(&actions);
    posix_spawnattr_init(&attributes);
    /* Ignored signals and the blocked mask survive exec (the daemon ignores its stop
     * signals and SIGPIPE): the child starts with default handling and nothing blocked. */
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attributes, &all);
    posix_spawnattr_setsigmask(&attributes, &none);
    /* Children get only stdin/stdout/stderr: no USB, BPF or socket descriptors. */
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF |
                                              POSIX_SPAWN_SETSIGMASK);
    posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    if (quiet) posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    else posix_spawn_file_actions_addinherit_np(&actions, 2);

    pid_t pid = -1;
    int spawned = posix_spawn(&pid, argv[0], &actions, &attributes, (char *const *)argv, environment);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    if (spawned) return false;

    int status = 0;
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC) + timeout_ms * 1000000ull;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (done < 0 && errno != EINTR) return false;
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            logmsg("command timed out: %s %s", argv[0], argv[1] ? argv[1] : "");
            return false;
        }
        usleep(CHILD_POLL_US);
    }
}

bool run_command(const char *const argv[], unsigned timeout_ms) {
    return spawn_and_wait(argv, timeout_ms, false);
}

bool run_command_quiet(const char *const argv[], unsigned timeout_ms) {
    return spawn_and_wait(argv, timeout_ms, true);
}

static bool run(const char *const argv[]) {
    return run_command(argv, COMMAND_TIMEOUT_MS);
}

bool feth_sysctls_ok(char *why, size_t why_size) {
    static const struct { const char *name; long long required; } checks[] = {
        {FETH_SYSCTL_PREFIX ".hwcsum", 0},      /* else checksums are left for "hardware" */
        {FETH_SYSCTL_PREFIX ".fcs", 0},         /* else a frame check sequence is appended */
        {FETH_SYSCTL_PREFIX ".tso_support", 0}, /* else oversized TCP segments reach BPF */
        {FETH_SYSCTL_PREFIX ".lro", 0},
        {FETH_SYSCTL_PREFIX ".trailer_length", 0},
        {FETH_SYSCTL_PREFIX ".separate_frame_header", 0},
        {FETH_SYSCTL_PREFIX ".nxattach", 0},    /* classic BSD path, where BPF sees frames */
        {FETH_SYSCTL_PREFIX ".bsd_mode", 1},
    };
    for (size_t i = 0; i < sizeof checks / sizeof *checks; ++i) {
        uint64_t raw = 0;
        size_t size = sizeof raw;
        if (sysctlbyname(checks[i].name, &raw, &size, NULL, 0) != 0) continue; /* absent on this macOS */
        long long value = size == sizeof(int32_t) ? (long long)(int32_t)(uint32_t)raw : (long long)raw;
        if (value != checks[i].required) {
            snprintf(why, why_size, "%s is %lld, expected %lld", checks[i].name, value, checks[i].required);
            return false;
        }
    }
    return true;
}

bool interface_exists(const char *name) {
    return if_nametoindex(name) != 0;
}

void feth_destroy(const char *name) {
    if (!interface_exists(name)) return;
    const char *argv[] = {IFCONFIG, name, "destroy", NULL};
    if (!run(argv)) logmsg("could not destroy %s", name);
}

/* feth50 keeps the MAC if_fake gives it at creation (66:65:74:68:00:32, "feth" + unit).
 * Changing it afterwards races with IPConfiguration: when the DHCP client picks up
 * the old address first, its requests carry a chaddr the interface no longer owns
 * and every offer from the phone is lost. The phone answers whatever MAC asks. */
bool feth_create_pair(const char *host, const char *peer, unsigned mtu) {
    char mtu_text[8];
    snprintf(mtu_text, sizeof mtu_text, "%u", mtu);
    const char *const steps[][5] = {
        {IFCONFIG, host, "create", NULL},
        {IFCONFIG, peer, "create", NULL},
        {IFCONFIG, host, "peer", peer, NULL},
        {IFCONFIG, host, "mtu", mtu_text, NULL},
        {IFCONFIG, peer, "mtu", mtu_text, NULL},
        {IFCONFIG, peer, "up", NULL},
        {IFCONFIG, host, "up", NULL},
    };
    for (size_t i = 0; i < sizeof steps / sizeof *steps; ++i) {
        if (!run(steps[i])) {
            logmsg("ifconfig step failed: %s %s", steps[i][1], steps[i][2]);
            /* Steps 0 and 1 create the pair: only what was created here is destroyed. */
            if (i > 0) feth_destroy(host);
            if (i > 1) feth_destroy(peer);
            return false;
        }
    }
    return true;
}

static bool set_flag(int fd, unsigned long request, unsigned value) {
    return ioctl(fd, request, &value) == 0;
}

int bpf_open_bound(const char *ifname, unsigned *buffer_size, char *why, size_t why_size) {
    int fd = -1;
    for (int i = 0; i < 256 && fd < 0; ++i) {
        char path[16];
        snprintf(path, sizeof path, "/dev/bpf%d", i);
        fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0 && errno != EBUSY) break;
    }
    if (fd < 0) { snprintf(why, why_size, "no free /dev/bpf device: %s", strerror(errno)); return -1; }

    unsigned requested = *buffer_size, dlt = 0, actual = 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
    const char *step = NULL, *reason = NULL;
    if (ioctl(fd, BIOCSBLEN, &requested)) step = "BIOCSBLEN";              /* must precede BIOCSETIF */
    else if (!set_flag(fd, BIOCSHDRCMPLT, 1)) step = "BIOCSHDRCMPLT";      /* keep our source MAC */
    else if (ioctl(fd, BIOCSETIF, &ifr)) step = "BIOCSETIF";
    else if (ioctl(fd, BIOCGDLT, &dlt)) step = "BIOCGDLT";
    else if (dlt != DLT_EN10MB) step = "BIOCGDLT", reason = "not Ethernet";
    else if (!set_flag(fd, BIOCIMMEDIATE, 1)) step = "BIOCIMMEDIATE";
    else if (!set_flag(fd, BIOCSSEESENT, 0)) step = "BIOCSSEESENT";        /* never read back our writes */
    else if (ioctl(fd, BIOCGBLEN, &actual)) step = "BIOCGBLEN";
    else if (!actual || actual > requested) step = "BIOCGBLEN", reason = "unexpected buffer size";
    else if (!set_flag(fd, FIONBIO, 1)) step = "FIONBIO";
    if (step) {
        snprintf(why, why_size, "%s on %s failed: %s", step, ifname, reason ? reason : strerror(errno));
        close(fd);
        return -1;
    }
    *buffer_size = actual;
    return fd;
}

/* Private XNU ioctl (bsd/net/bpf_private.h): with BIOCSHDRCMPLT set, one write() may carry
 * several frames, each as a record laid out like the ones read(2) returns. */
#ifndef BIOCSBATCHWRITE
#define BIOCGBATCHWRITE _IOR('B', 142, int)
#define BIOCSBATCHWRITE _IOW('B', 143, int)
#endif

bool bpf_set_batch_write(int fd, bool on) {
    int value = on, check = !on;
    return !ioctl(fd, BIOCSBATCHWRITE, &value) && !ioctl(fd, BIOCGBATCHWRITE, &check) && check == (int)on;
}

size_t bpf_put(uint8_t *buffer, size_t used, size_t capacity, const uint8_t *frame, size_t length) {
    struct bpf_hdr header;
    size_t record = BPF_WORDALIGN(sizeof header + length);
    if (used > capacity || record > capacity - used || length > UINT32_MAX) return 0;
    memset(&header, 0, sizeof header);
    header.bh_caplen = header.bh_datalen = (uint32_t)length;
    header.bh_hdrlen = (unsigned short)sizeof header; /* the kernel skips bytes past bh_hdrlen's end */
    memcpy(buffer + used, &header, sizeof header);
    memcpy(buffer + used + sizeof header, frame, length);
    memset(buffer + used + sizeof header + length, 0, record - sizeof header - length);
    return record;
}

/* The kernel writes SIZEOF_BPF_HDR (18) bytes, not sizeof(struct bpf_hdr) (20 with padding). */
#define BPF_HEADER_MIN (offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(((struct bpf_hdr *)0)->bh_hdrlen))

bool bpf_next(BpfCursor *cursor, const uint8_t **frame, size_t *length, bool *truncated) {
    struct bpf_hdr header;
    if (cursor->left < BPF_HEADER_MIN) return false;
    memset(&header, 0, sizeof header);
    memcpy(&header, cursor->next, BPF_HEADER_MIN);
    size_t header_length = header.bh_hdrlen, captured = header.bh_caplen;
    if (header_length < BPF_HEADER_MIN || header_length > cursor->left ||
        captured > cursor->left - header_length) { cursor->left = 0; return false; }
    *frame = cursor->next + header_length;
    *length = captured;
    *truncated = header.bh_caplen != header.bh_datalen;
    size_t step = BPF_WORDALIGN(header_length + captured);
    if (step > cursor->left) step = cursor->left;
    cursor->next += step;
    cursor->left -= step;
    return true;
}

bool ipconfig_set(const char *ifname, const char *method) {
    const char *argv[] = {IPCONFIG, "set", ifname, method, NULL};
    return run(argv);
}

/* IPConfiguration publishes each lease as State:/Network/Service/<id>/IPv4 with
 * InterfaceName, Addresses and Router. Every service's IPv4 entity is watched and
 * filtered by interface name; the service id comes with the match. */
static SCDynamicStoreRef store;
static CFArrayRef ipv4_patterns;
static void (*state_changed)(void);

static void notified(SCDynamicStoreRef s, CFArrayRef keys, void *info) {
    (void)s;
    (void)keys;
    (void)info;
    state_changed();
}

bool netstate_watch(void (*changed)(void)) {
    CFStringRef pattern = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainState,
                                                                      kSCCompAnyRegex, kSCEntNetIPv4);
    if (!pattern) return false;
    ipv4_patterns = CFArrayCreate(NULL, (const void **)&pattern, 1, &kCFTypeArrayCallBacks);
    CFRelease(pattern);
    state_changed = changed;
    store = SCDynamicStoreCreate(NULL, CFSTR("rndis-tether"), notified, NULL);
    if (!store || !ipv4_patterns) return false;
    if (!SCDynamicStoreSetNotificationKeys(store, NULL, ipv4_patterns)) return false;
    CFRunLoopSourceRef source = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
    if (!source) return false;
    CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopDefaultMode);
    CFRelease(source);
    return true;
}

static bool ipv4_text(CFTypeRef value, char out[INET_ADDRSTRLEN]) {
    struct in_addr parsed;
    return value && CFGetTypeID(value) == CFStringGetTypeID() &&
           CFStringGetCString((CFStringRef)value, out, INET_ADDRSTRLEN, kCFStringEncodingASCII) &&
           inet_pton(AF_INET, out, &parsed) == 1;
}

typedef struct {
    CFStringRef ifname;
    Lease *lease;
    bool found;
} LeaseSearch;

#define SERVICE_STATE_PREFIX "State:/Network/Service/" /* service_key builds this; <id>/IPv4 follows */

/* The <id> of State:/Network/Service/<id>/IPv4; false when it does not fit out. */
static bool service_id_from_key(CFStringRef key, char *out, size_t size) {
    char path[256];
    if (!CFStringGetCString(key, path, sizeof path, kCFStringEncodingUTF8)) return false;
    if (strncmp(path, SERVICE_STATE_PREFIX, strlen(SERVICE_STATE_PREFIX))) return false;
    const char *id = path + strlen(SERVICE_STATE_PREFIX), *slash = strchr(id, '/');
    if (!slash || (size_t)(slash - id) >= size) return false;
    memcpy(out, id, (size_t)(slash - id));
    out[slash - id] = 0;
    return true;
}

static CFTypeRef first_address(CFDictionaryRef ipv4) {
    CFTypeRef addresses = CFDictionaryGetValue(ipv4, kSCPropNetIPv4Addresses);
    if (!addresses || CFGetTypeID(addresses) != CFArrayGetTypeID() || !CFArrayGetCount(addresses)) return NULL;
    return CFArrayGetValueAtIndex(addresses, 0);
}

/* key: State:/Network/Service/<id>/IPv4 */
static void lease_match(const void *key, const void *value, void *context) {
    LeaseSearch *search = context;
    if (search->found || CFGetTypeID(value) != CFDictionaryGetTypeID()) return;
    CFDictionaryRef ipv4 = value;
    CFTypeRef name = CFDictionaryGetValue(ipv4, kSCPropInterfaceName);
    if (!name || !CFEqual(name, search->ifname)) return;
    char id[SERVICE_ID_MAX];
    if (!service_id_from_key(key, id, sizeof id)) return;
    /* SC calls the gateway Router. */
    search->found = ipv4_text(first_address(ipv4), search->lease->address) &&
                    ipv4_text(CFDictionaryGetValue(ipv4, kSCPropNetIPv4Router), search->lease->gateway);
    if (search->found) strlcpy(search->lease->service, id, sizeof search->lease->service);
}

bool lease_get(const char *ifname, Lease *lease) {
    if (!store) return false;
    CFDictionaryRef services = SCDynamicStoreCopyMultiple(store, NULL, ipv4_patterns);
    CFStringRef name = CFStringCreateWithCString(NULL, ifname, kCFStringEncodingUTF8);
    LeaseSearch search = {.ifname = name, .lease = lease};
    if (services && name) CFDictionaryApplyFunction(services, lease_match, &search);
    if (services) CFRelease(services);
    if (name) CFRelease(name);
    return search.found;
}

static CFStringRef service_key(const char *service) {
    CFStringRef id = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef key = id ? SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainState, id, NULL) : NULL;
    if (id) CFRelease(id);
    return key;
}

/* configd's IPMonitor reads PrimaryRank from State:/Network/Service/<id> (the same
 * key SCNetworkService's private rank API writes; not in the public headers). */
bool service_rank_first(const char *service) {
    CFStringRef key = service_key(service);
    const void *name = CFSTR("PrimaryRank"), *value = CFSTR("First");
    CFDictionaryRef rank = CFDictionaryCreate(NULL, &name, &value, 1, &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    bool ok = false;
    if (store && key && rank) {
        /* AddTemporaryValue refuses a key that already exists. */
        (void)SCDynamicStoreRemoveValue(store, key);
        ok = SCDynamicStoreAddTemporaryValue(store, key, rank);
    }
    if (rank) CFRelease(rank);
    if (key) CFRelease(key);
    return ok;
}

void service_rank_clear(const char *service) {
    CFStringRef key = service_key(service);
    if (store && key) (void)SCDynamicStoreRemoveValue(store, key);
    if (key) CFRelease(key);
}

void primary_interface(char *out, size_t size) {
    out[0] = 0;
    CFStringRef key = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
    CFPropertyListRef global = store && key ? SCDynamicStoreCopyValue(store, key) : NULL;
    CFTypeRef name = global && CFGetTypeID(global) == CFDictionaryGetTypeID() ?
                     CFDictionaryGetValue(global, kSCDynamicStorePropNetPrimaryInterface) : NULL;
    if (name && CFGetTypeID(name) == CFStringGetTypeID())
        (void)CFStringGetCString(name, out, (CFIndex)size, kCFStringEncodingUTF8);
    if (global) CFRelease(global);
    if (key) CFRelease(key);
}

void interface_display_name(const char *ifname, char *out, size_t size) {
    strlcpy(out, ifname, size);
    CFArrayRef all = SCNetworkInterfaceCopyAll();
    CFStringRef name = CFStringCreateWithCString(NULL, ifname, kCFStringEncodingUTF8);
    for (CFIndex i = 0; all && name && i < CFArrayGetCount(all); ++i) {
        SCNetworkInterfaceRef interface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(all, i);
        CFStringRef bsd = SCNetworkInterfaceGetBSDName(interface);
        CFStringRef display = SCNetworkInterfaceGetLocalizedDisplayName(interface);
        if (bsd && display && CFEqual(bsd, name)) {
            if (!CFStringGetCString(display, out, (CFIndex)size, kCFStringEncodingUTF8)) strlcpy(out, ifname, size);
            break;
        }
    }
    if (name) CFRelease(name);
    if (all) CFRelease(all);
}
