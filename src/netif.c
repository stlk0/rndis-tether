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

static bool spawn_and_wait(const char *const argv[], unsigned timeout_ms, bool quiet) {
    static char *const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_init(&actions);
    posix_spawnattr_init(&attributes);
    /* Children get only stdin/stdout/stderr: no USB, BPF or socket descriptors. */
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attributes, &all);
    posix_spawnattr_setsigmask(&attributes, &none);
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
        usleep(5000);
    }
}

bool run_command(const char *const argv[], unsigned timeout_ms) {
    return spawn_and_wait(argv, timeout_ms, false);
}

bool run_command_quiet(const char *const argv[], unsigned timeout_ms) {
    return spawn_and_wait(argv, timeout_ms, true);
}

static bool run(const char *const argv[]) {
    return run_command(argv, 5000);
}

bool feth_sysctls_ok(char *why, size_t why_size) {
    static const struct { const char *name; long long required; } checks[] = {
        {"net.link.fake.hwcsum", 0},           /* else checksums are left for "hardware" */
        {"net.link.fake.fcs", 0},              /* else a frame check sequence is appended */
        {"net.link.fake.tso_support", 0},      /* else oversized TCP segments reach BPF */
        {"net.link.fake.lro", 0},
        {"net.link.fake.trailer_length", 0},
        {"net.link.fake.separate_frame_header", 0},
        {"net.link.fake.nxattach", 0},         /* classic BSD path, where BPF sees frames */
        {"net.link.fake.bsd_mode", 1},
    };
    for (size_t i = 0; i < sizeof checks / sizeof *checks; ++i) {
        uint64_t raw = 0;
        size_t size = sizeof raw;
        if (sysctlbyname(checks[i].name, &raw, &size, NULL, 0) != 0) continue; /* absent on this macOS */
        long long value = size == 4 ? (long long)(int32_t)(uint32_t)raw : (long long)raw;
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
    const char *argv[] = {"/sbin/ifconfig", name, "destroy", NULL};
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
        {"/sbin/ifconfig", host, "create", NULL},
        {"/sbin/ifconfig", peer, "create", NULL},
        {"/sbin/ifconfig", host, "peer", peer, NULL},
        {"/sbin/ifconfig", host, "mtu", mtu_text, NULL},
        {"/sbin/ifconfig", peer, "mtu", mtu_text, NULL},
        {"/sbin/ifconfig", peer, "up", NULL},
        {"/sbin/ifconfig", host, "up", NULL},
    };
    for (size_t i = 0; i < sizeof steps / sizeof *steps; ++i) {
        if (!run(steps[i])) {
            logmsg("ifconfig step failed: %s %s", steps[i][1], steps[i][2]);
            feth_destroy(host);
            feth_destroy(peer);
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
    const char *step = NULL;
    if (ioctl(fd, BIOCSBLEN, &requested)) step = "BIOCSBLEN";              /* must precede BIOCSETIF */
    else if (!set_flag(fd, BIOCSHDRCMPLT, 1)) step = "BIOCSHDRCMPLT";      /* keep our source MAC */
    else if (ioctl(fd, BIOCSETIF, &ifr)) step = "BIOCSETIF";
    else if (ioctl(fd, BIOCGDLT, &dlt) || dlt != DLT_EN10MB) step = "BIOCGDLT (not Ethernet)";
    else if (!set_flag(fd, BIOCIMMEDIATE, 1)) step = "BIOCIMMEDIATE";
    else if (!set_flag(fd, BIOCSSEESENT, 0)) step = "BIOCSSEESENT";        /* never read back our writes */
    else if (ioctl(fd, BIOCGBLEN, &actual) || !actual || actual > requested) step = "BIOCGBLEN";
    else if (!set_flag(fd, FIONBIO, 1)) step = "FIONBIO";
    if (step) {
        snprintf(why, why_size, "%s on %s failed: %s", step, ifname, strerror(errno));
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

bool bpf_batch_write(int fd, bool on) {
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

bool bpf_next(BpfCursor *c, const uint8_t **frame, size_t *length, bool *truncated) {
    struct bpf_hdr h;
    if (c->n < BPF_HEADER_MIN) return false;
    memset(&h, 0, sizeof h);
    memcpy(&h, c->p, BPF_HEADER_MIN);
    size_t header = h.bh_hdrlen, captured = h.bh_caplen;
    if (header < BPF_HEADER_MIN || header > c->n || captured > c->n - header) { c->n = 0; return false; }
    *frame = c->p + header;
    *length = captured;
    *truncated = h.bh_caplen != h.bh_datalen;
    size_t step = BPF_WORDALIGN(header + captured);
    if (step > c->n) step = c->n;
    c->p += step;
    c->n -= step;
    return true;
}

bool ipconfig_set(const char *ifname, const char *method) {
    const char *argv[] = {"/usr/sbin/ipconfig", "set", ifname, method, NULL};
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
    CFRunLoopSourceRef source = store && ipv4_patterns &&
        SCDynamicStoreSetNotificationKeys(store, NULL, ipv4_patterns) ?
        SCDynamicStoreCreateRunLoopSource(NULL, store, 0) : NULL;
    if (!source) return false;
    CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopDefaultMode);
    CFRelease(source);
    return true;
}

static bool ipv4_text(CFTypeRef value, char out[16]) {
    struct in_addr parsed;
    return value && CFGetTypeID(value) == CFStringGetTypeID() &&
           CFStringGetCString((CFStringRef)value, out, 16, kCFStringEncodingASCII) &&
           inet_pton(AF_INET, out, &parsed) == 1;
}

typedef struct {
    CFStringRef ifname;
    char *address, *router, *service;
    size_t service_size;
    bool found;
} LeaseSearch;

/* key: State:/Network/Service/<id>/IPv4 */
static void lease_match(const void *key, const void *value, void *context) {
    LeaseSearch *search = context;
    if (search->found || CFGetTypeID(value) != CFDictionaryGetTypeID()) return;
    CFDictionaryRef ipv4 = value;
    CFTypeRef name = CFDictionaryGetValue(ipv4, kSCPropInterfaceName);
    if (!name || !CFEqual(name, search->ifname)) return;
    CFTypeRef addresses = CFDictionaryGetValue(ipv4, kSCPropNetIPv4Addresses);
    CFTypeRef first = addresses && CFGetTypeID(addresses) == CFArrayGetTypeID() &&
                      CFArrayGetCount((CFArrayRef)addresses) ?
                      CFArrayGetValueAtIndex((CFArrayRef)addresses, 0) : NULL;
    char path[256];
    const char *prefix = "State:/Network/Service/", *id = NULL, *slash = NULL;
    if (CFStringGetCString(key, path, sizeof path, kCFStringEncodingUTF8) && !strncmp(path, prefix, strlen(prefix))) {
        id = path + strlen(prefix);
        slash = strchr(id, '/');
    }
    if (!slash || (size_t)(slash - id) >= search->service_size) return;
    search->found = ipv4_text(first, search->address) &&
                    ipv4_text(CFDictionaryGetValue(ipv4, kSCPropNetIPv4Router), search->router);
    if (search->found) {
        memcpy(search->service, id, (size_t)(slash - id));
        search->service[slash - id] = 0;
    }
}

bool lease_get(const char *ifname, char address[16], char router[16], char *service, size_t service_size) {
    if (!store) return false;
    CFDictionaryRef services = SCDynamicStoreCopyMultiple(store, NULL, ipv4_patterns);
    CFStringRef name = CFStringCreateWithCString(NULL, ifname, kCFStringEncodingUTF8);
    LeaseSearch search = {name, address, router, service, service_size, false};
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
