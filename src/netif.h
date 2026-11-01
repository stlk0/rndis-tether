/* macOS side: a feth pair stands in for the Ethernet NIC macOS lacks.
 *
 *   macOS IP stack, DHCP, DNS, routes          rndis-tether
 *            |                                     |
 *   <host> (feth, gets the phone's DHCP lease) <-> <peer> (feth, BPF read/write)
 *
 * Frames macOS sends on <host> arrive on <peer>, where BPF reads them; frames written
 * to BPF on <peer> arrive on <host> as received traffic.
 */
#ifndef NETIF_H
#define NETIF_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define COMMAND_TIMEOUT_MS 5000u /* each ifconfig and ipconfig the daemon runs */

/* Runs a fixed argv (absolute path, no shell) with a timeout; true on exit status 0. */
bool run_command(const char *const argv[], unsigned timeout_ms);
/* The same with the child's stderr discarded (expected failures, e.g. launchctl print). */
bool run_command_quiet(const char *const argv[], unsigned timeout_ms);

/* feth snapshots these sysctls at creation; non-default values corrupt frames. */
#define FETH_SYSCTL_PREFIX "net.link.fake" /* cli.c matches this for advice */
bool feth_sysctls_ok(char *why, size_t why_size);
bool interface_exists(const char *name);
/* Undoes only its own steps when one fails: a name that is taken stays as it is. */
bool feth_create_pair(const char *host, const char *peer, unsigned mtu);
void feth_destroy(const char *name);

/* Opens a BPF device bound to ifname in the mode the bridge needs. Returns fd or -1.
 * *buffer_size: requested read size in, actual out (never larger, so a static buffer fits). */
int bpf_open_bound(const char *ifname, unsigned *buffer_size, char *why, size_t why_size);

/* Turns batch write on or off: with it on, one write() carries several frames as BPF
 * records (bpf_put). A private XNU ioctl; true when the mode now is `on`, false when
 * the kernel lacks it (the caller then writes frame by frame). */
bool bpf_set_batch_write(int fd, bool on);
/* Appends a frame as a record; returns the bytes appended, 0 when it does not fit. */
size_t bpf_put(uint8_t *buffer, size_t used, size_t capacity, const uint8_t *frame, size_t length);

/* Iterates records in one BPF read buffer. Returns false at the end. */
typedef struct { const uint8_t *next; size_t left; } BpfCursor; /* next record, bytes left in the read */
bool bpf_next(BpfCursor *cursor, const uint8_t **frame, size_t *length, bool *truncated);

bool ipconfig_set(const char *ifname, const char *method);

/* Network state as macOS publishes it (SCDynamicStore). netstate_watch opens the store
 * lease_get, service_rank_* and primary_interface use; before it they find nothing
 * and change nothing.
 * It calls changed() on the main run loop whenever any network service's IPv4 state changes. */
bool netstate_watch(void (*changed)(void));
#define SERVICE_ID_MAX 64 /* a network service id, e.g. a UUID */
typedef struct {
    char address[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN]; /* validated IPv4 literals */
    char service[SERVICE_ID_MAX]; /* the network service macOS made for the interface */
} Lease;

/* ifname's DHCP lease; ignore lease when false is returned. */
bool lease_get(const char *ifname, Lease *lease);
/* Ranks a network service first, as if it were at the top of the service order: macOS
 * routes the internet through it and uses its DNS; LAN routes and VPNs work as usual.
 * The value is temporary: it disappears with this process. */
bool service_rank_first(const char *service);
void service_rank_clear(const char *service);
/* The interface of macOS's default route right now; empty when there is none. */
void primary_interface(char *out, size_t size);
/* "Wi-Fi", "Thunderbolt Ethernet", ... for a BSD name; the BSD name itself if unknown. */
void interface_display_name(const char *ifname, char *out, size_t size);

#endif
