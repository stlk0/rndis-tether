/* Diagnostic: does BPF on the driver side of a feth pair see what macOS sends on the
 * host side, which way of waiting for it works (GCD source, poll, blocking read), and
 * does a batch write (several frames in one write) reach the host side?
 * Uses a separate test pair feth60/feth61 and the TEST-NET address 192.0.2.1; removes both. */
#include "netif.h"

#include <CoreFoundation/CoreFoundation.h>

#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int bpf = -1, udp = -1;
static unsigned size, fires, frames, sent;
static uint8_t *buffer;

static void send_probe(void) {
    struct sockaddr_in to = {.sin_len = sizeof to, .sin_family = AF_INET, .sin_port = htons(9)};
    inet_pton(AF_INET, "192.0.2.2", &to.sin_addr); /* unresolved neighbour: macOS sends ARP on feth60 */
    if (sendto(udp, "x", 1, 0, (struct sockaddr *)&to, sizeof to) >= 0 || errno == EHOSTDOWN) ++sent;
}

static unsigned count_frames(ssize_t n) {
    BpfCursor c = {buffer, (size_t)n};
    const uint8_t *f;
    size_t l;
    bool t;
    unsigned k = 0;
    while (bpf_next(&c, &f, &l, &t)) ++k;
    return k;
}

static void readable(void *context) {
    (void)context;
    ++fires;
    ssize_t n = read(bpf, buffer, size);
    if (n > 0) frames += count_frames(n);
}

int main(void) {
    if (geteuid()) { fputs("run with sudo\n", stderr); return 1; }
    char why[200];
    feth_destroy("feth60");
    feth_destroy("feth61");
    if (!feth_create_pair("feth60", "feth61", 1500)) { fputs("cannot create feth60/feth61\n", stderr); return 1; }
    size = 32768;
    bpf = bpf_open_bound("feth61", &size, why, sizeof why);
    const char *addr[] = {"/sbin/ifconfig", "feth60", "inet", "192.0.2.1/24", "up", NULL};
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (bpf < 0 || !run_command(addr, 5000) || udp < 0) {
        fprintf(stderr, "setup failed: %s\n", bpf < 0 ? why : "ifconfig/socket");
        feth_destroy("feth60");
        feth_destroy("feth61");
        return 1;
    }
    buffer = malloc(size);
    printf("BPF on feth61 ready, buffer %u bytes\n", size);

    /* 1. GCD read source, exactly as rndis-tether does it. */
    dispatch_source_t s = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)bpf, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler_f(s, readable);
    dispatch_resume(s);
    for (int i = 0; i < 10; ++i) {
        send_probe();
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.3, false);
    }
    dispatch_source_cancel(s);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, false);
    printf("1. GCD source:    %u probes sent, handler ran %u times, %u frames read\n", sent, fires, frames);

    /* 2. poll() + non-blocking read. */
    unsigned ready = 0, polled = 0;
    for (int i = 0; i < 5; ++i) {
        send_probe();
        struct pollfd p = {bpf, POLLIN, 0};
        if (poll(&p, 1, 1000) > 0) {
            ++ready;
            ssize_t n = read(bpf, buffer, size);
            if (n > 0) polled += count_frames(n);
        }
    }
    printf("2. poll():        ready %u/5 times, %u frames read\n", ready, polled);

    /* Raw view of one read, to see what the kernel actually returns. */
    for (int i = 0; i < 3; ++i) {
        send_probe();
        struct pollfd p = {bpf, POLLIN, 0};
        int pr = poll(&p, 1, 1000);
        memset(buffer, 0xee, 64);
        errno = 0;
        ssize_t n = read(bpf, buffer, size);
        int e = errno;
        printf("raw read %d: poll=%d revents=0x%x read=%zd errno=%d (%s) sizeof(bpf_hdr)=%zu\n   ",
               i, pr, p.revents, n, e, strerror(e), sizeof(struct bpf_hdr));
        for (int k = 0; k < 48; ++k) printf("%02x%s", buffer[k], k % 4 == 3 ? " " : "");
        putchar('\n');
    }

    /* 3. Blocking read with a timeout (what TetherKit does). */
    unsigned blocking = 0;
    int off = 0;
    struct timeval timeout = {.tv_sec = 1};
    ioctl(bpf, FIONBIO, &off);
    ioctl(bpf, BIOCSRTIMEOUT, &timeout);
    for (int i = 0; i < 5; ++i) {
        send_probe();
        ssize_t n = read(bpf, buffer, size);
        if (n > 0) blocking += count_frames(n);
    }
    printf("3. blocking read: %u frames read\n", blocking);

    /* 4. Batch write on feth61: both frames must arrive on feth60 (seen by a second BPF). */
    unsigned in_size = 32768;
    int in = bpf_open_bound("feth60", &in_size, why, sizeof why);
    uint8_t frame[2][60], batch[256], *in_buffer = malloc(in_size);
    size_t used = 0;
    for (int k = 0; k < 2; ++k) {
        memset(frame[k], 0, sizeof frame[k]);
        memset(frame[k], 0xff, 6);                       /* broadcast */
        frame[k][6] = 0x02;                              /* locally administered source */
        frame[k][12] = 0x88, frame[k][13] = 0xb5;        /* local experimental EtherType */
        frame[k][14] = (uint8_t)k;
        used += bpf_put(batch, used, sizeof batch, frame[k], sizeof frame[k]);
    }
    bool batch_on = bpf_batch_write(bpf, true);
    ssize_t written = batch_on ? write(bpf, batch, used) : -1;
    int write_error = errno;
    unsigned arrived = 0;
    for (int i = 0; in >= 0 && in_buffer && i < 5 && arrived < 2; ++i) {
        struct pollfd p = {in, POLLIN, 0};
        if (poll(&p, 1, 300) <= 0) continue;
        ssize_t n = read(in, in_buffer, in_size);
        BpfCursor c = {in_buffer, n > 0 ? (size_t)n : 0};
        const uint8_t *f;
        size_t l;
        bool t;
        while (bpf_next(&c, &f, &l, &t)) if (l >= 15 && f[12] == 0x88 && f[13] == 0xb5) ++arrived;
    }
    printf("4. batch write:   ioctl %s, write %zd of %zu bytes%s%s, %u/2 frames arrived on feth60\n",
           batch_on ? "accepted" : "not available", written, used, written < 0 ? ", errno " : "",
           written < 0 ? strerror(write_error) : "", arrived);
    if (in >= 0) close(in);
    free(in_buffer);

    struct bpf_stat st = {0};
    if (!ioctl(bpf, BIOCGSTATS, &st)) printf("BPF stats: received %u, dropped %u\n", st.bs_recv, st.bs_drop);
    close(bpf);
    feth_destroy("feth60");
    feth_destroy("feth61");
    puts("feth60/feth61 removed");
    return 0;
}
