#include "runtime.h"
#include "config.h"
#include "netif.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

bool runtime_dir_ready(const char *dir) {
    struct stat st;
    if (mkdir(dir, 0700) && errno != EEXIST) return false;
    if (lstat(dir, &st)) return false;
    if (S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077)) return true;
    errno = EPERM;
    return false;
}

int runtime_listen(const char *dir, const char *path, gid_t gid, mode_t mode) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    const char *slash = strrchr(path, '/');
    int length = snprintf(address.sun_path, sizeof address.sun_path, "%s/%s.new", dir, slash ? slash + 1 : path);
    if (length < 0 || (size_t)length >= sizeof address.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    unlink(address.sun_path);
    /* Owner-only until it has its mode, so nobody else can connect in between. */
    mode_t umask_before = umask(0177);
    bool bound = fd >= 0 && !fcntl(fd, F_SETFD, FD_CLOEXEC) && !fcntl(fd, F_SETFL, O_NONBLOCK) &&
                 !bind(fd, (const struct sockaddr *)&address, sizeof address);
    umask(umask_before);
    if (bound && !chown(address.sun_path, (uid_t)-1, gid) && !chmod(address.sun_path, mode) && !listen(fd, RUNTIME_BACKLOG) &&
        !rename(address.sun_path, path))
        return fd;
    int error = errno;
    if (fd >= 0) close(fd);
    if (bound) unlink(address.sun_path);
    errno = error;
    return -1;
}

bool runtime_mark_interfaces(const char *marker, const char *host, const char *peer) {
    char text[2 * IFNAMSIZ + 2];
    int length = snprintf(text, sizeof text, "%s %s\n", host, peer);
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = length > 0 && (size_t)length < sizeof text && write(fd, text, (size_t)length) == length;
    if (close(fd)) ok = false;
    return ok;
}

bool runtime_marked_interfaces(const char *marker, char host[IFNAMSIZ], char peer[IFNAMSIZ]) {
    /* Wider than IFNAMSIZ on purpose: an overlong name (or its first 31 characters) is still
     * too long and is rejected below, never cut into a valid-looking one.
     * %31s is one less than the buffers. */
    char text[64], host_name[32], peer_name[32], extra;
    int fd = open(marker, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, text, sizeof text - 1);
    close(fd);
    if (n <= 0) return false;
    text[n] = 0;
    /* The names go to `ifconfig <name> destroy`: only two different fethN. */
    if (sscanf(text, "%31s %31s %c", host_name, peer_name, &extra) != 2 || !config_interface_valid(host_name) ||
        !config_interface_valid(peer_name) || !strcmp(host_name, peer_name)) return false;
    strlcpy(host, host_name, IFNAMSIZ);
    strlcpy(peer, peer_name, IFNAMSIZ);
    return true;
}

void runtime_destroy_interfaces(const char *marker) {
    char host[IFNAMSIZ], peer[IFNAMSIZ];
    if (runtime_marked_interfaces(marker, host, peer)) {
        feth_destroy(host);
        feth_destroy(peer);
        if (interface_exists(host) || interface_exists(peer)) return; /* try again next time */
    }
    unlink(marker);
}
