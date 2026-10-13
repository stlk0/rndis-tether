/* Files the service keeps while it runs. /var/run is root:daemon 0775 without the
 * sticky bit, so nothing there is opened, chmod'ed or chown'ed by name: a socket gets
 * its owner and mode in a directory only root can enter (RUNTIME_DIR in config.h) and
 * is then renamed into place. The lock and the interface marker stay in that directory.
 */
#ifndef RUNTIME_H
#define RUNTIME_H

#include <net/if.h>
#include <stdbool.h>
#include <sys/types.h>

/* Creates dir for this user only, or checks that an existing one is just that; false
 * with errno EPERM when it is not. */
bool runtime_dir(const char *dir);
/* A non-blocking listening socket at path, owned by group gid with mode, prepared in
 * dir and renamed over whatever is at path. The descriptor, or -1. */
int runtime_listen(const char *dir, const char *path, gid_t gid, mode_t mode);

/* The marker names the feth pair this program created, so that only those are ever
 * destroyed: a crashed instance's leftovers, never another program's interfaces. */
bool runtime_mark_interfaces(const char *marker, const char *host, const char *peer);
/* The pair a marker names; false when there is none or it is not two valid names. */
bool runtime_marked_interfaces(const char *marker, char host[IFNAMSIZ], char peer[IFNAMSIZ]);
/* Destroys the marked pair; the marker goes once neither interface exists. */
void runtime_destroy_interfaces(const char *marker);

#endif
