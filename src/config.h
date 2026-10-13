/* Settings and the fixed places rndis-tether uses. Settings come from CONFIG_PATH
 * ("name = value" lines, # comments); options of `rndis-tether run` override them.
 * Shared by the daemon and the command-line tool.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define VERSION "1.0.1"
#define LABEL "io.github.stlk0.rndis-tether"           /* launchd label and log subsystem */
#define HELPER_PATH "/Library/PrivilegedHelperTools/" LABEL
#define PLIST_PATH "/Library/LaunchDaemons/" LABEL ".plist"
#define CONFIG_PATH "/etc/rndis-tether.conf"
#define STATUS_SOCKET "/var/run/rndis-tether.sock"     /* the daemon answers with its state */
#define ADMIN_SOCKET "/var/run/rndis-tether-admin.sock" /* administrators change settings (admin.h) */
/* Only root may enter RUNTIME_DIR: /var/run is writable by group daemon, so the sockets
 * are prepared here and renamed into place (runtime.h). */
#define RUNTIME_DIR "/var/db/rndis-tether"
#define LOCK_PATH RUNTIME_DIR "/lock"                  /* held by the running daemon */
#define INTERFACES_PATH RUNTIME_DIR "/interfaces"      /* the feth pair this program created */
#define OLD_LOCK_PATH "/var/run/rndis-tether.lock"     /* 1.0.0; install and uninstall remove it */

typedef struct {
    bool prefer_phone, ipv6, verbose;
    unsigned tx_batch; /* 0 = auto: what the phone allows, up to 32 */
    char host[IFNAMSIZ], peer[IFNAMSIZ];
} Config;

void config_defaults(Config *c);
/* One setting by its file name ("prefer-phone", "tx-batch", ...). */
bool config_set(Config *c, const char *name, const char *value, char *why, size_t why_size);
/* A name for host-interface or peer-interface: fethN. */
bool config_interface_valid(const char *name);
/* Settings that cannot go together (both interfaces with one name). */
bool config_check(const Config *c, char *why, size_t why_size);
/* Settings the running service applies at once (prefer-phone, verbose); the others
 * only when the service starts again. */
bool config_live(const char *name);
/* A missing file leaves the defaults. A bad or overlong line is skipped; why names the first one. */
bool config_load(Config *c, const char *path, char *why, size_t why_size);
/* Rewrites the whole file, with an explanation above every setting. */
bool config_save(const Config *c, const char *path, char *why, size_t why_size);
/* "name = value" lines, as in the file. */
void config_print(const Config *c, FILE *out);

#endif
