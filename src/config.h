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

#define VERSION "1.1.1"
#define LABEL "io.github.stlk0.rndis-tether"           /* launchd label and log subsystem */
#define SERVICE_TARGET "system/" LABEL /* launchctl's name for the service */
#define HELPER_DIR "/Library/PrivilegedHelperTools" /* root-owned; launchd runs the copy here */
#define HELPER_PATH HELPER_DIR "/" LABEL
#define PLIST_PATH "/Library/LaunchDaemons/" LABEL ".plist"
#define CONFIG_PATH "/etc/rndis-tether.conf"
#define STATUS_SOCKET "/var/run/rndis-tether.sock"     /* the daemon answers with its state */
#define ADMIN_SOCKET "/var/run/rndis-tether-admin.sock" /* administrators change settings (admin.h) */
/* Only root may enter RUNTIME_DIR: /var/run is writable by group daemon, so the sockets
 * are prepared here and renamed into place (runtime.h). */
#define RUNTIME_DIR "/var/db/rndis-tether"
#define LOCK_PATH RUNTIME_DIR "/lock"                  /* held by the running daemon */
#define INTERFACES_PATH RUNTIME_DIR "/interfaces"      /* the feth pair this program created */

#define TX_BATCH_MAX 32u        /* tx-batch: packets per bulk OUT transfer; auto goes up to it */
#define CONFIG_PROBLEM_SIZE 300 /* a settings problem: a bad line as config_load reports it, or a rejected setting */

/* Setting names: keys in CONFIG_PATH, `config NAME VALUE` and `set NAME VALUE`. */
#define SETTING_PREFER_PHONE "prefer-phone"
#define SETTING_IPV6 "ipv6"
#define SETTING_TX_BATCH "tx-batch"
#define SETTING_VERBOSE "verbose"
#define SETTING_HOST_INTERFACE "host-interface"
#define SETTING_PEER_INTERFACE "peer-interface"

typedef struct {
    bool prefer_phone, ipv6, verbose;
    unsigned tx_batch; /* 0 = auto: what the phone allows, up to TX_BATCH_MAX */
    char host[IFNAMSIZ], peer[IFNAMSIZ];
} Config;

/* How the settings file and the status socket write a bool. */
static inline const char *config_bool_text(bool on) {
    return on ? "yes" : "no";
}

void config_defaults(Config *c);
/* One setting by its file name ("prefer-phone", "tx-batch", ...). */
bool config_set(Config *c, const char *name, const char *value, char *why, size_t why_size);
/* yes/no (also true/false, on/off, 1/0); false and why naming name otherwise. */
bool config_parse_bool(const char *name, const char *value, bool *out, char *why, size_t why_size);
/* A name for host-interface or peer-interface: fethN. */
bool config_interface_valid(const char *name);
/* Settings that cannot go together (both interfaces with one name). */
bool config_check(const Config *c, char *why, size_t why_size);
/* Settings the running service applies at once (prefer-phone, verbose); the others
 * only when the service starts again. */
bool config_live(const char *name);
/* One setting for the running service: false and why when the name or value is not
 * valid or the setting applies only after a restart; c changes only on success. */
bool config_set_live(Config *c, const char *name, const char *value, char *why, size_t why_size);
/* Reads path into c, which keeps its values for what the file does not set (a missing
 * file changes nothing). A bad or overlong line is skipped; why names the first problem.
 * Equal interface names both go back to their defaults. */
bool config_load(Config *c, const char *path, char *why, size_t why_size);
/* Rewrites the whole file, with an explanation above every setting. */
bool config_save(const Config *c, const char *path, char *why, size_t why_size);
/* "name = value" lines, as in the file. */
void config_print(const Config *c, FILE *out);

#endif
