/* One connection to the phone, from opening its USB interfaces to closing them: RNDIS
 * bring-up, the feth pair, the data path, health checks, and the DHCP lease together
 * with the phone's rank among macOS's network services.
 *
 * Only one session exists at a time. It never retries by itself: when it breaks, it
 * tells the daemon, which decides between stopping it for good and trying again.
 */
#ifndef SESSION_H
#define SESSION_H

#include "config.h"
#include "datapath.h"

#include <IOKit/IOKitLib.h>
#include <time.h>

typedef struct {
    char interface[IFNAMSIZ];
    time_t connected_at;
    char address[16], gateway[16]; /* empty until the phone's DHCP answers */
    char primary[IFNAMSIZ];        /* the interface macOS sends internet traffic to now */
    DataStats data;
    uint64_t usb_errors; /* data and control pipes */
    unsigned resets;
} SessionStatus;

/* Starts a session on an RNDIS control interface. NULL, or why it could not start;
 * *init_failed: the interface did not answer RNDIS INITIALIZE at all. If the session
 * breaks later, failed() runs from the run loop; the daemon then calls session_stop. */
const char *session_start(io_service_t device, const char *name, const Config *cfg, void (*failed)(void),
                          bool *init_failed);
/* Why the session broke, for the log and `rndis-tether status`. */
const char *session_failure(void);
/* The phone is gone: no HALT on the way out. */
void session_unplugged(void);
/* Ends the session; quiet: no "disconnecting" line (a failure repeating itself). */
void session_stop(const char *reason, bool quiet);
bool session_active(void);
uint64_t session_age_ms(void);
bool session_status(SessionStatus *out);
/* For netstate_watch: macOS changed some service's IPv4 state. Also after prefer-phone
 * changed in the running service. */
void session_network_changed(void);

#endif
