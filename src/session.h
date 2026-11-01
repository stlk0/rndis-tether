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
#include "control.h"
#include "datapath.h"
#include "netif.h"

#include <IOKit/IOKitLib.h>
#include <netinet/in.h>
#include <time.h>

#define SESSION_REASON_SIZE 200 /* why a session failed or could not start */
#define SESSION_REASON_TAKEN "already exists" /* cli.c matches this for advice */

typedef struct {
    char interface[IFNAMSIZ];
    time_t connected_at;
    char address[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN]; /* empty until the phone's DHCP answers */
    char primary[IFNAMSIZ];        /* the interface macOS sends internet traffic to now */
    DataStats data;
    uint64_t usb_errors; /* data and control pipes */
    unsigned resets;
} SessionStatus;

/* Starts a session on an RNDIS control interface; phone_name is how the log names the
 * phone. NULL, or why it could not start; *init_failed: INITIALIZE got no usable
 * completion (no answer, a failed transfer, or a reply that is not RNDIS 1.0 over 802.3).
 * If the session breaks later, failed() runs from the run loop; the daemon then calls
 * session_stop. */
const char *session_start(io_service_t device, const char *phone_name, const Config *cfg, void (*failed)(void),
                          bool *init_failed);
/* Why the session broke, for the log and `rndis-tether status`. */
const char *session_failure(void);
/* The phone is gone: no HALT on the way out. */
void session_unplugged(void);
/* Two ipconfig commands, HALT behind an in-flight pipe-0 request, then two ifconfig destroys. */
#define SESSION_TEARDOWN_MAX_MS (4 * COMMAND_TIMEOUT_MS + 2 * CONTROL_SEND_TIMEOUT_MS)
/* Ends the session; quiet: no "disconnecting" line (a failure repeating itself). */
void session_stop(const char *reason, bool quiet);
/* True while the USB interfaces are open, bring-up included. */
bool session_active(void);
/* Milliseconds since the USB interfaces were opened, bring-up included; 0 without a session. */
uint64_t session_age_ms(void);
/* The figures `rndis-tether status` shows; false without a session. */
bool session_status(SessionStatus *out);
/* For netstate_watch: macOS changed some service's IPv4 state. Also after prefer-phone
 * changed in the running service. */
void session_network_changed(void);

#endif
