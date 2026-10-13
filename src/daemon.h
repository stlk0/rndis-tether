/* The background service (`rndis-tether run`): waits for a phone with USB tethering,
 * keeps one session with it across failures, sleep and re-enumeration, answers
 * `rndis-tether status` and applies settings that administrators change.
 * Single-threaded: IOKit notifications, USB completions, BPF, timers, signals and
 * both sockets all run on the main run loop, so no locks are needed.
 */
#ifndef DAEMON_H
#define DAEMON_H

#include "config.h"

/* settings_problem: a bad line in the settings file, shown by `status`, or "".
 * Returns the process exit status. */
int daemon_run(const Config *cfg, const char *settings_problem);

#endif
