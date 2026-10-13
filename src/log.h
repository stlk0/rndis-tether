/* One log line. Under launchd it goes to unified logging (subsystem LABEL
 * from config.h), which rotates and keeps history by itself:
 *   log stream --style compact --predicate 'subsystem == "io.github.stlk0.rndis-tether"'
 * Foreground runs and tests get timestamped lines on stderr instead.
 */
#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

/* The verbose setting: logdebug lines are written only when it is on. */
extern bool log_verbose;

void logmsg(const char *format, ...) __attribute__((format(printf, 1, 2)));
void logdebug(const char *format, ...) __attribute__((format(printf, 1, 2)));
/* Text from a device, before it reaches logs, status lines or a terminal: every byte
 * outside printable ASCII becomes '?'. */
void printable(char *text);

#endif
