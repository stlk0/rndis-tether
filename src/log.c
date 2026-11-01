#include "log.h"
#include "config.h"

#include <os/log.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

bool log_verbose;

static void write_line(const char *format, va_list args) {
    static os_log_t daemon_log;
    static int under_launchd = -1; /* -1: not checked yet */
    if (under_launchd < 0) under_launchd = getppid() == 1; /* launchd is PID 1 */

    char line[512];
    size_t used = 0;
    if (!under_launchd) {
        time_t now = time(NULL);
        struct tm local;
        localtime_r(&now, &local);
        used = strftime(line, sizeof line, "%Y-%m-%d %H:%M:%S ", &local);
    }
    int n = vsnprintf(line + used, sizeof line - used, format, args);
    if (n < 0) return;
    /* vsnprintf returns the untruncated length; a cut line keeps its last byte for the newline. */
    used = (size_t)n < sizeof line - used ? used + (size_t)n : sizeof line - 1;

    if (under_launchd) {
        if (!daemon_log) daemon_log = os_log_create(LABEL, "daemon");
        os_log(daemon_log, "%{public}s", line);
    } else {
        line[used++] = '\n'; /* one write per line */
        (void)write(STDERR_FILENO, line, used);
    }
}

void logmsg(const char *format, ...) {
    va_list args;
    va_start(args, format);
    write_line(format, args);
    va_end(args);
}

void logdebug(const char *format, ...) {
    if (!log_verbose) return;
    va_list args;
    va_start(args, format);
    write_line(format, args);
    va_end(args);
}

void make_printable(char *text) {
    for (; *text; ++text)
        if ((unsigned char)*text < 0x20 || (unsigned char)*text > 0x7e) *text = '?';
}
