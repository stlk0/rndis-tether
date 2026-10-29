#include "cli.h"
#include "config.h"
#include "netif.h"
#include "runtime.h"

#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define COMMAND_LINK "/usr/local/bin/rndis-tether"
#define PAUSE_DENIED "only administrators of this Mac can disconnect or connect the phone"
#define LOG_HINT "/usr/bin/log show --last 30m --style compact --predicate 'subsystem == \"" LABEL "\"'"

/* ------------------------------------------------------------ talking to the daemon */

/* Connects to one of the service's sockets; -1 unless root is listening there. A
 * process of group daemon could put its own socket into /var/run. */
static int connect_service(const char *path, int seconds) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strlcpy(address.sun_path, path, sizeof address.sun_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {seconds, 0};
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    uid_t uid = 0;
    gid_t gid;
    if (connect(fd, (const struct sockaddr *)&address, sizeof address) || getpeereid(fd, &uid, &gid) || uid) {
        int error = uid ? ECONNREFUSED : errno; /* ask_service tells EACCES (not an administrator) apart */
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

/* The running daemon's state as "name=value" lines; false when no daemon answers. */
static bool status_query(char *text, size_t size) {
    int fd = connect_service(STATUS_SOCKET, 2);
    size_t used = 0;
    ssize_t n;
    while (fd >= 0 && used + 1 < size && (n = read(fd, text + used, size - 1 - used)) > 0) used += (size_t)n;
    if (fd >= 0) close(fd);
    if (size) text[used] = 0;
    return used > 0;
}

/* A setting the running service applies at once. 1: applied; 0: refused, see why
 * (denied when the caller is not an administrator); -1: no service answers, so only
 * the file can change. */
static int ask_service(const char *name, const char *value, const char *denied, char *why, size_t why_size) {
    int fd = connect_service(ADMIN_SOCKET, 5);
    if (fd < 0) {
        if (errno != EACCES) return -1;
        strlcpy(why, denied, why_size);
        return 0;
    }
    char request[160], reply[400];
    int length = snprintf(request, sizeof request, "set %s %s\n", name, value);
    size_t used = 0;
    ssize_t n;
    if (length > 0 && (size_t)length < sizeof request && write(fd, request, (size_t)length) == length)
        while (used + 1 < sizeof reply && (n = read(fd, reply + used, sizeof reply - 1 - used)) > 0) used += (size_t)n;
    close(fd);
    reply[used] = 0;
    if (!strcmp(reply, "ok\n")) return 1;
    reply[strcspn(reply, "\n")] = 0;
    strlcpy(why, !strncmp(reply, "error: ", 7) ? reply + 7 : "the service did not answer", why_size);
    return 0;
}

/* Value of "name=value" in the daemon's answer; empty when absent. */
static const char *field(const char *text, const char *name, char *out, size_t size) {
    size_t length = strlen(name);
    out[0] = 0;
    for (const char *line = text; *line;) {
        const char *end = strchr(line, '\n');
        size_t line_length = end ? (size_t)(end - line) : strlen(line);
        if (line_length > length && !strncmp(line, name, length) && line[length] == '=') {
            size_t n = line_length - length - 1;
            if (n >= size) n = size - 1;
            memcpy(out, line + length + 1, n);
            out[n] = 0;
            break;
        }
        line += line_length + (end ? 1 : 0);
    }
    return out;
}

static unsigned long long number(const char *text, const char *name) {
    char value[32];
    return strtoull(field(text, name, value, sizeof value), NULL, 10);
}

/* ------------------------------------------------------------------ status output */

static void bytes_text(unsigned long long bytes, char *out, size_t size) {
    if (bytes >= 1000000000ull) snprintf(out, size, "%.2f GB", (double)bytes / 1e9);
    else if (bytes >= 1000000ull) snprintf(out, size, "%.1f MB", (double)bytes / 1e6);
    else snprintf(out, size, "%.0f KB", (double)bytes / 1e3);
}

static void speed_text(double bits_per_second, char *out, size_t size) {
    if (bits_per_second >= 1e6) snprintf(out, size, "%.1f Mbit/s", bits_per_second / 1e6);
    else snprintf(out, size, "%.0f kbit/s", bits_per_second / 1e3);
}

static void duration_text(long long seconds, char *out, size_t size) {
    if (seconds < 0) seconds = 0;
    if (seconds < 60) snprintf(out, size, "%lld s", seconds);
    else if (seconds < 3600) snprintf(out, size, "%lld min", seconds / 60);
    else snprintf(out, size, "%lld h %lld min", seconds / 3600, seconds / 60 % 60);
}

/* What to do about a failure the daemon reports, in plain words. */
static const char *advice(const char *problem) {
    if (strstr(problem, "already open by another program"))
        return "Another program is using the phone's USB tethering (HoRNDIS, TetherKit or a second\n"
               "  copy of rndis-tether). Quit it; rndis-tether keeps trying by itself.";
    if (strstr(problem, "net.link.fake"))
        return "A macOS setting for virtual network interfaces was changed (see above). Restarting\n"
               "  the Mac restores it.";
    if (strstr(problem, "already exists"))
        return "Another program (a VPN or another tethering tool?) uses that network interface.\n"
               "  Quit it, or let rndis-tether use other names:\n"
               "    sudo rndis-tether config host-interface feth52\n"
               "    sudo rndis-tether config peer-interface feth53";
    if (strstr(problem, "data interface not found"))
        return "The phone is still switching USB tethering on. Wait a few seconds.";
    return "rndis-tether keeps trying by itself. If this does not go away, unlock the phone and\n"
           "  turn USB tethering off and on again, or unplug the cable and plug it in again.";
}

static const char *const TETHERING_HELP =
    "  Connect the phone with a USB cable, then turn on USB tethering on the phone:\n"
    "    Samsung: Settings > Connections > Mobile Hotspot and Tethering > USB tethering\n"
    "    Pixel and most others: Settings > Network & internet > Hotspot & tethering > USB tethering\n";

/* Which connection carries the internet, as macOS decided it. */
static void print_route(const char *text) {
    char primary[32], interface[32], prefer[8], name[128];
    field(text, "primary", primary, sizeof primary);
    field(text, "interface", interface, sizeof interface);
    field(text, "prefer-phone", prefer, sizeof prefer);
    if (!strcmp(primary, interface)) {
        printf("Internet: goes through the phone\n");
        return;
    }
    if (!primary[0]) {
        printf("Internet: macOS has no route to the internet right now\n");
        return;
    }
    interface_display_name(primary, name, sizeof name);
    if (!strcmp(prefer, "yes"))
        printf("Internet: goes through %s, which macOS ranks above the phone (a VPN?)\n", name);
    else
        printf("Internet: goes through %s; the phone takes over without it (prefer-phone = no)\n", name);
}

/* down/up < 0: no speed line (one-shot status). */
static void print_status(const char *text, double down, double up) {
    char state[32], phone[160], address[32], gateway[32], problem[256], settings[300], version[32];
    field(text, "state", state, sizeof state);
    field(text, "phone", phone, sizeof phone);
    field(text, "problem", problem, sizeof problem);

    if (!strcmp(state, "paused")) {
        if (phone[0]) printf("Phone:    %s\n", phone);
        printf("Status:   disconnected (run: rndis-tether connect)\n");
    } else if (!strcmp(state, "no-phone")) {
        printf("Status:   waiting for a phone\n\n%s", TETHERING_HELP);
    } else if (!strcmp(state, "unsupported")) {
        printf("Phone:    %s\nStatus:   this USB device does not work as USB tethering\n\n"
               "  It looked like a tethering phone but did not answer like one. Unplug it and plug it\n"
               "  in again after turning USB tethering on.\n", phone);
    } else if (!strcmp(state, "sleeping")) {
        printf("Status:   paused while the Mac sleeps\n");
    } else if (!strcmp(state, "retrying")) {
        printf("Phone:    %s\nStatus:   cannot connect: %s\n\n  %s\n", phone, problem, advice(problem));
    } else if (!strcmp(state, "connecting")) {
        printf("Phone:    %s\nStatus:   connecting, waiting for an address from the phone...\n", phone);
    } else if (!strcmp(state, "online")) {
        char since[32], received[32], sent[32];
        long long started = (long long)number(text, "connected-since");
        duration_text((long long)time(NULL) - started, since, sizeof since);
        field(text, "address", address, sizeof address);
        field(text, "gateway", gateway, sizeof gateway);
        bytes_text(number(text, "rx-bytes"), received, sizeof received);
        bytes_text(number(text, "tx-bytes"), sent, sizeof sent);
        printf("Phone:    %s\n", phone);
        printf("Status:   online for %s, address %s (phone %s)\n", since, address, gateway);
        print_route(text);
        printf("Traffic:  received %s, sent %s\n", received, sent);
        if (down >= 0) {
            char d[32], u[32];
            speed_text(down, d, sizeof d);
            speed_text(up, u, sizeof u);
            printf("Speed:    down %s, up %s\n", d, u);
        }
        unsigned long long dropped = number(text, "rx-dropped") + number(text, "tx-dropped");
        unsigned long long errors = number(text, "usb-errors"), resets = number(text, "resets");
        if (dropped || errors || resets)
            printf("Problems: %llu packets dropped, %llu USB errors, %llu resets\n", dropped, errors, resets);
    } else {
        printf("Status:   %s\n", state);
    }
    if (*field(text, "settings-problem", settings, sizeof settings))
        printf("\nSettings: %s\n  Fix it with: sudo rndis-tether config <name> <value>\n", settings);
    if (strcmp(field(text, "version", version, sizeof version), VERSION))
        printf("\nThe service runs version %s, this program is %s. Update the service:\n"
               "  sudo rndis-tether install\n", version, VERSION);
}

static bool service_installed(void) {
    struct stat st;
    return !stat(PLIST_PATH, &st);
}

static void print_not_running(void) {
    if (!service_installed())
        printf("rndis-tether is not installed as a service.\n  Install it:  sudo rndis-tether install\n");
    else
        printf("The rndis-tether service is installed but not running.\n"
               "  Start it again:  sudo rndis-tether install\n"
               "  Its log:  " LOG_HINT "\n");
}

int cli_status(bool raw) {
    char text[2048];
    if (!status_query(text, sizeof text)) {
        if (raw) puts("state=not-running");
        else print_not_running();
        return 1;
    }
    if (raw) fputs(text, stdout);
    else print_status(text, -1, -1);
    return 0;
}

static volatile sig_atomic_t interrupted;

static void on_interrupt(int signal_number) {
    (void)signal_number;
    interrupted = 1;
}

int cli_monitor(void) {
    signal(SIGINT, on_interrupt);
    signal(SIGTERM, on_interrupt);
    bool terminal = isatty(STDOUT_FILENO);
    if (terminal) fputs("\033[?25l", stdout); /* hide the cursor */
    unsigned long long last_rx = 0, last_tx = 0;
    uint64_t last_ns = 0;
    while (!interrupted) {
        char text[2048], clock[16];
        bool running = status_query(text, sizeof text);
        uint64_t now_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        double down = 0, up = 0;
        unsigned long long rx = running ? number(text, "rx-bytes") : 0, tx = running ? number(text, "tx-bytes") : 0;
        if (last_ns && rx >= last_rx && tx >= last_tx) { /* counters restart with every session */
            double seconds = (double)(now_ns - last_ns) / 1e9;
            down = (double)(rx - last_rx) * 8 / seconds;
            up = (double)(tx - last_tx) * 8 / seconds;
        }
        last_rx = rx;
        last_tx = tx;
        last_ns = now_ns;

        time_t wall = time(NULL);
        struct tm local;
        localtime_r(&wall, &local);
        strftime(clock, sizeof clock, "%H:%M:%S", &local);
        if (terminal) fputs("\033[H\033[J", stdout); /* home, clear */
        printf("rndis-tether monitor    %s    Ctrl-C to quit\n\n", clock);
        if (running) print_status(text, down, up);
        else print_not_running();
        fflush(stdout);
        struct timespec second = {1, 0};
        nanosleep(&second, NULL); /* a signal ends it early */
    }
    if (terminal) fputs("\033[?25h", stdout);
    putchar('\n');
    return 0;
}

int cli_pause(bool paused) {
    char text[2048], value[8], why[400];
    if (!status_query(text, sizeof text)) {
        print_not_running();
        return 1;
    }
    if (!*field(text, "paused", value, sizeof value)) { /* 1.0.x would answer with advice about restarting */
        fprintf(stderr, "The service runs version %s, which cannot %s. Update the service:\n"
                "  sudo rndis-tether install\n", field(text, "version", value, sizeof value),
                paused ? "disconnect" : "connect");
        return 1;
    }
    int asked = ask_service("paused", paused ? "yes" : "no", PAUSE_DENIED, why, sizeof why);
    if (asked < 0) fputs("The service did not answer. Its log:\n  " LOG_HINT "\n", stderr);
    else if (!asked) fprintf(stderr, "Not changed: %s.\n", why);
    else if (paused) puts("Disconnected; the phone can stay plugged in. Use it again with:  rndis-tether connect");
    else puts("Connected again; rndis-tether status shows the details.");
    return asked > 0 ? 0 : 1;
}

/* ---------------------------------------------------------------- service control */

static bool need_root(const char *command) {
    if (!geteuid()) return true;
    fprintf(stderr, "This needs administrator rights. Run:\n  sudo rndis-tether %s\n", command);
    return false;
}

static bool launchctl(const char *a, const char *b, const char *c, bool quiet) {
    const char *argv[] = {"/bin/launchctl", a, b, c, NULL};
    return quiet ? run_command_quiet(argv, 20000) : run_command(argv, 20000);
}

static bool loaded(const char *label) {
    char target[128];
    snprintf(target, sizeof target, "system/%s", label);
    return launchctl("print", target, NULL, true);
}

static bool wait_for_daemon(void) {
    for (int i = 0; i < 50; ++i) {
        char text[64];
        if (status_query(text, sizeof text)) return true;
        usleep(100000);
    }
    return false;
}

static void self_path(char *out, size_t size) {
    char path[PATH_MAX];
    uint32_t length = sizeof path;
    out[0] = 0;
    if (!_NSGetExecutablePath(path, &length) && realpath(path, out) && strlen(out) < size) return;
    out[0] = 0;
}

static bool install_binary(const char *self, char *why, size_t why_size) {
    if (!strcmp(self, HELPER_PATH)) return true; /* reinstalling from the installed copy */
    const char *temporary = HELPER_PATH ".new";
    (void)mkdir("/Library/PrivilegedHelperTools", 0755);
    unlink(temporary);
    /* Data only: no quarantine or other extended attributes travel with it. */
    if (copyfile(self, temporary, NULL, COPYFILE_DATA) || chown(temporary, 0, 0) || chmod(temporary, 0755) ||
        rename(temporary, HELPER_PATH)) {
        snprintf(why, why_size, "cannot copy the program to " HELPER_PATH ": %s", strerror(errno));
        unlink(temporary);
        return false;
    }
    return true;
}

static bool write_plist(char *why, size_t why_size) {
    static const char plist[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "    <key>Label</key>\n"
        "    <string>" LABEL "</string>\n"
        "    <key>ProgramArguments</key>\n"
        "    <array>\n"
        "        <string>" HELPER_PATH "</string>\n"
        "        <string>run</string>\n"
        "    </array>\n"
        "    <key>RunAtLoad</key>\n"
        "    <true/>\n"
        "    <key>KeepAlive</key>\n"
        "    <true/>\n"
        "    <key>ThrottleInterval</key>\n"
        "    <integer>10</integer>\n"
        "    <key>ExitTimeOut</key>\n"     /* the longest teardown takes about 21 s */
        "    <integer>30</integer>\n"
        "</dict>\n"
        "</plist>\n";
    const char *temporary = PLIST_PATH ".new";
    FILE *f = fopen(temporary, "w");
    bool ok = f && fputs(plist, f) >= 0;
    if (f && fclose(f)) ok = false;
    if (!ok || chown(temporary, 0, 0) || chmod(temporary, 0644) || rename(temporary, PLIST_PATH)) {
        snprintf(why, why_size, "cannot write " PLIST_PATH ": %s", strerror(errno));
        unlink(temporary);
        return false;
    }
    return true;
}

/* Without Homebrew nothing puts rndis-tether on PATH; /usr/local/bin is on it by default. */
static void link_command(void) {
    struct stat st;
    if (!lstat(COMMAND_LINK, &st) || !lstat("/opt/homebrew/bin/rndis-tether", &st)) return;
    (void)mkdir("/usr/local", 0755);
    (void)mkdir("/usr/local/bin", 0755);
    (void)symlink(HELPER_PATH, COMMAND_LINK);
}

static void unlink_command(void) {
    char target[PATH_MAX];
    ssize_t n = readlink(COMMAND_LINK, target, sizeof target - 1);
    if (n <= 0) return;
    target[n] = 0;
    if (!strcmp(target, HELPER_PATH)) unlink(COMMAND_LINK);
}

int cli_install(void) {
    if (!need_root("install")) return 1;
    char self[PATH_MAX], why[400];
    self_path(self, sizeof self);
    if (!self[0]) {
        fputs("Installation failed: cannot find this program's own file.\n", stderr);
        return 1;
    }
    bool updating = loaded(LABEL);
    if (updating) (void)launchctl("bootout", "system/" LABEL, NULL, true);
    unlink(OLD_LOCK_PATH);
    if (!install_binary(self, why, sizeof why) || !write_plist(why, sizeof why)) {
        fprintf(stderr, "Installation failed: %s\n", why);
        return 1;
    }
    struct stat st;
    Config config;
    config_defaults(&config);
    if (stat(CONFIG_PATH, &st)) {
        if (!config_save(&config, CONFIG_PATH, why, sizeof why)) fprintf(stderr, "Warning: %s\n", why);
    } else if (!config_load(&config, CONFIG_PATH, why, sizeof why)) {
        printf("Warning: problem in the settings file: %s\n", why);
    }
    link_command();
    if (!launchctl("bootstrap", "system", PLIST_PATH, false) || !wait_for_daemon()) {
        fprintf(stderr, "The service was installed but did not start. Its log:\n  %s\n", LOG_HINT);
        return 1;
    }
    printf("rndis-tether %s is %s. It runs in the background and starts with the Mac.\n\n",
           VERSION, updating ? "updated" : "installed");
    sleep(2); /* let a phone that is already plugged in connect */
    return cli_status(false) ? 1 : 0;
}

int cli_uninstall(void) {
    if (!need_root("uninstall")) return 1;
    char self[PATH_MAX];
    if (loaded(LABEL)) (void)launchctl("bootout", "system/" LABEL, NULL, true);
    unlink(PLIST_PATH);
    unlink(HELPER_PATH);
    unlink(CONFIG_PATH);
    unlink(OLD_LOCK_PATH);
    unlink_command();
    /* A foreground `run` still holds the lock: its sockets, interfaces and lock stay,
     * or a second daemon could start next to it. */
    int lock = open(LOCK_PATH, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    bool running = lock >= 0 && flock(lock, LOCK_EX | LOCK_NB);
    if (!running) {
        unlink(STATUS_SOCKET);
        unlink(ADMIN_SOCKET);
        runtime_destroy_interfaces(INTERFACES_PATH); /* only left behind if the daemon was killed */
        unlink(LOCK_PATH);
        rmdir(RUNTIME_DIR);
    }
    if (lock >= 0) close(lock);
    puts("rndis-tether is removed: the background service, its settings and its network interfaces.");
    if (running) puts("A foreground `rndis-tether run` is still running; stop it with Ctrl-C.");
    self_path(self, sizeof self);
    if (strstr(self, "/Cellar/")) puts("To remove the program itself as well:  brew uninstall rndis-tether");
    return 0;
}

int cli_restart(void) {
    if (!need_root("restart")) return 1;
    if (!service_installed()) {
        print_not_running();
        return 1;
    }
    if (!launchctl("kickstart", "-k", "system/" LABEL, false) || !wait_for_daemon()) {
        fprintf(stderr, "The service did not start again. Its log:\n  %s\n", LOG_HINT);
        return 1;
    }
    puts("Restarted.");
    return 0;
}

int cli_config(int argc, char **argv) {
    Config config;
    char why[400];
    struct stat st;
    config_defaults(&config);
    bool exists = !stat(CONFIG_PATH, &st);
    bool readable = config_load(&config, CONFIG_PATH, why, sizeof why);
    if (!readable) fprintf(stderr, "Problem: %s\n\n", why);
    if (argc == 0) {
        printf("Settings in %s%s:\n\n", CONFIG_PATH, exists ? "" : " (not created yet, these are the defaults)");
        config_print(&config, stdout);
        printf("\nChange one:  rndis-tether config <name> <value>\n"
               "prefer-phone and verbose apply at once; the others need sudo and reconnect the phone.\n"
               "The file explains every setting.\n");
        return 0;
    }
    if (argc != 2) {
        fputs("usage: rndis-tether config <name> <value>\n", stderr);
        return 2;
    }
    if (!config_set(&config, argv[0], argv[1], why, sizeof why)) {
        fprintf(stderr, "%s\n", why);
        return 2;
    }
    if (config_live(argv[0])) {
        int asked = ask_service(argv[0], argv[1], "only administrators of this Mac can change settings", why,
                                sizeof why);
        if (asked > 0) {
            printf("%s = %s: the service applied it at once and saved it in %s.\n", argv[0], argv[1], CONFIG_PATH);
            return 0;
        }
        if (!asked) {
            fprintf(stderr, "Not changed: %s.\n", why);
            return 1;
        }
    }
    char command[160]; /* validated above: no spaces or quotes to escape */
    snprintf(command, sizeof command, "config %s %s", argv[0], argv[1]);
    if (!need_root(command)) return 1;
    if (!config_save(&config, CONFIG_PATH, why, sizeof why)) {
        fprintf(stderr, "%s\n", why);
        return 1;
    }
    printf("Saved in %s.%s\n", CONFIG_PATH, readable ? "" : " The faulty line was replaced by its default.");
    if (!loaded(LABEL)) return 0;
    if (!launchctl("kickstart", "-k", "system/" LABEL, false) || !wait_for_daemon()) {
        fprintf(stderr, "The service did not start again. Its log:\n  %s\n", LOG_HINT);
        return 1;
    }
    puts("The service was restarted with the new settings.");
    return 0;
}
