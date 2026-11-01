#include "cli.h"
#include "admin.h"
#include "config.h"
#include "log.h"
#include "netif.h"
#include "runtime.h"
#include "session.h"
#include "status.h"
#include "usb.h"

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

#define COMMAND_DIR "/usr/local/bin" /* on PATH by default */
#define COMMAND_LINK COMMAND_DIR "/rndis-tether"
#define REASON_SIZE 400 /* a why text; also the admin reply it is cut from */
#define PAUSE_DENIED_REASON "only administrators of this Mac can disconnect or connect the phone"
#define STATUS_STATE_NOT_RUNNING "not-running" /* the CLI got no daemon reply */
#define LOG_HINT "/usr/bin/log show --last 30m --style compact --predicate 'subsystem == \"" LABEL "\"'"
/* launchd waits this long for the service to exit before it kills it (ExitTimeOut); the
 * limit is longer than SESSION_TEARDOWN_MAX_MS. A bootout or kickstart -k must be
 * given longer, or the next bootstrap can find the old job. */
#define EXIT_TIMEOUT_S 30
#define LAUNCHCTL_EXIT_MARGIN_S 10 /* allow launchctl to finish after launchd kills the job */
#define LAUNCHCTL_TIMEOUT_MS ((EXIT_TIMEOUT_S + LAUNCHCTL_EXIT_MARGIN_S) * 1000)
#define BOOTOUT_WAIT_S (EXIT_TIMEOUT_S + 5) /* launchd has killed the old job by then */
#define POLL_INTERVAL_MS 100u
#define DAEMON_START_WAIT_S 5u /* after bootstrap or kickstart, for the status socket to answer */
#define STATUS_TIMEOUT_S 2
#define ADMIN_TIMEOUT_S 5 /* the service saves the settings file before it answers */
#define HIDE_CURSOR "\033[?25l"
#define SHOW_CURSOR "\033[?25h"
#define CLEAR_SCREEN "\033[H\033[J" /* cursor home, clear to the end */
_Static_assert(EXIT_TIMEOUT_S * 1000u > SESSION_TEARDOWN_MAX_MS, "teardown must fit in ExitTimeOut");

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
    uid_t uid;
    gid_t gid;
    if (connect(fd, (const struct sockaddr *)&address, sizeof address) || getpeereid(fd, &uid, &gid)) {
        int error = errno; /* ask_service tells EACCES (not an administrator) apart */
        close(fd);
        errno = error;
        return -1;
    }
    if (uid != 0) { /* not root's socket */
        close(fd);
        errno = ECONNREFUSED;
        return -1;
    }
    return fd;
}

/* Reads until the peer closes, a read fails or times out, or buf is full; always terminated. */
static size_t read_reply(int fd, char *buf, size_t size) {
    size_t used = 0;
    ssize_t n;
    while (used + 1 < size && (n = read(fd, buf + used, size - 1 - used)) > 0) used += (size_t)n;
    buf[used] = 0;
    return used;
}

/* The running daemon's state as "name=value" lines; text is empty when false is returned. */
static bool status_query(char *text, size_t size) {
    int fd = connect_service(STATUS_SOCKET, STATUS_TIMEOUT_S);
    if (fd < 0) {
        text[0] = 0;
        return false;
    }
    size_t used = read_reply(fd, text, size);
    close(fd);
    return used > 0;
}

typedef enum { SERVICE_APPLIED, SERVICE_REFUSED, SERVICE_ABSENT } ServiceAnswer;

/* SERVICE_APPLIED: applied; SERVICE_REFUSED: why says why (also denied, when the
 * caller is not an administrator); SERVICE_ABSENT: no service answers, so only
 * the file can change. */
static ServiceAnswer ask_service(const char *name, const char *value, const char *denied,
                                  char *why, size_t why_size) {
    int fd = connect_service(ADMIN_SOCKET, ADMIN_TIMEOUT_S);
    if (fd < 0) {
        if (errno != EACCES) return SERVICE_ABSENT;
        strlcpy(why, denied, why_size);
        return SERVICE_REFUSED;
    }
    char request[160], reply[REASON_SIZE];
    int length = snprintf(request, sizeof request, ADMIN_VERB_SET " %s %s\n", name, value);
    reply[0] = 0;
    if (length > 0 && (size_t)length < sizeof request && write(fd, request, (size_t)length) == length)
        (void)read_reply(fd, reply, sizeof reply);
    close(fd);
    if (!strcmp(reply, ADMIN_REPLY_OK)) return SERVICE_APPLIED;
    reply[strcspn(reply, "\n")] = 0;
    const size_t prefix = sizeof ADMIN_REPLY_ERROR - 1;
    strlcpy(why, !strncmp(reply, ADMIN_REPLY_ERROR, prefix) ? reply + prefix : "the service did not answer", why_size);
    return SERVICE_REFUSED;
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
    if (strstr(problem, USB_REASON_BUSY))
        return "Another program is using the phone's USB tethering (HoRNDIS, TetherKit or a second\n"
               "  copy of rndis-tether). Quit it; rndis-tether keeps trying by itself.";
    if (strstr(problem, FETH_SYSCTL_PREFIX))
        return "A macOS setting for virtual network interfaces was changed (see above). Restarting\n"
               "  the Mac restores it.";
    if (strstr(problem, SESSION_REASON_TAKEN))
        return "Another program (a VPN or another tethering tool?) uses that network interface.\n"
               "  Quit it, or let rndis-tether use other names:\n"
               "    sudo rndis-tether config host-interface feth52\n"
               "    sudo rndis-tether config peer-interface feth53";
    if (strstr(problem, USB_REASON_NO_DATA))
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
    if (!strcmp(prefer, config_bool_text(true)))
        printf("Internet: goes through %s, which macOS ranks above the phone (a VPN?)\n", name);
    else
        printf("Internet: goes through %s; the phone takes over without it (prefer-phone = no)\n", name);
}

/* down/up < 0: no speed line (one-shot status). */
static void print_online(const char *text, const char *phone, double down, double up) {
    char since[32], received[32], sent[32], address[32], gateway[32];
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
}

/* What needs the administrator's attention besides the connection. */
static void print_service_notes(const char *text) {
    char settings[CONFIG_PROBLEM_SIZE], version[32];
    if (*field(text, "settings-problem", settings, sizeof settings))
        printf("\nSettings: %s\n  Fix it with: sudo rndis-tether config <name> <value>\n", settings);
    if (strcmp(field(text, "version", version, sizeof version), VERSION))
        printf("\nThe service runs version %s, this program is %s. Update the service:\n"
               "  sudo rndis-tether install\n", version, VERSION);
}

/* down/up < 0: no speed line (one-shot status). */
static void print_status(const char *text, double down, double up) {
    char state[32], phone[USB_DESCRIPTION_SIZE], problem[256];
    field(text, "state", state, sizeof state);
    field(text, "phone", phone, sizeof phone);
    field(text, "problem", problem, sizeof problem);

    if (!strcmp(state, STATUS_STATE_PAUSED)) {
        if (phone[0]) printf("Phone:    %s\n", phone);
        printf("Status:   disconnected (run: rndis-tether connect)\n");
    } else if (!strcmp(state, STATUS_STATE_NO_PHONE)) {
        printf("Status:   waiting for a phone\n\n%s", TETHERING_HELP);
    } else if (!strcmp(state, STATUS_STATE_UNSUPPORTED)) {
        printf("Phone:    %s\nStatus:   this USB device does not work as USB tethering\n\n"
               "  It looked like a tethering phone but did not answer like one. Unplug it and plug it\n"
               "  in again after turning USB tethering on.\n", phone);
    } else if (!strcmp(state, STATUS_STATE_SLEEPING)) {
        printf("Status:   paused while the Mac sleeps\n");
    } else if (!strcmp(state, STATUS_STATE_RETRYING)) {
        printf("Phone:    %s\nStatus:   cannot connect: %s\n\n  %s\n", phone, problem, advice(problem));
    } else if (!strcmp(state, STATUS_STATE_CONNECTING)) {
        printf("Phone:    %s\nStatus:   connecting, waiting for an address from the phone...\n", phone);
    } else if (!strcmp(state, STATUS_STATE_ONLINE)) {
        print_online(text, phone, down, up);
    } else {
        printf("Status:   %s\n", state);
    }
    print_service_notes(text);
}

static bool file_exists(const char *path) {
    struct stat st;
    return !stat(path, &st);
}

static bool service_installed(void) {
    return file_exists(PLIST_PATH);
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
    char text[STATUS_TEXT_SIZE];
    if (!status_query(text, sizeof text)) {
        if (raw) puts("state=" STATUS_STATE_NOT_RUNNING);
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
    if (terminal) fputs(HIDE_CURSOR, stdout);
    unsigned long long last_rx = 0, last_tx = 0;
    uint64_t last_ns = 0;
    while (!interrupted) {
        char text[STATUS_TEXT_SIZE], time_text[16];
        bool running = status_query(text, sizeof text);
        uint64_t now_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        double down = 0, up = 0;
        unsigned long long rx = number(text, "rx-bytes");
        unsigned long long tx = number(text, "tx-bytes");
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
        strftime(time_text, sizeof time_text, "%H:%M:%S", &local);
        if (terminal) fputs(CLEAR_SCREEN, stdout);
        printf("rndis-tether monitor    %s    Ctrl-C to quit\n\n", time_text);
        if (running) print_status(text, down, up);
        else print_not_running();
        fflush(stdout);
        struct timespec second = {1, 0};
        nanosleep(&second, NULL); /* a signal ends it early */
    }
    if (terminal) fputs(SHOW_CURSOR, stdout);
    putchar('\n');
    return 0;
}

int cli_set_paused(bool paused) {
    char text[STATUS_TEXT_SIZE], paused_field[8], version[32], why[REASON_SIZE];
    if (!status_query(text, sizeof text)) {
        print_not_running();
        return 1;
    }
    /* 1.0.x has no paused field and would answer with advice about restarting. */
    if (!*field(text, "paused", paused_field, sizeof paused_field)) {
        fprintf(stderr, "The service runs version %s, which cannot %s. Update the service:\n"
                "  sudo rndis-tether install\n", field(text, "version", version, sizeof version),
                paused ? "disconnect" : "connect");
        return 1;
    }
    ServiceAnswer answer = ask_service(ADMIN_SETTING_PAUSED, config_bool_text(paused), PAUSE_DENIED_REASON,
                                       why, sizeof why);
    if (answer == SERVICE_ABSENT) fputs("The service did not answer. Its log:\n  " LOG_HINT "\n", stderr);
    else if (answer == SERVICE_REFUSED) fprintf(stderr, "Not changed: %s.\n", why);
    else if (paused) puts("Disconnected; the phone can stay plugged in. Use it again with:  rndis-tether connect");
    else puts("Connected again; rndis-tether status shows the details.");
    return answer == SERVICE_APPLIED ? 0 : 1;
}

/* ---------------------------------------------------------------- service control */

/* True when running as root; otherwise tells how to run command with sudo. */
static bool require_root(const char *command) {
    if (!geteuid()) return true;
    fprintf(stderr, "This needs administrator rights. Run:\n  sudo rndis-tether %s\n", command);
    return false;
}

static bool launchctl(const char *verb, const char *arg1, const char *arg2, bool quiet) {
    const char *argv[] = {"/bin/launchctl", verb, arg1, arg2, NULL};
    return quiet ? run_command_quiet(argv, LAUNCHCTL_TIMEOUT_MS) : run_command(argv, LAUNCHCTL_TIMEOUT_MS);
}

static bool service_loaded(void) {
    return launchctl("print", SERVICE_TARGET, NULL, true);
}

static bool wait_for_daemon(void) {
    for (unsigned i = 0; i < DAEMON_START_WAIT_S * 1000 / POLL_INTERVAL_MS; ++i) {
        char text[64];
        if (status_query(text, sizeof text)) return true;
        usleep(POLL_INTERVAL_MS * 1000);
    }
    return false;
}

/* kickstart -k stops the running daemon and starts it again. */
static bool restart_service(void) {
    if (launchctl("kickstart", "-k", SERVICE_TARGET, false) && wait_for_daemon()) return true;
    fprintf(stderr, "The service did not start again. Its log:\n  %s\n", LOG_HINT);
    return false;
}

/* A daemon holds the lock: the service, or a foreground `run`. When none does, the
 * lock is ours until *fd (-1 when there is no lock file) is closed. */
static bool daemon_holds_lock(int *fd) {
    *fd = open(LOCK_PATH, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    return *fd >= 0 && flock(*fd, LOCK_EX | LOCK_NB);
}

/* A bootout can return before the old daemon has finished its teardown ("Operation now
 * in progress"); launchd kills it after EXIT_TIMEOUT_S. True once nobody holds the lock. */
static bool lock_released(unsigned seconds) {
    for (unsigned waited = 0;; ++waited) {
        int lock;
        bool held = daemon_holds_lock(&lock);
        if (lock >= 0) close(lock);
        if (!held) return true;
        if (waited >= seconds * 1000 / POLL_INTERVAL_MS) return false;
        usleep(POLL_INTERVAL_MS * 1000);
    }
}

/* A bootout can return while the old daemon still tears down ("Operation now in progress"). */
static bool stop_service(bool loaded) {
    if (loaded) (void)launchctl("bootout", SERVICE_TARGET, NULL, true);
    return lock_released(loaded ? BOOTOUT_WAIT_S : 0);
}

/* This program's own file with symlinks resolved; false when it cannot be found. */
static bool self_path(char out[static PATH_MAX]) {
    char path[PATH_MAX];
    uint32_t length = sizeof path;
    return !_NSGetExecutablePath(path, &length) && realpath(path, out);
}

/* Gives a written temporary file to root with mode and renames it over path. */
static bool put_in_place(const char *temporary, const char *path, mode_t mode) {
    return !chown(temporary, 0, 0) && !chmod(temporary, mode) && !rename(temporary, path);
}

static bool install_binary(const char *self, char *why, size_t why_size) {
    if (!strcmp(self, HELPER_PATH)) return true; /* reinstalling from the installed copy */
    const char *temporary = HELPER_PATH ".new";
    (void)mkdir(HELPER_DIR, 0755);
    unlink(temporary);
    /* Data only: no quarantine or other extended attributes travel with it. */
    if (copyfile(self, temporary, NULL, COPYFILE_DATA) || !put_in_place(temporary, HELPER_PATH, 0755)) {
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
        "    <key>ExitTimeOut</key>\n"
        "    <integer>" NUMBER_TEXT(EXIT_TIMEOUT_S) "</integer>\n"
        "</dict>\n"
        "</plist>\n";
    const char *temporary = PLIST_PATH ".new";
    FILE *f = fopen(temporary, "w");
    bool ok = f && fputs(plist, f) >= 0;
    if (f && fclose(f)) ok = false;
    if (!ok || !put_in_place(temporary, PLIST_PATH, 0644)) {
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
    (void)mkdir(COMMAND_DIR, 0755);
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
    if (!require_root("install")) return 1;
    char self[PATH_MAX], why[REASON_SIZE];
    if (!self_path(self)) {
        fputs("Installation failed: cannot find this program's own file.\n", stderr);
        return 1;
    }
    bool updating = service_loaded();
    /* The new service would only find the lock taken, and the other daemon would answer for it. */
    if (!stop_service(updating)) {
        fputs("rndis-tether is still running outside the service (`rndis-tether run` in a terminal?).\n"
              "  Stop it with Ctrl-C, then install again.\n", stderr);
        return 1;
    }
    unlink(OLD_LOCK_PATH);
    if (!install_binary(self, why, sizeof why) || !write_plist(why, sizeof why)) {
        fprintf(stderr, "Installation failed: %s\n", why);
        return 1;
    }
    Config config;
    config_defaults(&config);
    if (!file_exists(CONFIG_PATH)) {
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
    return cli_status(false);
}

int cli_uninstall(void) {
    if (!require_root("uninstall")) return 1;
    char self[PATH_MAX];
    (void)stop_service(service_loaded());
    unlink(PLIST_PATH);
    unlink(HELPER_PATH);
    unlink(CONFIG_PATH);
    unlink(OLD_LOCK_PATH);
    unlink_command();
    /* A foreground `run` still holds the lock: its sockets, interfaces and lock stay,
     * or a second daemon could start next to it. */
    int lock;
    bool running = daemon_holds_lock(&lock);
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
    if (self_path(self) && strstr(self, "/Cellar/"))
        puts("To remove the program itself as well:  brew uninstall rndis-tether");
    return 0;
}

int cli_restart(void) {
    if (!require_root("restart")) return 1;
    if (!service_installed()) {
        print_not_running();
        return 1;
    }
    if (!restart_service()) return 1;
    puts("Restarted.");
    return 0;
}

int cli_config(int argc, char **argv) {
    Config config;
    char why[REASON_SIZE];
    config_defaults(&config);
    bool exists = file_exists(CONFIG_PATH);
    bool loaded_cleanly = config_load(&config, CONFIG_PATH, why, sizeof why);
    if (!loaded_cleanly) fprintf(stderr, "Problem: %s\n\n", why);
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
        ServiceAnswer answer = ask_service(argv[0], argv[1], ADMIN_DENIED_REASON, why, sizeof why);
        if (answer == SERVICE_APPLIED) {
            printf("%s = %s: the service applied it at once and saved it in %s.\n", argv[0], argv[1], CONFIG_PATH);
            return 0;
        }
        if (answer == SERVICE_REFUSED) {
            fprintf(stderr, "Not changed: %s.\n", why);
            return 1;
        }
    }
    char command[160]; /* validated above: no spaces or quotes to escape */
    snprintf(command, sizeof command, "config %s %s", argv[0], argv[1]);
    if (!require_root(command)) return 1;
    if (!config_save(&config, CONFIG_PATH, why, sizeof why)) {
        fprintf(stderr, "%s\n", why);
        return 1;
    }
    printf("Saved in %s.%s\n", CONFIG_PATH, loaded_cleanly ? "" : " The faulty line was replaced by its default.");
    if (!service_loaded()) return 0;
    if (!restart_service()) return 1;
    puts("The service was restarted with the new settings.");
    return 0;
}
