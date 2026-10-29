#include "daemon.h"
#include "admin.h"
#include "clock.h"
#include "log.h"
#include "netif.h"
#include "runtime.h"
#include "session.h"
#include "status.h"
#include "usb.h"

#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define REJECTED_MAX 16u      /* non-RNDIS CDC functions remembered by registry ID */
#define CDC_INIT_ATTEMPTS 3u  /* a 02/02/ff function that never answers INITIALIZE is not RNDIS */
#define REPEAT_LOG_EVERY 20u  /* an identical retry failure: about every 10 minutes */

static struct {
    Config cfg;
    char settings_problem[300];
    dispatch_source_t signals[3];

    IONotificationPortRef port;
    io_iterator_t matches[2];
    io_service_t device;
    io_object_t device_interest;
    char device_name[160];
    uint64_t device_id;
    bool device_cdc, device_rejected;
    unsigned init_failures;
    uint64_t rejected[REJECTED_MAX]; /* ring; a replugged device gets a new registry ID */
    unsigned rejected_next;

    CFRunLoopTimerRef retry_timer;
    unsigned attempts;
    char last_failure[200]; /* the retry loop logs a repeating failure only now and then */
    unsigned failure_repeats;

    io_connect_t power_root;
    IONotificationPortRef power_port;
    io_object_t power_notifier;
    bool sleeping, shutting_down;
    bool paused; /* runtime only: never saved, so every start begins connected */
} g;

static void device_removed(void);
static void device_matched(void *refcon, io_iterator_t iterator);
static void forget_device(void);
static void rescan_devices(void);

/* ------------------------------------------------------------ connecting */

/* A phone that keeps failing the same way (interface held by another program, wrong
 * feth sysctl) is retried every 30 s for as long as it stays plugged in. Log the
 * failure when it changes and then only every REPEAT_LOG_EVERY-th time. */
static bool failure_worth_logging(const char *reason) {
    if (strcmp(reason, g.last_failure)) {
        strlcpy(g.last_failure, reason, sizeof g.last_failure);
        g.failure_repeats = 0;
        return true;
    }
    return ++g.failure_repeats % REPEAT_LOG_EVERY == 0;
}

static bool may_connect(void) {
    return g.device && !g.device_rejected && !g.sleeping && !g.paused && !g.shutting_down;
}

static void schedule_retry(bool quiet) {
    double delay = g.attempts < 5 ? (double)(1u << g.attempts) : 30.0;
    ++g.attempts;
    if (!may_connect()) return;
    if (!quiet) {
        if (g.failure_repeats) logmsg("next attempt in %.0f s (same failure %u times in a row)", delay,
                                      g.failure_repeats + 1);
        else logmsg("next attempt in %.0f s", delay);
    }
    timer_set(g.retry_timer, delay);
}

static bool device_gone(void) {
    return g.device && !usb_attached(g.device);
}

static void disconnect(const char *reason, bool retry) {
    if (!session_active()) return;
    uint64_t lived = session_age_ms();
    bool quiet = retry && !failure_worth_logging(reason);
    session_stop(reason, quiet);
    if (retry && may_connect()) {
        if (lived > 60000) g.attempts = 0;
        schedule_retry(quiet);
    }
}

/* The session broke. On unplug a transfer usually fails before the removal notification arrives. */
static void session_broke(void) {
    if (device_gone()) device_removed();
    else disconnect(session_failure(), true);
}

static void reject_device(const char *why) {
    g.device_rejected = true;
    g.rejected[g.rejected_next++ % REJECTED_MAX] = g.device_id;
    logmsg("%s: %s; ignoring it until it is plugged in again", g.device_name, why);
}

static void connect_phone(void) {
    if (session_active() || !may_connect()) return;
    bool init_failed = false;
    const char *e = session_start(g.device, g.device_name, &g.cfg, session_broke, &init_failed);
    if (!e) {
        g.last_failure[0] = 0;
        g.failure_repeats = g.init_failures = 0;
        return;
    }
    /* A CDC-ACM lookalike must not be held open and probed every 30 seconds. */
    if (init_failed && g.device_cdc && ++g.init_failures >= CDC_INIT_ATTEMPTS) {
        reject_device("this CDC function does not answer as RNDIS");
        return;
    }
    bool quiet = !failure_worth_logging(e);
    if (!quiet) logmsg("cannot connect to %s: %s", g.device_name, e);
    schedule_retry(quiet);
}

static void retry_fired(CFRunLoopTimerRef timer, void *info) {
    (void)timer;
    (void)info;
    if (device_gone()) {
        logmsg("%s is no longer attached; looking for it again", g.device_name);
        forget_device();
        rescan_devices();
        return;
    }
    connect_phone();
}

/* --------------------------------------------------------------- devices */

static void forget_device(void) {
    timer_disarm(g.retry_timer);
    if (g.device_interest) { IOObjectRelease(g.device_interest); g.device_interest = IO_OBJECT_NULL; }
    if (g.device) { IOObjectRelease(g.device); g.device = IO_OBJECT_NULL; }
    g.device_cdc = g.device_rejected = false;
}

static void rescan_devices(void) {
    for (unsigned kind = 0; kind < USB_MATCHING_KINDS; ++kind) {
        io_iterator_t existing = IO_OBJECT_NULL;
        CFMutableDictionaryRef match = usb_create_matching(kind);
        if (match && IOServiceGetMatchingServices(kIOMainPortDefault, match, &existing) == KERN_SUCCESS) {
            device_matched(NULL, existing);
            IOObjectRelease(existing);
        }
    }
}

static void device_removed(void) {
    logmsg("phone unplugged or USB tethering turned off");
    session_unplugged();
    disconnect("device removed", false);
    forget_device();
    rescan_devices(); /* pick up a device that was ignored while this one was in use */
}

static void device_message(void *refcon, io_service_t service, natural_t type, void *argument) {
    (void)refcon;
    (void)argument;
    if (type == kIOMessageServiceIsTerminated && g.device && IOObjectIsEqualTo(service, g.device)) device_removed();
}

static bool rejected_device(uint64_t id) {
    for (unsigned i = 0; i < REJECTED_MAX; ++i) if (id && g.rejected[i] == id) return true;
    return false;
}

static void device_matched(void *refcon, io_iterator_t iterator) {
    (void)refcon;
    io_service_t service;
    while ((service = IOIteratorNext(iterator))) {
        bool cdc = false;
        uint64_t id = 0;
        if (IORegistryEntryGetRegistryEntryID(service, &id) != KERN_SUCCESS || rejected_device(id) ||
            !usb_rndis_candidate(service, &cdc)) { IOObjectRelease(service); continue; }
        if (g.device && IOObjectIsEqualTo(service, g.device)) { IOObjectRelease(service); continue; }
        if (g.device && session_active() && !device_gone()) {
            char name[160];
            usb_describe(service, name, sizeof name);
            logmsg("ignoring additional RNDIS device %s (one phone at a time)", name);
            IOObjectRelease(service);
            continue;
        }
        if (g.device) { /* A re-enumerated phone leaves a stale entry: switch to the new one. */
            logmsg("switching to the newly attached RNDIS function");
            if (device_gone()) session_unplugged();
            disconnect("device re-enumerated", false);
            forget_device();
        }
        g.device = service;
        g.device_id = id;
        g.device_cdc = cdc;
        g.device_rejected = false;
        usb_describe(service, g.device_name, sizeof g.device_name);
        kern_return_t interest = IOServiceAddInterestNotification(g.port, service, kIOGeneralInterest,
                                                                  device_message, NULL, &g.device_interest);
        if (interest != KERN_SUCCESS) {
            g.device_interest = IO_OBJECT_NULL;
            logmsg("warning: no removal notifications for this device (0x%08x)", interest);
        }
        logmsg("USB tethering detected: %s", g.device_name);
        g.attempts = g.failure_repeats = g.init_failures = 0;
        g.last_failure[0] = 0;
        if (may_connect()) timer_set(g.retry_timer, 1.0); /* let the data interface and the phone settle */
    }
}

static bool watch_devices(void) {
    g.port = IONotificationPortCreate(kIOMainPortDefault);
    if (!g.port) return false;
    CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(g.port), kCFRunLoopDefaultMode);
    for (unsigned kind = 0; kind < USB_MATCHING_KINDS; ++kind) {
        CFMutableDictionaryRef match = usb_create_matching(kind);
        if (!match || IOServiceAddMatchingNotification(g.port, kIOFirstMatchNotification, match, device_matched,
                                                       NULL, &g.matches[kind]) != KERN_SUCCESS) return false;
        device_matched(NULL, g.matches[kind]); /* also arms notifications for devices already present */
    }
    return true;
}

/* ------------------------------------------------------- power and signals */

static void power_message(void *refcon, io_service_t service, natural_t type, void *argument) {
    (void)refcon;
    (void)service;
    switch (type) {
    case kIOMessageCanSystemSleep:
        IOAllowPowerChange(g.power_root, (long)argument);
        break;
    case kIOMessageSystemWillSleep:
        g.sleeping = true;
        timer_disarm(g.retry_timer);
        disconnect("system is going to sleep", false);
        IOAllowPowerChange(g.power_root, (long)argument);
        break;
    case kIOMessageSystemHasPoweredOn:
        g.sleeping = false;
        if (g.device && !session_active()) {
            g.attempts = 0;
            if (may_connect()) timer_set(g.retry_timer, 2.0);
        }
        break;
    default:
        break;
    }
}

static void watch_power(void) {
    g.power_root = IORegisterForSystemPower(NULL, &g.power_port, power_message, &g.power_notifier);
    if (g.power_root)
        CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(g.power_port), kCFRunLoopDefaultMode);
    else
        logmsg("warning: no sleep/wake notifications");
}

static void on_signal(void *context) {
    logmsg("signal %d: shutting down", (int)(intptr_t)context);
    g.shutting_down = true;
    disconnect("service stopped", false);
    unlink(STATUS_SOCKET);
    unlink(ADMIN_SOCKET);
    CFRunLoopStop(CFRunLoopGetMain());
}

static void watch_signal(unsigned slot, int signal_number) {
    signal(signal_number, SIG_IGN);
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t)signal_number, 0,
                                                      dispatch_get_main_queue());
    dispatch_set_context(source, (void *)(intptr_t)signal_number);
    dispatch_source_set_event_handler_f(source, on_signal);
    dispatch_resume(source);
    g.signals[slot] = source; /* lives as long as the daemon */
}

/* ------------------------------------------------------------------ status */

static size_t status_report(char *buffer, size_t size) {
    SessionStatus session;
    bool active = session_status(&session);
    /* While paused no retry notices a phone whose removal notification was lost. */
    bool phone = g.device && !(g.paused && device_gone());
    StatusFacts facts = {
        .phone = phone ? g.device_name : NULL,
        .rejected = g.device_rejected,
        .sleeping = g.sleeping,
        .paused = g.paused,
        .last_failure = g.last_failure,
        .session = active ? &session : NULL,
    };
    StatusReport report = {
        .prefer_phone = g.cfg.prefer_phone,
        .settings_problem = g.settings_problem[0] ? g.settings_problem : NULL,
    };
    status_choose(&facts, &report);
    return status_format(&report, buffer, size);
}

/* --------------------------------------------------------------- settings */

static const char *user_name(uid_t uid) {
    const struct passwd *user = getpwuid(uid);
    return user ? user->pw_name : "an administrator";
}

/* After the admin reply: a teardown can take seconds, longer than a client waits. */
static void pause_now(void *context) {
    (void)context;
    if (g.paused) disconnect("paused", false);
}

/* `set paused yes|no`: not a setting, never saved. Pausing ends the session as sleep
 * does (HALT, interfaces removed) and keeps new ones from starting; resuming connects
 * a phone that is plugged in, as when it was plugged in. */
static bool set_paused(uid_t uid, const char *value, char *why, size_t why_size) {
    bool paused;
    if (!admin_yes_no("paused", value, &paused, why, why_size)) return false;
    if (paused == g.paused) return true;
    g.paused = paused;
    logmsg("%s by %s", paused ? "paused" : "resumed", user_name(uid));
    if (paused) {
        timer_disarm(g.retry_timer);
        dispatch_async_f(dispatch_get_main_queue(), NULL, pause_now);
    } else if (g.device && !session_active()) {
        g.attempts = g.failure_repeats = g.init_failures = 0;
        g.last_failure[0] = 0;
        if (may_connect()) timer_set(g.retry_timer, 1.0);
    }
    return true;
}

/* From the admin socket: a setting the service applies at once, also saved in the file. */
static bool change_setting(uid_t uid, const char *name, const char *value, char *why, size_t why_size) {
    if (!strcmp(name, "paused")) return set_paused(uid, value, why, why_size);
    if (!config_live(name)) {
        snprintf(why, why_size, "%s applies only when the service starts again: sudo rndis-tether config %s %s",
                 name, name, value);
        return false;
    }
    Config file, running = g.cfg; /* options of a foreground `run` stay as they are */
    char problem[300];
    config_defaults(&file);
    (void)config_load(&file, CONFIG_PATH, problem, sizeof problem); /* a bad line is saved as its default */
    if (!config_set(&file, name, value, why, why_size) || !config_set(&running, name, value, why, why_size) ||
        !config_save(&file, CONFIG_PATH, why, why_size)) return false;
    g.cfg = running;
    g.settings_problem[0] = 0;
    log_verbose = g.cfg.verbose;
    logmsg("settings: %s = %s, changed by %s", name, value, user_name(uid));
    session_network_changed(); /* prefer-phone: rank the phone first, or leave the order to macOS */
    return true;
}

static void serve_admin(void) {
    const struct group *admin = getgrnam("admin");
    if (!admin || !admin_serve(RUNTIME_DIR, ADMIN_SOCKET, admin->gr_gid, change_setting))
        logmsg("warning: settings can be changed only with sudo and a restart: %s",
               admin ? strerror(errno) : "no admin group");
}

/* -------------------------------------------------------------------- run */

/* Held for the daemon's lifetime; the kernel releases it however the process ends.
 * Only root can open it: a user holding it would keep the service from starting. */
static bool take_lock(void) {
    if (!runtime_dir(RUNTIME_DIR)) return false;
    int fd = open(LOCK_PATH, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    return fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB);
}

int daemon_run(const Config *cfg, const char *settings_problem) {
    g.cfg = *cfg;
    strlcpy(g.settings_problem, settings_problem, sizeof g.settings_problem);
    log_verbose = cfg->verbose;
    if (geteuid() != 0) {
        fputs("rndis-tether run needs root. Normally the background service runs it:\n"
              "  sudo rndis-tether install\n", stderr);
        return 1;
    }
    if (!take_lock()) {
        if (errno == EWOULDBLOCK)
            fputs("rndis-tether is already running (the installed service?). To run it here instead:\n"
                  "  sudo launchctl bootout system/" LABEL "\n"
                  "and afterwards start the service again with:  sudo rndis-tether install\n", stderr);
        else if (errno == EPERM)
            fputs(RUNTIME_DIR " must be a directory only root can use (mode 0700); remove it and try again\n",
                  stderr);
        else perror(LOCK_PATH);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    logmsg("rndis-tether " VERSION " started (%s <-> %s%s%s)", g.cfg.host, g.cfg.peer,
           g.cfg.prefer_phone ? ", prefer phone for internet" : "", g.cfg.ipv6 ? ", IPv6" : "");
    if (settings_problem[0]) logmsg("settings: %s; that line is ignored", settings_problem);

    /* A previous instance may have been killed without cleanup; only its own interfaces go. */
    runtime_destroy_interfaces(INTERFACES_PATH);

    g.retry_timer = timer_new(retry_fired, NULL, 0, 0.5);
    if (!netstate_watch(session_network_changed)) {
        logmsg("cannot watch network state (SystemConfiguration)");
        return 1;
    }
    watch_signal(0, SIGTERM);
    watch_signal(1, SIGINT);
    watch_signal(2, SIGHUP);
    if (!status_serve(RUNTIME_DIR, STATUS_SOCKET, status_report))
        logmsg("warning: no answers for `rndis-tether status`: %s", strerror(errno));
    serve_admin();
    watch_power();
    if (!watch_devices()) {
        logmsg("cannot watch USB devices");
        return 1;
    }
    if (!g.device) logmsg("waiting for a phone with USB tethering turned on");

    CFRunLoopRun();
    logmsg("stopped");
    return 0;
}
