/* rndis-tether: Android USB tethering (RNDIS) as a normal Ethernet interface on macOS.
 *
 * One program for everything: `run` is the background service (daemon.c), the other
 * commands install it, show its state and change its settings (cli.c).
 */
#include "cli.h"
#include "config.h"
#include "daemon.h"
#include "usb.h"

#include <stdio.h>
#include <string.h>

static int list_devices(void) {
    unsigned count = 0;
    for (UsbMatching kind = 0; kind < USB_MATCHING_KINDS; ++kind) {
        io_iterator_t it = IO_OBJECT_NULL;
        CFMutableDictionaryRef match = usb_create_matching(kind);
        if (!match || IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) != KERN_SUCCESS) return 1;
        io_service_t service;
        while ((service = IOIteratorNext(it))) {
            bool cdc = false;
            if (usb_rndis_candidate(service, &cdc)) {
                char name[USB_DESCRIPTION_SIZE];
                usb_describe(service, name, sizeof name);
                printf("RNDIS %s: %s\n", cdc ? "candidate" : "function", name);
                ++count;
            }
            IOObjectRelease(service);
        }
        IOObjectRelease(it);
    }
    if (!count) puts("No phone with USB tethering found. Connect the phone and turn on USB tethering.");
    return 0;
}

static int usage(FILE *out, int code) {
    fputs("rndis-tether " VERSION ": internet from an Android phone over a USB cable (USB tethering)\n"
          "\n"
          "  rndis-tether status                 is it working, and what to do if not\n"
          "  rndis-tether monitor                live status and speed (Ctrl-C to quit)\n"
          "  rndis-tether disconnect             stop using the phone; it can stay plugged in\n"
          "  rndis-tether connect                use the phone again\n"
          "  sudo rndis-tether install           install or update the background service\n"
          "  sudo rndis-tether uninstall         remove the service, its settings and interfaces\n"
          "  rndis-tether config                 show the settings\n"
          "  rndis-tether config NAME VALUE      change a setting, e.g. config prefer-phone no\n"
          "                                      (sudo for ipv6, tx-batch and the interface names)\n"
          "  sudo rndis-tether restart           restart the service (after editing " CONFIG_PATH ")\n"
          "  rndis-tether list                   USB tethering devices connected right now\n"
          "  rndis-tether version\n"
          "\n"
          "Troubleshooting, with the service stopped (sudo launchctl bootout " SERVICE_TARGET "):\n"
          "  sudo rndis-tether run [--verbose] [--no-prefer] [--ipv6] [--tx-batch N] [--host fethN] [--peer fethM]\n",
          out);
    return code;
}

/* The settings file, overridden by the options of `run`. */
static int run(int argc, char **argv) {
    Config cfg;
    char settings_problem[CONFIG_PROBLEM_SIZE] = "", why[CONFIG_PROBLEM_SIZE];
    config_defaults(&cfg);
    (void)config_load(&cfg, CONFIG_PATH, settings_problem, sizeof settings_problem);
    for (int i = 0; i < argc; ++i) {
        const char *a = argv[i], *name = NULL, *value = "yes";
        if (!strcmp(a, "--verbose")) name = SETTING_VERBOSE;
        else if (!strcmp(a, "--ipv6")) name = SETTING_IPV6;
        else if (!strcmp(a, "--no-prefer")) { name = SETTING_PREFER_PHONE; value = "no"; }
        else if (i + 1 < argc && !strcmp(a, "--tx-batch")) { name = SETTING_TX_BATCH; value = argv[++i]; }
        else if (i + 1 < argc && !strcmp(a, "--host")) { name = SETTING_HOST_INTERFACE; value = argv[++i]; }
        else if (i + 1 < argc && !strcmp(a, "--peer")) { name = SETTING_PEER_INTERFACE; value = argv[++i]; }
        else return usage(stderr, 2);
        if (!config_set(&cfg, name, value, why, sizeof why)) {
            fprintf(stderr, "%s\n", why);
            return 2;
        }
    }
    if (!config_check(&cfg, why, sizeof why)) {
        fprintf(stderr, "%s\n", why);
        return 2;
    }
    return daemon_run(&cfg, settings_problem);
}

int main(int argc, char **argv) {
    const char *command = argc > 1 ? argv[1] : "help";
    if (!strcmp(command, "run")) return run(argc - 2, argv + 2);
    if (!strcmp(command, "config")) return cli_config(argc - 2, argv + 2);
    if (!strcmp(command, "status") && argc == 3 && !strcmp(argv[2], "--raw")) return cli_status(true);
    if (argc > 2) return usage(stderr, 2);
    if (!strcmp(command, "status")) return cli_status(false);
    if (!strcmp(command, "monitor")) return cli_monitor();
    if (!strcmp(command, "disconnect")) return cli_set_paused(true);
    if (!strcmp(command, "connect")) return cli_set_paused(false);
    if (!strcmp(command, "install")) return cli_install();
    if (!strcmp(command, "uninstall")) return cli_uninstall();
    if (!strcmp(command, "restart")) return cli_restart();
    if (!strcmp(command, "list") || !strcmp(command, "--list")) return list_devices();
    if (!strcmp(command, "version") || !strcmp(command, "--version")) {
        puts("rndis-tether " VERSION);
        return 0;
    }
    if (!strcmp(command, "help") || !strcmp(command, "--help") || !strcmp(command, "-h")) return usage(stdout, 0);
    return usage(stderr, 2);
}
