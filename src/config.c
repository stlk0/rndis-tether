#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void config_defaults(Config *c) {
    *c = (Config){.prefer_phone = true};
    strlcpy(c->host, "feth50", sizeof c->host);
    strlcpy(c->peer, "feth51", sizeof c->peer);
}

static bool parse_bool(const char *value, bool *out) {
    static const char *const yes[] = {"yes", "true", "on", "1"}, *const no[] = {"no", "false", "off", "0"};
    for (size_t i = 0; i < sizeof yes / sizeof *yes; ++i) {
        if (!strcasecmp(value, yes[i])) { *out = true; return true; }
        if (!strcasecmp(value, no[i])) { *out = false; return true; }
    }
    return false;
}

bool config_interface_valid(const char *name) {
    size_t n = strlen(name);
    if (n < 5 || n >= IFNAMSIZ || strncmp(name, "feth", 4)) return false;
    for (size_t i = 4; i < n; ++i) if (!isdigit((unsigned char)name[i])) return false;
    return true;
}

static bool set_bool(bool *flag, const char *name, const char *value, char *why, size_t why_size) {
    if (parse_bool(value, flag)) return true;
    snprintf(why, why_size, "%s must be yes or no, not \"%s\"", name, value);
    return false;
}

static bool set_interface(char *interface, const char *name, const char *value, char *why, size_t why_size) {
    if (config_interface_valid(value)) {
        strlcpy(interface, value, IFNAMSIZ);
        return true;
    }
    snprintf(why, why_size, "%s must be fethN (for example feth50), not \"%s\"", name, value);
    return false;
}

bool config_set(Config *c, const char *name, const char *value, char *why, size_t why_size) {
    if (!strcmp(name, "prefer-phone")) return set_bool(&c->prefer_phone, name, value, why, why_size);
    if (!strcmp(name, "ipv6")) return set_bool(&c->ipv6, name, value, why, why_size);
    if (!strcmp(name, "verbose")) return set_bool(&c->verbose, name, value, why, why_size);
    if (!strcmp(name, "host-interface")) return set_interface(c->host, name, value, why, why_size);
    if (!strcmp(name, "peer-interface")) return set_interface(c->peer, name, value, why, why_size);
    if (!strcmp(name, "tx-batch")) {
        char *end = NULL;
        long n = strtol(value, &end, 10);
        if (!strcasecmp(value, "auto")) c->tx_batch = 0;
        else if (*value && !*end && n >= 1 && n <= 32) c->tx_batch = (unsigned)n;
        else {
            snprintf(why, why_size, "tx-batch must be auto or a number from 1 to 32, not \"%s\"", value);
            return false;
        }
        return true;
    }
    snprintf(why, why_size, "unknown setting \"%s\" (known: prefer-phone, ipv6, tx-batch, verbose, "
             "host-interface, peer-interface)", name);
    return false;
}

bool config_live(const char *name) {
    return !strcmp(name, "prefer-phone") || !strcmp(name, "verbose");
}

bool config_check(const Config *c, char *why, size_t why_size) {
    if (strcmp(c->host, c->peer)) return true;
    snprintf(why, why_size, "host-interface and peer-interface must differ (both are %s)", c->host);
    return false;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) ++s;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = 0;
    return s;
}

/* One line without its newline; false and problem when it is not a setting. */
static bool parse_line(Config *c, char *line, char *problem, size_t problem_size) {
    char *hash = strchr(line, '#');
    if (hash) *hash = 0;
    char *text = trim(line), *equals = strchr(text, '=');
    if (!*text) return true;
    if (!equals) {
        strlcpy(problem, "expected \"name = value\"", problem_size);
        return false;
    }
    *equals = 0;
    return config_set(c, trim(text), trim(equals + 1), problem, problem_size);
}

bool config_load(Config *c, const char *path, char *why, size_t why_size) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return true;
        snprintf(why, why_size, "cannot read %s: %s", path, strerror(errno));
        return false;
    }
    /* One bad line must not cost the others: `config` saves what was read. */
    char line[512], problem[200];
    unsigned number = 0;
    bool ok = true;
    bool end = false;
    while (!end && fgets(line, sizeof line, f)) {
        ++number;
        size_t length = strlen(line);
        bool fits = true;
        if (length == sizeof line - 1 && line[length - 1] != '\n') {
            int next = getc(f);
            fits = next == '\n' || next == EOF;
            /* The rest of an overlong line is not a line of its own (a long comment). */
            while (next != '\n' && next != EOF) next = getc(f);
            end = next == EOF;
        }
        if (!fits) strlcpy(problem, "line is too long", sizeof problem);
        else if (parse_line(c, line, problem, sizeof problem)) continue;
        if (ok) snprintf(why, why_size, "%s line %u: %s", path, number, problem);
        ok = false;
    }
    if (ferror(f) && ok) {
        snprintf(why, why_size, "cannot read %s", path);
        ok = false;
    }
    fclose(f);
    char clash[200];
    if (!config_check(c, clash, sizeof clash)) { /* neither interface line can be trusted */
        if (ok) strlcpy(why, clash, why_size);
        ok = false;
        Config defaults;
        config_defaults(&defaults);
        strlcpy(c->host, defaults.host, sizeof c->host);
        strlcpy(c->peer, defaults.peer, sizeof c->peer);
    }
    return ok;
}

void config_print(const Config *c, FILE *out) {
    fprintf(out, "prefer-phone = %s\n", c->prefer_phone ? "yes" : "no");
    fprintf(out, "ipv6 = %s\n", c->ipv6 ? "yes" : "no");
    if (c->tx_batch) fprintf(out, "tx-batch = %u\n", c->tx_batch);
    else fputs("tx-batch = auto\n", out);
    fprintf(out, "verbose = %s\n", c->verbose ? "yes" : "no");
    fprintf(out, "host-interface = %s\n", c->host);
    fprintf(out, "peer-interface = %s\n", c->peer);
}

bool config_save(const Config *c, const char *path, char *why, size_t why_size) {
    if (!config_check(c, why, why_size)) return false;
    char temporary[1024];
    snprintf(temporary, sizeof temporary, "%s.new", path);
    FILE *f = fopen(temporary, "w");
    if (!f) {
        snprintf(why, why_size, "cannot write %s: %s", temporary, strerror(errno));
        return false;
    }
    fprintf(f,
        "# rndis-tether settings.\n"
        "# Change one with:  rndis-tether config <name> <value>\n"
        "# prefer-phone and verbose apply at once; the others need sudo and reconnect the\n"
        "# phone. After editing this file by hand run:  sudo rndis-tether restart\n"
        "\n"
        "# Send internet traffic through the phone while it is connected, even when Wi-Fi\n"
        "# is on. Local network and VPNs keep working. With \"no\", the phone is used only\n"
        "# when there is no other connection.\n"
        "prefer-phone = %s\n"
        "\n"
        "# Also set up IPv6 on the phone connection.\n"
        "ipv6 = %s\n"
        "\n"
        "# Most network packets sent to the phone in one USB transfer: auto (what the phone\n"
        "# allows, up to 32) or 1 to 32. Try 1 if uploads stall with a particular phone.\n"
        "tx-batch = ",
        c->prefer_phone ? "yes" : "no", c->ipv6 ? "yes" : "no");
    if (c->tx_batch) fprintf(f, "%u\n", c->tx_batch);
    else fputs("auto\n", f);
    fprintf(f,
        "\n"
        "# Detailed log, for troubleshooting.\n"
        "verbose = %s\n"
        "\n"
        "# Names of the two virtual network interfaces. Change only if these are taken.\n"
        "host-interface = %s\n"
        "peer-interface = %s\n",
        c->verbose ? "yes" : "no", c->host, c->peer);
    /* On disk before the rename: a power cut must not leave an empty file behind. */
    bool written = !ferror(f) && !fflush(f) && !fsync(fileno(f));
    if (fclose(f) || !written || chmod(temporary, 0644) || rename(temporary, path)) {
        snprintf(why, why_size, "cannot write %s: %s", path, strerror(errno));
        unlink(temporary);
        return false;
    }
    return true;
}
