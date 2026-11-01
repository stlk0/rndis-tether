#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FETH_PREFIX "feth" /* if_fake's interface name, followed by the unit number */
#define CONFIG_LINE_SIZE 512 /* a longer line is reported as too long */
#define TX_BATCH_AUTO "auto" /* tx-batch 0 in the file and in config: what the phone allows */

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
    const size_t prefix = sizeof FETH_PREFIX - 1;
    size_t n = strlen(name);
    if (n <= prefix || n >= IFNAMSIZ || strncmp(name, FETH_PREFIX, prefix)) return false;
    for (size_t i = prefix; i < n; ++i) if (!isdigit((unsigned char)name[i])) return false;
    return true;
}

bool config_parse_bool(const char *name, const char *value, bool *out, char *why, size_t why_size) {
    if (parse_bool(value, out)) return true;
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

static bool set_tx_batch(unsigned *tx_batch, const char *value, char *why, size_t why_size) {
    if (!strcasecmp(value, TX_BATCH_AUTO)) { *tx_batch = 0; return true; }
    /* strtol alone would also take leading spaces and a sign. */
    bool digits = *value && strspn(value, "0123456789") == strlen(value);
    long n = digits ? strtol(value, NULL, 10) : 0;
    if (digits && n >= 1 && n <= TX_BATCH_MAX) {
        *tx_batch = (unsigned)n;
        return true;
    }
    snprintf(why, why_size, "tx-batch must be auto or a number from 1 to %u, not \"%s\"", TX_BATCH_MAX, value);
    return false;
}

bool config_set(Config *c, const char *name, const char *value, char *why, size_t why_size) {
    if (!strcmp(name, SETTING_PREFER_PHONE)) return config_parse_bool(name, value, &c->prefer_phone, why, why_size);
    if (!strcmp(name, SETTING_IPV6)) return config_parse_bool(name, value, &c->ipv6, why, why_size);
    if (!strcmp(name, SETTING_VERBOSE)) return config_parse_bool(name, value, &c->verbose, why, why_size);
    if (!strcmp(name, SETTING_HOST_INTERFACE)) return set_interface(c->host, name, value, why, why_size);
    if (!strcmp(name, SETTING_PEER_INTERFACE)) return set_interface(c->peer, name, value, why, why_size);
    if (!strcmp(name, SETTING_TX_BATCH)) return set_tx_batch(&c->tx_batch, value, why, why_size);
    snprintf(why, why_size, "unknown setting \"%s\" (known: " SETTING_PREFER_PHONE ", " SETTING_IPV6 ", "
             SETTING_TX_BATCH ", " SETTING_VERBOSE ", " SETTING_HOST_INTERFACE ", " SETTING_PEER_INTERFACE ")", name);
    return false;
}

bool config_live(const char *name) {
    return !strcmp(name, SETTING_PREFER_PHONE) || !strcmp(name, SETTING_VERBOSE);
}

bool config_set_live(Config *c, const char *name, const char *value, char *why, size_t why_size) {
    Config changed = *c;
    if (!config_set(&changed, name, value, why, why_size)) return false;
    if (!config_live(name)) {
        snprintf(why, why_size, "%s applies only when the service starts again: sudo rndis-tether config %s %s",
                 name, name, value);
        return false;
    }
    *c = changed;
    return true;
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

/* One line of the file (its newline goes with the trailing spaces); false and problem
 * when it is not a setting. */
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
    char line[CONFIG_LINE_SIZE], problem[200];
    unsigned line_number = 0;
    bool ok = true;
    bool end = false;
    while (!end && fgets(line, sizeof line, f)) {
        ++line_number;
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
        if (ok) snprintf(why, why_size, "%s line %u: %s", path, line_number, problem);
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

#define TX_BATCH_TEXT_SIZE sizeof "4294967295"

/* tx-batch as written in the file; buffer holds a number. */
static const char *tx_batch_text(unsigned tx_batch, char *buffer, size_t size) {
    if (!tx_batch) return TX_BATCH_AUTO;
    snprintf(buffer, size, "%u", tx_batch);
    return buffer;
}

void config_print(const Config *c, FILE *out) {
    char batch[TX_BATCH_TEXT_SIZE];
    fprintf(out, SETTING_PREFER_PHONE " = %s\n", config_bool_text(c->prefer_phone));
    fprintf(out, SETTING_IPV6 " = %s\n", config_bool_text(c->ipv6));
    fprintf(out, SETTING_TX_BATCH " = %s\n", tx_batch_text(c->tx_batch, batch, sizeof batch));
    fprintf(out, SETTING_VERBOSE " = %s\n", config_bool_text(c->verbose));
    fprintf(out, SETTING_HOST_INTERFACE " = %s\n", c->host);
    fprintf(out, SETTING_PEER_INTERFACE " = %s\n", c->peer);
}

bool config_save(const Config *c, const char *path, char *why, size_t why_size) {
    if (!config_check(c, why, why_size)) return false;
    char temporary[PATH_MAX];
    snprintf(temporary, sizeof temporary, "%s.new", path);
    FILE *f = fopen(temporary, "w");
    if (!f) {
        snprintf(why, why_size, "cannot write %s: %s", temporary, strerror(errno));
        return false;
    }
    char batch[TX_BATCH_TEXT_SIZE];
    fprintf(f,
        "# rndis-tether settings.\n"
        "# Change one with:  rndis-tether config <name> <value>\n"
        "# prefer-phone and verbose apply at once; the others need sudo and reconnect the\n"
        "# phone. After editing this file by hand run:  sudo rndis-tether restart\n"
        "\n"
        "# Send internet traffic through the phone while it is connected, even when Wi-Fi\n"
        "# is on. Local network and VPNs keep working. With \"no\", the phone is used only\n"
        "# when there is no other connection.\n"
        SETTING_PREFER_PHONE " = %s\n"
        "\n"
        "# Also set up IPv6 on the phone connection.\n"
        SETTING_IPV6 " = %s\n"
        "\n"
        "# Most network packets sent to the phone in one USB transfer: auto (what the phone\n"
        "# allows, up to %u) or 1 to %u. Try 1 if uploads stall with a particular phone.\n"
        SETTING_TX_BATCH " = %s\n"
        "\n"
        "# Detailed log, for troubleshooting.\n"
        SETTING_VERBOSE " = %s\n"
        "\n"
        "# Names of the two virtual network interfaces. Change only if these are taken.\n"
        SETTING_HOST_INTERFACE " = %s\n"
        SETTING_PEER_INTERFACE " = %s\n",
        config_bool_text(c->prefer_phone), config_bool_text(c->ipv6), TX_BATCH_MAX, TX_BATCH_MAX,
        tx_batch_text(c->tx_batch, batch, sizeof batch), config_bool_text(c->verbose), c->host, c->peer);
    /* On disk before the rename: a power cut must not leave an empty file behind. */
    bool written = !ferror(f) && !fflush(f) && !fsync(fileno(f));
    if (fclose(f) || !written || chmod(temporary, 0644) || rename(temporary, path)) {
        snprintf(why, why_size, "cannot write %s: %s", path, strerror(errno));
        unlink(temporary);
        return false;
    }
    return true;
}
