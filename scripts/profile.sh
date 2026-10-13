#!/bin/sh
# Power, CPU and leak snapshot for one test state. Run as root, once per state:
#   sudo scripts/profile.sh unplugged    phone not connected
#   sudo scripts/profile.sh cable        phone plugged in, tethering on, daemon stopped
#   sudo scripts/profile.sh idle         daemon running, no traffic
#   sudo scripts/profile.sh load         daemon running during a large download/upload
# Optional second argument: powermetrics duration in seconds (default 60).
# Results: profile/<state>-<time>/ in the repo; summary.txt is the short version.
# Leak check: run "idle" with the daemon up, do 5 unplug/replug and 2 sleep/wake
# cycles, run "idle" again and compare ports, files and rss in the two summaries.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run as: sudo $0 <state> [seconds]" >&2
    exit 1
fi
STATE=${1:?usage: sudo scripts/profile.sh <state> [seconds]}
DURATION=${2:-60}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/profile/$STATE-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
SUMMARY=$OUT/summary.txt

note() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }

# On battery, the battery current is the whole machine's power draw.
battery() {
    info=$(ioreg -rn AppleSmartBattery)
    amps=$(printf '%s\n' "$info" | sed -n 's/^ *"InstantAmperage" = \([0-9]*\)$/\1/p')
    volts=$(printf '%s\n' "$info" | sed -n 's/^ *"Voltage" = \([0-9]*\)$/\1/p')
    charger=$(printf '%s\n' "$info" | sed -n 's/^ *"ExternalConnected" = \(.*\)$/\1/p')
    [ -n "$amps" ] && [ -n "$volts" ] || { echo "battery: no data"; return; }
    # The register is signed 64-bit but printed unsigned.
    ma=$(echo "a = $amps; if (a > 9223372036854775807) a = a - 18446744073709551616; a" | bc)
    if [ "$charger" = "No" ]; then
        echo "battery: $ma mA at $volts mV, system draw $(echo "scale=1; -($ma) * $volts / 1000000" | bc) W"
    else
        echo "battery: $ma mA at $volts mV, charger connected (system draw not measurable this way)"
    fi
}

# The daemon reports its pid; process names are cut to 16 characters, so pgrep -x misses it.
PID=$("$ROOT/rndis-tether" status --raw 2>/dev/null | sed -n 's/^pid=//p' || true)
note "state: $STATE, $(date '+%Y-%m-%d %H:%M:%S'), macOS $(sw_vers -productVersion) $(uname -m)"
note "daemon pid: ${PID:-not running}"
note "$(battery)"

system_profiler SPUSBHostDataType > "$OUT/usb.txt" 2>&1 || true

if [ -n "$PID" ]; then
    # Second top sample gives rates over 5 s: CPU, idle wakeups, power score.
    top -l 2 -s 5 -pid "$PID" -stats pid,command,cpu,time,threads,ports,mem,idlew,power > "$OUT/top.txt" 2>&1 || true
    note "top (5 s): $(grep -E '^ *PID' "$OUT/top.txt" | tail -1 | tr -s ' ')"
    note "           $(grep -E "^ *$PID " "$OUT/top.txt" | tail -1 | tr -s ' ')"
    lsof -p "$PID" > "$OUT/files.txt" 2>&1 || true
    note "open files: $(($(wc -l < "$OUT/files.txt") - 1))"
    leaks "$PID" > "$OUT/leaks.txt" 2>&1 || true
    note "leaks: $(grep -E 'leaks for' "$OUT/leaks.txt" | sed 's/^Process [0-9]*: //' || true)"
    note "sampling the daemon for 10 s ..."
    sample "$PID" 10 -file "$OUT/sample.txt" > /dev/null 2>&1 || true
fi

COUNT=$((DURATION / 5))
[ "$COUNT" -ge 1 ] || COUNT=1
note "powermetrics: $COUNT x 5 s ..."
measure() {
    powermetrics --samplers "$1" --show-process-energy --show-process-netstats \
        -i 5000 -n "$COUNT" > "$OUT/powermetrics.txt" 2>&1
}
measure tasks,cpu_power,smc,thermal || measure tasks,cpu_power,thermal || true
note "$(grep -iE 'package power|die temperature|fan:|pressure level' "$OUT/powermetrics.txt" | sort | uniq -c | sort -rn | head -12)"
note "per-process lines (each 5 s sample):"
note "$(grep -m1 -E '^Name +ID' "$OUT/powermetrics.txt" || true)"
note "$(grep -E '^(io\.github\.stlk0|rndis-tether|kernel_task)' "$OUT/powermetrics.txt" || true)"
note "$(battery)"

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$ROOT/profile"
echo "saved to $OUT"
