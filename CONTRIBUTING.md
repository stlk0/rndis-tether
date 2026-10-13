# Contributing to rndis-tether

Bug reports, phone reports and pull requests are welcome. For a bug, please open an
issue with the output of `rndis-tether status --raw`, your macOS version, the Mac
(Apple silicon or Intel) and the phone model. Reports from phones other than Samsung
are especially useful.

## Building and testing

rndis-tether builds only on macOS, with the Command Line Tools (`xcode-select --install`).

```bash
make            # the program: ./rndis-tether
make check      # offline tests under UndefinedBehaviorSanitizer and Guard Malloc
make analyze    # clang static analyzer; fails on any finding
make dist       # release archive: universal binary, ad-hoc signed
```

Everything is compiled with `-Werror -Wpedantic`; CI runs all of the above on Apple
silicon and Intel. Guard Malloc is used instead of AddressSanitizer, which aborts at
startup with the Command Line Tools clang on recent macOS. `make check` runs each test
twice: with the guard page after every allocation, then before it.

The daemon needs a real phone. To try a change, stop the installed service, run the new
build in the foreground, and reinstall the service afterwards:

```bash
sudo launchctl bootout system/io.github.stlk0.rndis-tether
sudo ./rndis-tether run --verbose
sudo ./rndis-tether install
```

Power, CPU and leak measurements for one state (unplugged, idle, under load):
`sudo scripts/profile.sh <state>`, described at the top of the script.
`make bpf-feth-test` builds a root-only check that BPF on a feth interface works.

## Layout

The code is plain C11 with IOKit, CoreFoundation and SystemConfiguration; no other
dependencies. Everything runs on one thread, on the main run loop. Dependencies point
down: lower modules report upwards only through event structs (`ControlEvents`,
`DatapathEvents`) or callbacks, so each can be tested alone.

| File | Role |
| --- | --- |
| `src/main.c` | Command dispatch, `run` options, `list` |
| `src/daemon.c` | The service: single-instance lock, device discovery (IOKit notifications), retry policy, sleep/wake, signals, status report, live settings |
| `src/session.c` | One connection: bring-up (INIT, queries, filter), feth + BPF, DHCP lease and the phone's `PrimaryRank`, teardown with HALT |
| `src/health.c` | KEEPALIVE after silence; soft RESET (drain bulk OUT, RESET, restore filter) |
| `src/control.c` | Pipe-0 channel: synchronous exchange for bring-up, then the async pump and the interrupt endpoint |
| `src/datapath.c` | Frames: bulk IN → BPF (batched writes), BPF → bulk OUT (batched transfers); statistics |
| `src/status.c` | `name=value` status lines and the socket that serves them |
| `src/admin.c` | The settings socket for administrators: `set <name> <value>`, caller checked by uid |
| `src/usb.c` | The only IOKit USB code: matching (`e0/01/03`, `02/02/ff` minus CDC-ACM modems), open/close, transfers |
| `src/netif.c` | feth pair, BPF, `ipconfig set`, SCDynamicStore (lease, service rank, primary interface), subprocesses |
| `src/rndis.c` | Pure RNDIS encoding and parsing, CDC descriptor walk. No I/O. |
| `src/clock.c`, `src/log.c` | Monotonic time and run-loop timers; logging (unified log under launchd, stderr otherwise) |
| `src/config.c` | Settings file `/etc/rndis-tether.conf`, fixed paths, version |
| `src/cli.c` | `install`, `uninstall`, `restart`, `status`, `monitor`, `config` |
| `tests/selftest.c` | Unit tests and a fuzzer for `rndis.c`, BPF records, the settings file |
| `tests/controltest.c` | `control.c` over a fake USB link |
| `tests/sessiontest.c` | `datapath.c`, `health.c`, `status.c` over fake USB and control; `admin.c` over a real socket |
| `tests/bpftest.c` | Root-only BPF diagnostic (`make bpf-feth-test`) |
| `install.sh` | One-line installer from the latest GitHub release |
| `packaging/homebrew/` | Formula for the `stlk0/homebrew-tap` repository |

## Things that must not regress

Each of these was found the hard way on a real phone.

- **The BPF header is 18 bytes on macOS** (`SIZEOF_BPF_HDR`), not
  `sizeof(struct bpf_hdr)` (20). There is a regression test with real bytes.
- **Never change feth50's MAC address** after creating it. `ifconfig lladdr` races with
  macOS's DHCP client, which may keep the old address; the phone then answers to it and
  every offer is lost (a 169.254 address). feth keeps its own; the phone answers any MAC.
- **TX batching** groups only frames already returned by one BPF read and never waits.
  On a Galaxy S25 it doubled upload speed (16 → 30 Mbit/s) and removed outgoing drops.
- **prefer-phone ranks the network service; it does not add routes.** A temporary
  `State:/Network/Service/<id>` = `{PrimaryRank = First}` in SCDynamicStore makes macOS
  itself move the default route and DNS. Extra `0/1` + `128/1` routes left Wi-Fi as the
  primary service, which broke VPN clients such as Tailscale. The rank is removed before
  `ipconfig set NONE`.
- **No nested run loop**, e.g. to wait for completions during teardown: signals, device
  notifications and timers would then run inside a half-closed session. Teardown aborts
  pipes, sends HALT synchronously and closes the interfaces.
- A completion from a closed USB link is dropped (link generation, bumped by
  `usb_close`); a failure reported after its session ended is dropped too. All
  per-session state lives in one struct, reset by one assignment.
- The DHCP lease is read from SCDynamicStore (`State:/Network/Service/*/IPv4`), not by
  polling `ipconfig`.
- A re-enumerated phone leaves a stale IOKit registry entry: check
  `IORegistryEntryInPlane` and switch to the new device.
- A transfer's last RNDIS message goes without alignment padding when only that fits;
  otherwise a phone with a 1558-byte limit drops every full-size frame.
- `install` copies the program to `/Library/PrivilegedHelperTools` (root-owned): launchd
  must never run a binary from a user-writable Homebrew prefix.
- Under launchd the daemon logs with `os_log` only; there is no log file to rotate.
- The status socket format is a public interface (README, "For other programs"): bump
  `STATUS_PROTOCOL` only when a field changes meaning or goes away.
- The settings socket is created owner-only and then given to `root:admin` with mode
  0660; every connection is checked with `getpeereid` and `mbr_check_membership`, and
  nothing is read from anyone else. Only settings that apply live are accepted.

## Tested so far

Samsung Galaxy S25 on an Intel Mac with macOS 26: connecting, unplugging, sleep and
wake, Wi-Fi on and off, VPN (Tailscale), settings changed live, sustained load. Not yet
tested: Apple silicon, phones with the CDC-style `02/02/ff` interface, the phone's RESET
and link up/down indications.

## Releasing

1. Bump `VERSION` in `src/config.h` (README examples mention it too), commit, push.
2. Tag `vX.Y.Z` and push the tag. The Release workflow builds `make dist` and creates a
   draft release with `rndis-tether-macos.tar.gz` and its `.sha256`. Review it, then
   publish.
3. Homebrew: take the SHA-256 of
   `https://github.com/stlk0/rndis-tether/archive/refs/tags/vX.Y.Z.tar.gz`, put the url
   and sha256 into `packaging/homebrew/rndis-tether.rb` and copy the file to
   `Formula/rndis-tether.rb` in `stlk0/homebrew-tap`.
