# rndis-tether

**Use your Android phone's internet on a Mac through a USB cable.**

macOS does not support USB tethering from Android phones. rndis-tether adds it: plug in
the phone, turn on USB tethering, and the Mac is online, as if you had plugged in a
network cable. It starts by itself, survives sleep, unplugging and restarts, and needs
no window or menu.

## What you need

- A Mac with **macOS 13 Ventura or newer** (Apple silicon or Intel).
- An **Android phone** with USB tethering. Almost every Android phone has it.
- A **USB cable that carries data**. Some cheap cables only charge.

An iPhone does not need this: macOS supports iPhone tethering already.

## Install

Pick one of the two ways.

### Option A: one command

1. Open **Terminal**: press Cmd-Space, type `Terminal`, press Return.
2. Copy this line, paste it into Terminal and press Return:

   ```bash
   /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/stlk0/rndis-tether/main/install.sh)"
   ```

3. Type your Mac password when asked (the one you log in with). Nothing appears while
   you type; that is normal. Press Return.

### Option B: Homebrew

If you use [Homebrew](https://brew.sh):

```bash
brew install stlk0/tap/rndis-tether
```

```bash
sudo rndis-tether install
```

Either way, the installer ends with `rndis-tether 1.0.1 is installed` and the current
status. macOS may show a notification "Background Items Added": that is rndis-tether,
leave it allowed.

## Use

1. Connect the phone to the Mac with the cable.
2. On the phone, turn on **USB tethering**:
   - Samsung: *Settings > Connections > Mobile Hotspot and Tethering > USB tethering*
   - Pixel and most others: *Settings > Network & internet > Hotspot & tethering > USB tethering*
3. Wait a few seconds. That is all.

Next time, just plug in and turn on USB tethering again. Many phones switch it off by
themselves when the cable is unplugged; the Mac cannot change that.

## Is it working?

In Terminal:

```bash
rndis-tether status
```

When everything works:

```
Phone:    SAMSUNG_Android 04e8:6864
Status:   online for 12 min, address 10.140.31.217 (phone 10.140.31.23)
Internet: goes through the phone
Traffic:  received 771.7 MB, sent 162.5 MB
```

When something is wrong, `status` says what and what to do about it. For a live view
with speeds, run `rndis-tether monitor` (Ctrl-C to quit).

## Settings

By default, **all internet traffic goes through the phone** while it is connected, even
if Wi-Fi is on: macOS treats the phone as its main connection. Your local network
(printers, file sharing) and VPNs such as Tailscale keep working. This uses the phone's
mobile data.

To keep Wi-Fi as the main connection and use the phone only when there is no other:

```bash
rndis-tether config prefer-phone no
```

and to switch back: `rndis-tether config prefer-phone yes`. This takes effect at once,
without disconnecting. It works without `sudo` for administrators of the Mac (the usual
account type); other users get a message that only an administrator can change it.

All settings, with their current values: `rndis-tether config`. `prefer-phone` and
`verbose` apply at once; the others need `sudo` and reconnect the phone, which takes a
few seconds.

| Setting | Default | Meaning |
| --- | --- | --- |
| `prefer-phone` | `yes` | Send internet traffic through the phone even when Wi-Fi is on |
| `ipv6` | `no` | Also set up IPv6 on the phone connection |
| `tx-batch` | `auto` | Packets per USB transfer to the phone; try `1` if uploads stall with a particular phone |
| `verbose` | `no` | Detailed log, for troubleshooting |
| `host-interface`, `peer-interface` | `feth50`, `feth51` | Names of the virtual network interfaces; change only if they are taken |

## Problems

| What you see | What to do |
| --- | --- |
| `status` says *waiting for a phone* | Check that USB tethering is on, unlock the phone, try another cable (it must carry data) or another USB port. `rndis-tether list` shows whether the Mac sees the phone. |
| *Another program is using the phone's USB tethering* | Quit HoRNDIS, TetherKit or any other tethering tool. |
| Online, but websites do not open | Check that the phone itself has internet (mobile data on, not out of data). |
| *Internet: goes through …, which macOS ranks above the phone* | A VPN that takes all traffic is on. That is fine: the VPN itself normally runs over the phone. |
| *The service is installed but not running* | Run `sudo rndis-tether install` again. |
| The phone does not appear in *System Settings > Network* | That is expected: rndis-tether sets the connection up on its own. |

If you are stuck, open an [issue](https://github.com/stlk0/rndis-tether/issues) and
include the output of `rndis-tether status --raw` and of:

```bash
/usr/bin/log show --last 30m --style compact --predicate 'subsystem == "io.github.stlk0.rndis-tether"'
```

## Update

- Option A: run the same install command again.
- Homebrew: `brew upgrade rndis-tether`, then `sudo rndis-tether install`.

Your settings are kept.

## Uninstall

```bash
sudo rndis-tether uninstall
```

This removes the background service, its settings and its network interfaces. With
Homebrew, then also run `brew uninstall rndis-tether`.

## Privacy and safety

- rndis-tether only passes your traffic between the phone and macOS. It sends nothing
  anywhere by itself: no telemetry, no update checks.
- It runs as a system service (as root) because creating a network interface requires
  that. The code is open: about 4,500 lines of C.
- The program is not yet signed with an Apple Developer ID. Both install options above
  avoid the macOS warning about that. If you download the archive from the Releases page
  in a browser instead, macOS blocks it until you allow it in
  *System Settings > Privacy & Security*.

---

## Technical details

### How it works

```
apps -> macOS TCP/IP -> feth50 (DHCP from the phone, via macOS's own ipconfig)
                           |  feth pair
                        feth51 <- BPF -> rndis-tether -> USB bulk <-> phone (RNDIS)
```

- A LaunchDaemon waits for an RNDIS function (USB interface class `e0/01/03`, or the
  Android variant `02/02/ff`; real CDC-ACM modems are filtered out by their
  descriptors). It opens the interfaces normally, so ADB on the same phone keeps working.
- It speaks RNDIS to the phone over IOKit and moves Ethernet frames to a `feth` pair
  through BPF. macOS sees an ordinary Ethernet interface: its own DHCP client, DNS and
  lease renewals do the rest.
- With `prefer-phone`, the phone's network service is ranked first among macOS's
  services (a temporary `PrimaryRank` in SCDynamicStore), as if it were at the top of
  the service order. macOS then moves the default route and DNS itself, and every app
  that follows the system's choice (VPN clients included) sees the same picture. Without
  it, the phone comes after the services in the service order and is used when they are
  gone.
- Frames macOS hands over in one burst go to the phone in one USB transfer (up to the
  phone's `MaxPacketsPerTransfer`, 15 on a Galaxy S25). Frames from the phone reach
  macOS with one BPF write per USB transfer where the kernel supports it.
- Health: a KEEPALIVE after 5 s of silence; USB stalls are cleared; error bursts lead to
  a soft RESET that keeps the interface and lease; failing that, the session restarts
  (after 1, 2, 4, 8, 16 s, then every 30 s). Sleep closes the session with HALT; wake
  opens a new one.

### What gets installed

| Path | What |
| --- | --- |
| `/Library/PrivilegedHelperTools/io.github.stlk0.rndis-tether` | The program the service runs |
| `/Library/LaunchDaemons/io.github.stlk0.rndis-tether.plist` | The service definition |
| `/etc/rndis-tether.conf` | Settings (explained inside the file) |
| `/usr/local/bin/rndis-tether` | Link to the program, only when Homebrew did not install it |
| `/var/run/rndis-tether.sock` | Status for `rndis-tether status`, while the service runs |
| `/var/run/rndis-tether-admin.sock` | Settings changed by administrators, while the service runs |
| `/var/db/rndis-tether` | Only root can enter it: the service's lock and the names of the interfaces it created |
| `feth50`, `feth51` | Network interfaces, while a phone is connected |

### Commands

```
rndis-tether status [--raw]          is it working, and what to do if not
rndis-tether monitor                 live status and speed
sudo rndis-tether install            install or update the service
sudo rndis-tether uninstall          remove the service, settings and interfaces
rndis-tether config                  show settings
rndis-tether config NAME VALUE       change a setting (sudo for ipv6, tx-batch, interfaces)
sudo rndis-tether restart            restart the service, e.g. after editing the file
rndis-tether list                    tethering devices connected now
sudo rndis-tether run [options]      the daemon itself, in the foreground
```

For troubleshooting in the foreground, stop the service first:

```bash
sudo launchctl bootout system/io.github.stlk0.rndis-tether
```

```bash
sudo rndis-tether run --verbose
```

and start it again afterwards with `sudo rndis-tether install`.

### For other programs

The service answers on two UNIX sockets, so another program (a menu bar app, a script)
can show its state and change settings without `sudo`. Both belong to root; a careful
client checks that with `getpeereid()` after connecting, as `rndis-tether` itself does.

**Status**, `/var/run/rndis-tether.sock`, readable by everyone. Connect and read until
the service closes the connection: one `name=value` per line, the same as
`rndis-tether status --raw`. The first line is `protocol=1`; the number changes only if
a field changes its meaning or goes away. New fields may appear at any time, so skip
names you do not know.

| Field | Meaning |
| --- | --- |
| `protocol`, `version`, `pid` | Status format, version and process of the service |
| `state` | `no-phone`, `unsupported`, `sleeping`, `retrying`, `connecting` or `online` |
| `prefer-phone` | `yes` or `no` |
| `phone` | USB name of the phone, when one is plugged in |
| `interface`, `connected-since` | `feth50`, and when the connection started (Unix time); while connected |
| `address`, `gateway` | The Mac's address from the phone, and the phone's; once DHCP has answered |
| `primary` | The interface macOS sends internet traffic to now; while connected |
| `rx-bytes`, `tx-bytes` | Received from and sent to the phone in this connection |
| `rx-dropped`, `tx-dropped`, `usb-errors`, `resets` | Trouble counters for this connection |
| `problem` | Why the last attempt to connect failed |
| `settings-problem` | A line in the settings file that could not be read |

Speed is the difference between two readings of `rx-bytes`/`tx-bytes`; the counters
start from zero with every connection.

**Settings**, `/var/run/rndis-tether-admin.sock`, owned by `root:admin` with mode `0660`:
only root and administrators can connect, and the service checks the caller again.
Send one line, read one line back:

```
set prefer-phone no      ->   ok
set verbose maybe        ->   error: verbose must be yes or no, not "maybe"
```

Only `prefer-phone` and `verbose` can be set this way. The service applies the change
at once and saves it in `/etc/rndis-tether.conf`.

### Logs

The service logs to the macOS unified log (subsystem `io.github.stlk0.rndis-tether`),
which rotates by itself. Live:

```bash
/usr/bin/log stream --style compact --predicate 'subsystem == "io.github.stlk0.rndis-tether"'
```

The full path `/usr/bin/log` matters in zsh, where `log` is a built-in command.

### Building from source

Needs the Xcode Command Line Tools (`xcode-select --install`).

```bash
make
sudo ./rndis-tether install
```

Tests, the code layout and how to contribute: [CONTRIBUTING.md](CONTRIBUTING.md).
Security problems: please report them privately, see [SECURITY.md](SECURITY.md).

### Limitations

- One phone at a time; a second one is ignored while the first is connected.
- The connection is a temporary macOS network service, so it does not appear in
  System Settings > Network.
- Only phones that use RNDIS for USB tethering. Some newer phones can also use CDC NCM,
  which macOS supports natively: such a phone works without rndis-tether, and
  `rndis-tether list` does not show it.
- Tested with a Samsung Galaxy S25 on an Intel Mac with macOS 26. Reports about other
  phones and Macs are welcome.

### Credits

- [TetherKit](https://github.com/XiaoMiku01/TetherKit) (MIT) showed that the feth + BPF
  approach works well on current macOS.
- [HoRNDIS](https://github.com/jwise/HoRNDIS), the original RNDIS driver for macOS.
- Linux `rndis_host`, for how a host should behave towards real phones.

### License

[MIT](LICENSE)
