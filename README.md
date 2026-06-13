# TR4WSERVER (Python)

A Python port of the Delphi `TR4WSERVER` — the network multi-station server for the
[TR4W](https://tr4w.net/) ham radio contest logging program. Designed to run
headlessly on a Raspberry Pi (or any Linux box) as the central hub for a
multi-op station, accepting connections from TR4W clients on the local network
so they can share QSO logs, DX spots, time sync, and intercom messages.

Copyright 2026 Thomas M. Schaefer NY4I
Original Delphi TR4WServer server copyright Dmitriy Gulyaev UA4WLI 2015.
GPL v3 (same as TR4W itself).

---

## Quick start

### Run it locally

Requires Python 3.7 or newer. No third-party dependencies — standard library only.

```sh
python3 tr4wserver.py
```

That's it. On first run it creates `tr4wserver.ini` (default config) and
`SERVERLOG.TRW` (empty log file with a header) in the current directory, then
listens on TCP port **1061** (main message bus) and **1062** (log-sync transfers).
Default password is `TR4WSERVER` — change it before exposing the server outside
your LAN (see [The INI file](#the-ini-file) below).

Interactive commands while it's running:
- `s` — print a one-shot status snapshot
- `q` — quit cleanly
- `Ctrl+C` — also quits cleanly

### Run it as a service on a Raspberry Pi

Clone or copy the repo to `/home/pi/tr4wserverpy` (any path works — the installer
patches the unit file). Then:

```sh
chmod +x install.sh
./install.sh
```

This rewrites the bundled `tr4wserver.service` to point at the current
directory, installs it to `/etc/systemd/system/`, enables it for boot, and
starts it. The unit runs as user `pi` with `Restart=always`.

Useful follow-ups:

```sh
sudo systemctl status tr4wserver       # is it up?
sudo systemctl restart tr4wserver      # after editing the INI
sudo journalctl -u tr4wserver -f       # live logs
```

Connect/disconnect events and a once-per-minute heartbeat (`heartbeat
clients=N/26 qsos=M rx=… tx=…`) appear in the journal, so a stuck server is
visible without manual polling.

If you're running outside the default `/home/pi/tr4wserverpy`, edit
`tr4wserver.service` after install to fix the `User=` and `WorkingDirectory=`
lines (the installer only patches the path on its first run).

---

## Command-line options

```
python3 tr4wserver.py [-h] [-c CONFIG] [-p PORT] [--password PASSWORD]
                      [--display] [--trace-rx]
```

| Flag | Purpose |
|------|---------|
| `-c, --config FILE` | Path to the INI file. Defaults to `tr4wserver.ini` in the current directory. Created with defaults if it doesn't exist. |
| `-p, --port PORT` | Override the main listening port from the INI. The sync port is always `PORT + 1`. |
| `--password PW` | Override the password from the INI. Useful for one-off testing. |
| `--display` | Redraw a per-station status table on stdout every 2 seconds. Mirrors the columns TR4W's own Network window shows (Name, Id, Band+Mode, Freq, St, PTT, Qs, Callsign, D, Op) plus the IP and hostname. Requires a TTY — has no effect when stdout goes to systemd's journal. |
| `--trace-rx` | Verbose protocol debug: log every `recv()` chunk in hex plus every framed message ID. Only useful when investigating a wire-format mismatch — leave off in normal use. |
| `--log-file PATH` | Append all log output to `PATH` in addition to stderr/journalctl. Useful for capturing a `--trace-rx` session for later analysis without losing the live view. |
| `--web-port PORT` | Serve a read-only HTML status page on `0.0.0.0:PORT`, in addition to the normal stdout/journalctl logging. Page auto-refreshes every 2 seconds. No auth — intended for a closed multi-op LAN. Overrides the `WEB PORT` INI key. |

The `s` interactive command produces the same per-station table as `--display`,
just as a one-shot snapshot instead of refreshing.

---

## The INI file

`tr4wserver.ini` is plain key/value, generated on first run if missing. All
keys live under a `[TR4WSERVER]` section.

```ini
[TR4WSERVER]
PORT = 1061
SERVER PASSWORD = TR4WSERVER
ALLOW TIME SYNCHRONIZING = 1
SERIAL NUMBER LOCKOUT = 0
LOG RECORD SIZE = 376
WEB PORT = 0
```

| Key | Default | What it does |
|-----|---------|--------------|
| `PORT` | `1061` | TCP port for the main message bus. The log-sync port is always `PORT + 1`, so the server binds two ports total. |
| `SERVER PASSWORD` | `TR4WSERVER` | 10-byte ASCII password. Every connecting TR4W client must send exactly this string. **Change it from the default if you can — anyone on your network who knows the default can join the server.** |
| `ALLOW TIME SYNCHRONIZING` | `1` | When `1`, `NET_TIMESYN` packets from one station are relayed to the others (so all clients agree on UTC). Set to `0` to disable. |
| `SERIAL NUMBER LOCKOUT` | `0` | Enables shared-serial coordination across multiple stations. When `1`, the server scans `SERVERLOG.TRW` at startup to find the highest `NumberSent` and seeds the next-serial counter to `max + 1`. Each connecting client is told the current next-serial; when any client reserves it (operator starts typing a callsign), the counter is bumped and every other free client is notified. Only matters in serial-exchange contests run as a multi-op with more than one station issuing serials at the same time. |
| `LOG RECORD SIZE` | `376` | `SizeOf(ContestExchange)` in bytes. See [TR4W version compatibility](#tr4w-version-compatibility) — only touch this if a TR4W update has changed the on-disk QSO record size and the server refuses to start because of a size mismatch. |
| `WEB PORT` | `0` (off) | If non-zero, bring up a read-only HTML status page on this TCP port (bound to all interfaces). Auto-refreshes every 2 seconds. Convenient for watching activity from a phone or tablet during a contest without SSH. No authentication — only enable on a closed LAN. Must not equal `PORT` or `PORT+1`. |

### Changing the password

Edit `tr4wserver.ini`, set `SERVER PASSWORD` to whatever you want (up to 10
ASCII characters), and restart the server:

```sh
sudo systemctl restart tr4wserver
```

Then update the matching `Server password` field in each TR4W client's network
settings to the same value. Clients that present the wrong password are
disconnected immediately — the server logs `Client <ip> - invalid password`.

You can also override the password at the command line with `--password PW`
without editing the file, useful when you're trying something temporarily.

---

## TR4W version compatibility

This server is a **protocol-compatible reimplementation** of the Delphi
`TR4WSERVER`, not a fork tied to any particular TR4W release. What matters for
compatibility is the binary wire format the Delphi clients speak, which is
defined by `VC.pas` in the TR4W source tree. As long as your clients and this
server agree on the message record sizes and the `ContestExchange` layout, the
server doesn't care which TR4W build is connecting.

In practice that means:

- **Routine TR4W releases that don't change any network record will Just Work.**
  Most TR4W changes are UI, contest definitions, radio support, etc.
- **A TR4W release that adds a field to one of the network records** (e.g. when
  the `ssOperator` field was added to `TStationState`, or any future change to
  `ContestExchange`) requires a corresponding update to this server's
  message-size table. The server is built to surface that situation rather than
  silently misbehaving:
  - For QSO records: on startup, if `SERVERLOG.TRW` exists with a size that
    isn't a multiple of `LOG RECORD SIZE`, the server refuses to run with a
    clear log line. Either delete the log (start fresh) or update `LOG RECORD
    SIZE` in the INI to the new `SizeOf(ContestExchange)`.
  - For other records: a mismatched client connection produces a `Disconnecting
    client: unknown or zero-size message ID …` log line, with a hex preview of
    the offending bytes. That client is dropped; other clients are unaffected.

The currently-shipped defaults track TR4W log format **v1.7** (`SizeOf(ContestExchange) = 376`),
with `TStationState` carrying the `ssOperator` field. See `CLAUDE.md` for the
full table of message sizes and which `VC.pas` line each one was reconciled
against — that's the file to update if you're chasing a future TR4W field
addition.

---

## Files generated at runtime

| File | Purpose |
|------|---------|
| `SERVERLOG.TRW` | The shared QSO log. Same on-disk format as TR4W's local `*.TRW` files — a header record followed by N `ContestExchange` records. Each client downloads this on connect via the sync port, then incremental QSOs are appended as they arrive. |
| `tr4wserver.ini` | Server configuration. Created with defaults if missing. |
| `tr4wserver.log` | Not used by this Python port — the Delphi server writes one, but here all logging goes to stdout (and therefore systemd's journal). |

Both `SERVERLOG.TRW` and `tr4wserver.ini` are gitignored so they're never
committed.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Cannot bind to port 1061: …` at startup | Another `tr4wserver` is already running on the box, or another process is using the port | `sudo systemctl status tr4wserver`; kill any stray instance |
| `SERVERLOG.TRW size … is not a multiple of LOG RECORD SIZE=376` | TR4W's `ContestExchange` record size has changed | Either delete `SERVERLOG.TRW` (loses the existing log) or set `LOG RECORD SIZE` in `tr4wserver.ini` to the new value |
| `Client <ip> - invalid password` | Client's `Server password` doesn't match `SERVER PASSWORD` in the INI | Sync the values |
| Connect-then-disconnect loop from a single client, `Disconnecting client: unknown or zero-size message ID …` | This server's per-message size table doesn't match what the client is sending | Capture a session with `--trace-rx` and check the message IDs / hex against `VC.pas` |
| Server feels hung, no heartbeat in `journalctl` | Genuine wedge — should not happen, please report | `sudo systemctl restart tr4wserver` and capture logs |

For deeper protocol debugging, run interactively with `--trace-rx`. Don't leave
it on in production; it's verbose.
