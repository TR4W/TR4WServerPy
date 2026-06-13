# TR4WSERVER (Python) Change Log

> Python port of the Delphi TR4WSERVER for TR4W contest logging
> Repository: [github.com/TR4W/TR4WServerPy](https://github.com/TR4W/TR4WServerPy)
> Generated: 2026-05-16

## Contributors

| Call | GitHub | Commits |
|------|--------|---------|
| NY4I — Tom Schaefer | [@ny4i](https://github.com/ny4i) | (port + ongoing) |
| UA4WLI — Dmitriy Gulyaev | | (original Delphi TR4WSERVER author) |

---

### 1.0 (2026-05-16) — NY4I

First versioned release. Establishes baseline parity with the Delphi `tr4wserver.exe` wire protocol as of TR4W log format **v1.7** (`SizeOf(ContestExchange) = 376`), plus operational hardening for unattended Raspberry Pi deployment.

#### Wire-format reconciliation with current `VC.pas` (`tr4wserver.py`, `CLAUDE.md`)

- **Corrected `NET_LOGINFO_MESSAGE = 3030002000`** (verbatim from `VC.pas:2644`). The prior value `0x52544847` (claimed in a comment to be `'GHTR'`) was fabricated and never matched any byte sequence TR4W actually sends — the log-info re-poll path was dead code.
- **Rewrote `TLogFileInformation`** to match the Delphi packed-record layout (6 fields, 19 bytes: `liID`, `liSeverCRC32`, `liLocalCRC32`, `liServerLogSize`, `liLocalLogSize`, `liContest`). Previous 4-field, 14-byte form silently misrendered every field clients tried to read.
- **Rebuilt `MESSAGE_SIZES`** from current `VC.pas` records under `{$A8}` alignment + `{$Z1}` enum size. Notable corrections: `NET_STATIONSTATUS_ID 36→46` (operator field added in TR4W commit `6708783`), `NET_NETWORKDXSPOT_ID 82→98`, `NET_PARAMETER_ID 516→514`, `NET_INTERCOMMESSAGE_ID 128→84`, `NET_CLIENTSTATUS_ID 4→3`, `NET_SPOTVIANETWORK_ID 64→48`, QSO messages `242→384`.
- **`LOG RECORD SIZE` INI key (default 376)** validates `SERVERLOG.TRW` at startup, refusing to run on size mismatch — matches Delphi `tr4wserver.dpr:70-83`. Future `ContestExchange` field adds fail loud instead of silently corrupting the log.
- **Critical handshake fix**: password reads were `recv(50)`; Delphi reads exactly 10 bytes. When TR4W coalesced password + first post-handshake message into one TCP write, the over-read silently dropped the message bytes, causing first-connect failures (`unknown message ID 0x0000`). Now uses `_recv_exact(sock, 10)` matching the Delphi server exactly.

#### Resilience hardening (`tr4wserver.py`)

- **Socket timeouts** on every accepted client: `SOCKET_RECV_TIMEOUT=300s` and `SOCKET_SEND_TIMEOUT=30s` via `SO_SNDTIMEO`. Slow/dead clients no longer freeze broadcast threads.
- **`_safe_sendall()` helper** with `sendall()` everywhere (was `.send()` with no partial-send handling). Dead-peer errors (`BrokenPipe`, `ConnectionReset`, `socket.timeout`, `OSError`) collapse to a "drop this client" path; broadcasts mark dead sockets for cleanup *after* the iteration completes.
- **Reverse DNS off the accept hot path** — moved to a 2-thread `concurrent.futures.ThreadPoolExecutor` with a 2-second hard timeout. Was a 30-second blocker per connection on bad resolvers.
- **Bounded per-client recv buffer** (`MAX_CLIENT_BUFFER = 8192`); overflow disconnects that one client with a diagnostic preview rather than an infinite reparse loop.
- **Unknown message IDs disconnect cleanly** via `UnknownMessageError` instead of the Delphi silent fall-through, which would have stuck a tight reparse loop on layout drift.
- **SIGTERM / SIGHUP handlers** call `server.stop()` so systemd's clean stop completes in-flight broadcasts. `stop()` is idempotent.
- **Streaming chunked CRC32** (was reading the whole log into memory).
- **60-second heartbeat line** (`heartbeat clients=N/26 qsos=M rx=X tx=Y`) so a hung server is visible in `journalctl` even with no client activity.
- **Bind/listen failures** logged via `logger.critical` and re-raised so systemd's retry has clear context in the journal.

#### Live status display (`tr4wserver.py`)

- **`--display` mode**: ANSI clear-screen refresh every 2 seconds in a TTY, with a TR4W-style per-station table (Name, Id, Band+Mode, Freq, St, PTT, Qs, Callsign, D, Op) parsed live from the `TStationState` packets the server already relays. Auto-falls-back to `os.system('cls')` on Windows builds where `ENABLE_VIRTUAL_TERMINAL_PROCESSING` can't be enabled.
- **Last-QSO line** between the header and the table — timestamp, callsign, band+mode, freq, sender computer ID, with `(edit)` tag for `NET_EDITEDQSO_ID`.
- **`s` interactive command** prints the same table once.
- **`--web-port PORT` flag** (and matching `WEB PORT` INI key): opt-in embedded HTML status page on `0.0.0.0:PORT`, no auth, intended for closed multi-op LAN. **Kiosk-friendly**: JavaScript `fetch()` polling against a `/status` plain-text endpoint instead of `<meta http-equiv="refresh">`, so a temporary server outage doesn't replace the browser tab with a chrome error page. Stale data stays visible with a red "offline" indicator until the server comes back. Collision guard refuses to bind on `PORT` or `PORT+1` (the message-bus and sync ports).

#### Serial-number lockout (`tr4wserver.py`, `tr4wserver.ini`)

- **Full implementation** of the Delphi `tr4wserverUnit.pas` state machine when `SERIAL NUMBER LOCKOUT = 1`:
  - Startup scan of `SERVERLOG.TRW` reads `NumberSent` at `CE_NUMBER_SENT_OFFSET=204` from every record, seeds `self.next_serial = max + 1`.
  - On each client connect: `_send_serial_numbers_changed()` pushes the current `next_serial` via `SM_SERIAL_NUMBER_CHANGED` to every `SNT_FREE` client.
  - On inbound `sntReserved` from a client: bumps the shared counter, re-broadcasts to remaining free clients. Mirrors `UpdateSerialNumbersStatus` (`tr4wserverUnit.pas:1132`).
  - On `SM_CLEARALLLOGS_MESSAGE`: re-scans the log, matching `ClearServerLog`'s call.
- **Simplification noted**: uses a single `self.next_serial` rather than the Delphi struct's 26-element per-client mirror — observable behavior is identical (all 26 slots stay in lockstep in the original).
- **Diagnostic logging**: `serial:` log line on every event (scan result, reservation/release with previous and new state, per-broadcast recipient list). Always on when lockout is enabled — made it possible to diagnose a "both stations got serial 4" report from log alone (lockout was disabled in the INI, which in turn disabled the TR4W client-side reservation send via `uNet.pas:1147` `if ServerSerialNumber = 0 then Exit`).
- **Known limitation**: single global counter shared across all bands. CQ WPX Multi-Unlimited requires separate sequences per band — that's a protocol + client + server change, filed upstream as TR4W issue [#913](https://github.com/n4af/TR4W/issues/913).

#### Contest type derivation (`tr4wserver.py`)

- **`get_contest_type()`** now reads `ceContest` at `CE_CONTEST_OFFSET=265` from the first QSO record (matches Delphi `SendLogFileInformation` at `tr4wserverUnit.pas:778-781`) instead of always returning `DUMMYCONTEST`. The "Difference in logs" dialog on TR4W clients now shows the real contest name.

#### Observability (`tr4wserver.py`)

- **`--trace-rx` flag** dumps every `recv()` chunk in hex and every framed message ID. For diagnosing wire-format mismatch.
- **`--log-file PATH` flag** attaches a `FileHandler` to the root logger so heartbeat, connect/disconnect, `serial:`, `--trace-rx`, etc. all tee into the file in addition to stderr/journalctl. Append mode; useful for capturing a diagnostic session for post-hoc analysis.
- **Connect/disconnect events** log to stdout regardless of `--display`, so they always reach journald.

#### Documentation

- **`README.md`**: quick-start (local + Raspberry Pi systemd), CLI flag table, INI key table including the password-change procedure, TR4W version compatibility section explaining when and how to update `LOG RECORD SIZE`, troubleshooting table.
- **`CLAUDE.md`**: source-of-truth pointers into the Delphi tree at `c:\TR4W\tr4w`, verified message-size table with `VC.pas` line refs for every entry, `{$A8}` + `{$Z1}` compiler-switch context, `ContestExchange` field offsets used by the QSO/serial logic, "things to be careful with" section covering known quirks.
- **`c:\TR4W\docs\NETWORK_LOG_AUTO_SYNC.md`** (in the TR4W repo, not this one): feature request for the TR4W client to skip the log-mismatch dialog and auto-synchronize.

---
