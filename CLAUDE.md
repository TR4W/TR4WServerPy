# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Python port of the Delphi `TR4WSERVER` — the network multi-station server for the TR4W ham radio contest logging program (original by Dmitriy Gulyaev UA4WLI, GPL v3). It is intended to run headless on a Raspberry Pi, accepting connections from TR4W client stations on the local network so they can share QSO logs, DX spots, time sync, and intercom messages.

The wire protocol and on-disk log file format are dictated by the existing TR4W Delphi clients. **This server is a protocol-compatible reimplementation, not a redesign.** Any change that alters byte layout, field offsets, or message sizing will break interoperability with unmodified TR4W clients in the field.

## Source-of-truth: the Delphi project

The protocol and record layouts live in the Delphi sources at:

- `c:\TR4W\tr4w\src\VC.pas` — all message records, all `NET_*`/`SM_*` constants, `ContestExchange`, `TLogHeader`, log version string. **Always reconcile against this file when changing wire format constants.**
- `c:\TR4W\tr4w\tr4wserver\src\tr4wserverUnit.pas` — the Delphi server unit (helper procs only — no message dispatch).
- `c:\TR4W\tr4w\tr4wserver\tr4wserver.dpr` — the Delphi server's `WM_SOCK_NET_RX` handler, which is the actual message dispatch loop. The Python `process_buffer` / `process_message` mirror its semantics.
- `c:\TR4W\tr4w\tr4wserver\tr4wserver.cfg` — Delphi compiler switches. The two that affect on-wire sizes are **`-$A8` (8-byte alignment, applies to non-`packed` records like `ContestExchange` and `TSpotRecord`)** and **`-$Z1` (`{$MINENUMSIZE 1}`, all enums are 1 byte)**.

The TR4W repo at `c:\TR4W` is a git checkout — `git -C c:\TR4W log -- tr4w/src/VC.pas` is the authoritative history of layout changes that this port must track.

## Run / develop / deploy

There is no build, no test suite, and no dependency file — the server uses only Python 3 standard library.

- Run locally for development: `python3 tr4wserver.py`
- Override config from CLI: `python3 tr4wserver.py -c <ini> -p <port> --password <pw>`
- Interactive console while running: `s` prints status, `q` quits.
- Deploy on Raspberry Pi: `./install.sh` rewrites `tr4wserver.service` to point at the current directory, copies it to `/etc/systemd/system/`, enables, and starts it. The unit file as committed hard-codes `User=pi` and `/home/pi/tr4wserverpy` — `install.sh` only patches the path, not the user.
- Service logs: `sudo journalctl -u tr4wserver -f`

Runtime artifacts (`SERVERLOG.TRW`, `tr4wserver.ini`) are gitignored (`*.ini` and `SERVERLOG.TRW`) and created on first run. The repo tracks a documented template, `tr4wserver.ini.sample`.

**Config resolution** (`resolve_config_path` in `tr4wserver.py`): an explicit `-c/--config` path wins outright; otherwise the server searches most-specific-first — `<program dir>/tr4wserver.ini`, then `~/.config/tr4wserver.ini` — mirroring `git config` precedence. The first that exists is used; if neither exists the default is created in the **program directory** (the script's own directory, via `__file__`, not necessarily CWD). `SERVERLOG.TRW` is still created relative to CWD; under the shipped systemd unit (`WorkingDirectory` = program dir) the two coincide.

## Architecture

Single file, single class (`TR4WServer` in `tr4wserver.py`). The shape is:

- **Two listening sockets**, both opened in `start()`:
   - `port` (default 1061) — the main message bus. Clients authenticate with a 10-byte password, then exchange fixed-size binary records.
   - `port + 1` — the "sync" port. A client connects, sends the password, receives a 4-byte little-endian log size followed by the raw `SERVERLOG.TRW` bytes. Used by clients to bulk-download the server's log on join or after a CRC mismatch.
- **Thread-per-connection**: `accept_clients` / `accept_sync_clients` spawn daemon threads (`handle_new_client`, `handle_sync_client`). Up to `MAX_CLIENTS = 26`. Shared state is guarded by `clients_lock` (the client dict) and `log_lock` (file I/O on `SERVERLOG.TRW`).
- **Message dispatch**: `handle_client` -> `process_buffer` -> `process_message`. The parser reads a 2-byte little-endian message ID, looks up the fixed size in `self.message_sizes`, waits for that many bytes, then dispatches. Most message types are simply rebroadcast to other clients; `NET_QSOINFO_ID` / `NET_OFFLINEQSO_ID` / `NET_EDITEDQSO_ID` also mutate the log file.
- **Special framing case**: a 4-byte `NET_LOGINFO_MESSAGE` sentinel is detected before the 2-byte ID lookup and triggers `send_log_file_info`. This is checked inside the same loop, so don't reorder that block. The Delphi version checks this *between* messages rather than before each one — both work because no real message ID's low word collides with the sentinel's low word.
- **Log file** (`SERVERLOG.TRW`): a fixed-size header (same byte size as `ContestExchange`) followed by N packed `ContestExchange` records. The header begins `v1.7\0 \r\n` (`LOGVERSION1..4` from `VC.pas:187`). CRC32 of the whole file is sent to clients on connect and recomputed lazily via the `server_crc32_changed` flag.

## Wire-format constants — verified values

All sizes below are derived from the current `VC.pas` and `tr4wserver.cfg`, treating each record's compiler-determined size (packed records = byte-summed; `ContestExchange` and `TSpotRecord` = field-aligned to multiples of 4 under `{$A8}`). Any change in `VC.pas` to one of these records must be re-reconciled here.

| ID                       | Size | Delphi type & alignment notes |
|--------------------------|-----:|-------------------------------|
| `NET_MESSAGESTATE_ID`    |   64 | `TMessageState` (packed): 2+2+1+59 |
| `NET_STATIONSTATUS_ID`   |   46 | `TStationState` (packed): 2+2+1+1+1+1+4+13+9+1+11. Was 35 before commit `6708783` added `ssOperator: OperatorType` (Issue #770, 2026-04-17). |
| `NET_NETWORKDXSPOT_ID`   |   98 | `TNetDXSpot` (packed): 2 + `SizeOf(TSpotRecord)`=96. `TSpotRecord` is a non-packed `record` and pads to 96 under `{$A8}`. |
| `NET_TIMESYN_ID`         |   20 | `TNetTimeSync` (packed): 2 + 16 (`SYSTEMTIME`) + 1 + 1 |
| `NET_PARAMETER_ID`       |  514 | `TParameterToNetwork` (packed): 2 + 256 + 256 (`ShortString` = length byte + 255 chars) |
| `NET_INTERCOMMESSAGE_ID` |   84 | `TIntercomMessage` (packed): 2 + 1 + 81 (`Str80` = length byte + 80 chars) |
| `NET_EDITEDQSO_ID`       |  384 | `TNetQSOInformation` (packed): 2 + 376 + 4 + 1 + 1 |
| `NET_OFFLINEQSO_ID`      |  384 | same |
| `NET_QSOINFO_ID`         |  384 | same |
| `NET_CLIENTSTATUS_ID`    |    3 | `TClientStatus` (packed): 2 + 1 |
| `NET_SPOTVIANETWORK_ID`  |   48 | `TSendSpotViaNetwork` (packed): 2 + 46 |
| `NET_COMPUTERID_ID`      |    4 | `TComputerNetID` (packed): 2 + 1 + 1 |
| `NET_SERVERMESSAGE_ID`   |    8 | `TServerMessage` (packed): 2 + 2 + 4 |

**`SizeOf(ContestExchange) = 376` bytes** under `{$A8}`. This is the on-disk record size in `SERVERLOG.TRW`. Verified against the deployed `c:\TR4W\tr4w\tr4wserver\SERVERLOG.TRW` (2256 bytes = 6 records). The Python port exposes this as the configurable `LOG RECORD SIZE` INI key (defaulting to 376) and validates it against the existing log file at startup, refusing to run on mismatch — same behavior as Delphi at `tr4wserver.dpr:70`.

**`NET_LOGINFO_MESSAGE = 3030002000`** (= `0xB49A2950`, bytes `50 29 9A B4` little-endian). From `VC.pas:2644`. **Not** the ASCII string `'GHTR'` — the prior Python comment claiming that was incorrect.

**`TLogFileInformation`** (sent by the server to every client on connect, packed, 19 bytes):
1. `liID: Word` (= `NET_LOGCOMPARE_ID = 1010`)
2. `liSeverCRC32: Cardinal`  *(sic, "Sever" not "Server" — verbatim from VC.pas:1494)*
3. `liLocalCRC32: Cardinal`  (server sends 0)
4. `liServerLogSize: Cardinal`
5. `liLocalLogSize: Cardinal`  (server sends 0)
6. `liContest: ContestType`  (1-byte enum, read from first QSO record)

## Things to be careful with

- **Sizes are derived, not invented.** Every entry in the `MESSAGE_SIZES` table maps to a concrete record in `VC.pas`. If you change one, comment the `VC.pas` line you reconciled against. Don't add fudge factors to make a number "feel right."
- **`ContestExchange` is not `packed`**, so `{$A8}` alignment matters. Field offsets within it (used by `update_qso_in_log` to find `ceQSOID1`/`ceQSOID2`, and by `_scan_log_for_serials` to find `NumberSent`) are:
   - `tSysTime`(0..5) + `Band`(6) + `Mode`(7) + `ceQSOID1`(8..11) + `ceQSOID2`(12..15) — tightly packed because `ceQSOID1` lands on a natural 4-byte boundary;
   - `NumberSent`(204..207) — the `CE_NUMBER_SENT_OFFSET` constant. A walk of every preceding field is documented in the constant's comment; any TR4W release that adds or reorders fields **before** `NumberSent` shifts this and must be re-derived.
  Do not assume the same kind of "no padding" elsewhere in the record.
- **All multi-byte fields are little-endian** (`<` in `struct` format strings). Delphi on x86 produces little-endian packed records; do not switch to network byte order anywhere.
- **Bare `except:` clauses are widespread** (especially around socket sends and file I/O). They mirror the original Delphi swallow-and-continue behavior so one dead client doesn't kill broadcasts. Don't tighten these without thinking about which exceptions you actually want to surface — but new code should prefer narrow `except OSError:` over bare except.
- **No graceful shutdown of the accept threads.** `stop()` closes the sockets, which raises in `accept()`; the daemon threads then exit when the process does. This is fine for the systemd `Restart=always` model but means there's no clean unit-test teardown story.
- **`forward_spot_to_telnet_client` only sends to the first client with `connected_to_telnet=True`** — that's intentional (the spot is forwarded to the one station that has the upstream telnet/cluster connection), not a bug to "fix" by broadcasting.
- **Unknown message IDs disconnect the offending client** (rather than silently break out of parsing). This is more aggressive than the Delphi server, which falls through silently — but the Delphi behavior risks an infinite reparse loop, and a noisy disconnect here makes layout drift visible immediately.

## Coding standards (from user globals)

Python: 3-space indentation, spaces only. Readability over brevity. The existing file uses 4-space indentation throughout — match the surrounding style when editing existing functions; apply the 3-space rule to new files only, and flag any larger reformat as a separate change rather than mixing it into a feature edit.
