#!/usr/bin/env python3
"""
TR4WSERVER - Python implementation for Raspberry Pi
A network server for TR4W ham radio logging application.

This is a Python port of the original Delphi TR4WSERVER.
Licensed under GPL v3 (same as original TR4W project).

Original copyright: Dmitriy Gulyaev UA4WLI 2015
Python port: 2025
"""

import socket
import struct
import threading
import configparser
import concurrent.futures
import os
import signal
import sys
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('TR4WSERVER')

# ----------------------------------------------------------------------------
# Resilience tuning
# ----------------------------------------------------------------------------
# All time values in seconds. Set high enough not to disconnect idle but
# legitimate contest stations, low enough to detect truly dead peers.
SOCKET_RECV_TIMEOUT      = 300   # 5 min — boots silent/dead clients
SOCKET_SEND_TIMEOUT      = 30    # send blocked >30s ⇒ slow consumer, drop it
HOSTNAME_LOOKUP_TIMEOUT  = 2     # bound on synchronous DNS during accept
PASSWORD_RECV_TIMEOUT    = 10    # initial handshake — short, not 5 min
HEARTBEAT_INTERVAL       = 60    # log a one-line stats heartbeat every minute
DISPLAY_REFRESH_INTERVAL = 2     # interactive --display redraw cadence
# Largest legitimate message is NET_PARAMETER_ID (514 bytes); anything past
# this in a single un-framed buffer means we're out of sync with the client.
MAX_CLIENT_BUFFER        = 8192

# ============================================================================
# Protocol Constants (from VC.pas)
# ============================================================================

# Network Message IDs
NET_MESSAGESTATE_ID = 1000
NET_LOGCOMPARE_ID = 1010
NET_INTERCOMMESSAGE_ID = 1020
NET_NETWORKDXSPOT_ID = 1030
NET_QSOINFO_ID = 1040
NET_EDITEDQSO_ID = 1050
NET_OFFLINEQSO_ID = 1055
NET_THIS_QTC_WAS_SEND_ID = 1056
NET_TAKESERVERQSO_ID = 1060
NET_TIMESYN_ID = 1070
NET_PARAMETER_ID = 1080
NET_STATIONSTATUS_ID = 1090
NET_CLIENTSTATUS_ID = 1110
NET_SPOTVIANETWORK_ID = 1120
NET_COMPUTERID_ID = 1130
NET_SERVERMESSAGE_ID = 1140
# 4-byte sentinel a client sends to ask for an updated TLogFileInformation.
# Value is verbatim from VC.pas:2644 — bytes are 50 29 9A B4 little-endian
# (NOT the ASCII string "GHTR" that an earlier version of this file claimed).
NET_LOGINFO_MESSAGE = 3030002000

# Server Message Types
SM_CLEARALLLOGS_MESSAGE = 8230
SM_SERVERLOG_CHANGED_MESSAGE = 8250
SM_DISCONECT_CLIENT_MESSAGE = 8260
SM_GETSTATUS_MESSAGE = 8270
SM_CLEAR_DUPESHEET_MESSAGE = 8280
SM_CLEAR_MULTSHEET_MESSAGE = 8290
SM_RECEIVED_UPDATED_QSO_MESSAGE = 8300
SM_SERIAL_NUMBER_CHANGED = 8310

# Server Constants
MAX_CLIENTS = 26
DEFAULT_PORT = 1061
SERVER_VERSION = "TR4WSERVER Python 1.0"
SEND_TR4W = b'TR4W'
PASS_TR4W = b'PASS'

# Dummy contest ID used when log is empty
DUMMYCONTEST = 0

# ============================================================================
# Data Structures
# ============================================================================

# Default SizeOf(ContestExchange) for a Delphi build with {$A8} alignment as of
# log format v1.7 (VC.pas:190 LOGVERSION4='7'). The Delphi compiler computes
# this at build time; we have to track it. Override in tr4wserver.ini if you
# are talking to clients built against a different VC.pas. The startup check in
# init_log_file refuses to run if the existing SERVERLOG.TRW is not a multiple
# of this value (matches Delphi tr4wserver.dpr:70-83).
DEFAULT_LOG_RECORD_SIZE = 376


class UnknownMessageError(Exception):
    """Raised when an inbound message ID isn't in self.message_sizes.

    The Delphi server falls through silently on unknown IDs, which risks an
    infinite reparse loop on layout drift. We disconnect that one client
    instead so the mismatch is visible in the logs."""


# Errors that mean "this one client is gone or unresponsive — drop it,
# don't propagate." Anything else is logged as unexpected.
_DEAD_CLIENT_ERRORS = (
    socket.timeout,
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
    OSError,  # catches "Bad file descriptor", "Transport endpoint not connected"
)


def _cstring(buf: bytes) -> str:
    """Decode a fixed-length null-terminated C string field. TR4W writes ASCII
    callsigns/operator/name; treat anything else as garbage rather than
    raising and tearing down the connection."""
    end = buf.find(b'\x00')
    if end >= 0:
        buf = buf[:end]
    return buf.decode('ascii', errors='replace').rstrip()


def _safe_sendall(sock: socket.socket, data: bytes) -> bool:
    """sendall with the dead-client errors swallowed.

    Returns True on success, False if the peer is gone or too slow. Callers
    that broadcast use the False return to mark the socket for cleanup;
    callers replying to one client can ignore it."""
    try:
        sock.sendall(data)
        return True
    except _DEAD_CLIENT_ERRORS:
        return False


@dataclass
class TServerMessage:
    """Server message structure (8 bytes)"""
    sm_id: int = NET_SERVERMESSAGE_ID  # Word (2 bytes)
    sm_message: int = 0  # Word (2 bytes)
    sm_param: int = 0  # Integer (4 bytes)

    def pack(self) -> bytes:
        return struct.pack('<HHi', self.sm_id, self.sm_message, self.sm_param)

    @classmethod
    def unpack(cls, data: bytes) -> 'TServerMessage':
        sm_id, sm_message, sm_param = struct.unpack('<HHi', data[:8])
        return cls(sm_id, sm_message, sm_param)


@dataclass
class TLogFileInformation:
    """Log file information packet (sent server->client on connect or LOGINFO ping).

    Wire layout from VC.pas:1492 (packed record, 19 bytes total). Field name
    'liSeverCRC32' is verbatim Delphi (typo carried from upstream)."""
    li_id: int = NET_LOGCOMPARE_ID  # Word, always NET_LOGCOMPARE_ID
    li_sever_crc32: int = 0  # Cardinal
    li_local_crc32: int = 0  # Cardinal — server always sends 0
    li_server_log_size: int = 0  # Cardinal
    li_local_log_size: int = 0  # Cardinal — server always sends 0
    li_contest: int = 0  # ContestType, 1-byte enum

    def pack(self) -> bytes:
        return struct.pack('<HIIIIB',
                           self.li_id,
                           self.li_sever_crc32,
                           self.li_local_crc32,
                           self.li_server_log_size,
                           self.li_local_log_size,
                           self.li_contest)


SIZE_OF_LOG_FILE_INFORMATION = 19  # struct.calcsize('<HIIIIB')


@dataclass
class ClientEntry:
    """Connected-client state. Most fields are populated lazily as the station
    broadcasts its TStationState packets — until then they stay at the defaults
    and render as blank in the status display."""
    conn: object = None                       # socket.socket
    ip_address: str = ""
    hostname: str = ""
    computer_id: str = ""                     # display letter A..Z
    connected_to_telnet: bool = False
    serial_number: int = 0
    serial_number_status: int = 0             # 0=Free, 1=Reserved

    # Live status, sourced from TStationState (NET_STATIONSTATUS_ID) packets.
    name: str = ""                            # ssName  (sstComputerNameAndID)
    band: Optional[int] = None                # ssCurrentBand index (sstBandModeFreq)
    mode: Optional[int] = None                # ssCurrentMode index (sstBandModeFreq)
    freq_hz: int = 0                          # ssFreq             (sstBandModeFreq)
    qsos: int = 0                             # ssQSOTotals        (sstQSOs)
    callsign: str = ""                        # ssCallsign         (sstCallsign)
    operator: str = ""                        # ssOperator         (sstOperator)
    ptt_on: bool = False                      # bit 0 of ssStatusByte
    sp_mode: bool = False                     # bit 1 (0=CQ/Run, 1=S&P)
    dupe: bool = False                        # bit 2 (call window shows dupe)


# StationStatusType enum values (VC.pas:1360). Order matters — index = ssType byte.
SST_COMPUTER_NAME_AND_ID = 0
SST_BAND_MODE_FREQ       = 1
SST_PTT                  = 2
SST_OP_MODE              = 3
SST_QSOS                 = 4
SST_CALLSIGN             = 5
SST_OPERATOR             = 6

# Status-byte bit layout (uNet.pas:169).
STATUS_BIT_PTT          = 1 << 0
STATUS_BIT_SP_MODE      = 1 << 1
STATUS_BIT_DUPE         = 1 << 2
STATUS_BIT_PTT_LOCKOUT  = 1 << 3

# Display strings for the BandType / ModeType enums. Index = enum value.
# Mirrors VC.pas:1275 (BandStringsArrayWithOutSpaces) and VC.pas:1239
# (ModeStringArray). Update if BandType in VC.pas gains entries — order is
# load-bearing because the wire format sends the raw enum index.
BAND_NAMES = [
    '160','80','40','20','15','10','30','17','12','6','2',
    '222','432','902','1GH','2GH','3GH','5GH','10G','24G','LGT','All','NON',
]
MODE_NAMES = ['CW', 'DIGI', 'SSB', 'BTH', 'NON', 'FM']


# ============================================================================
# Message size table
# ============================================================================
#
# Sizes are derived from the current Delphi VC.pas record definitions and the
# tr4wserver.cfg compiler switches ({$A8} alignment, {$Z1} 1-byte enums). All
# message records except the QSO/spot ones are `packed record`s so their size
# is just the byte sum of their fields. ContestExchange and TSpotRecord are
# unpacked, so they pad to multiples of 4 under {$A8}.
#
# Re-verify against VC.pas after any field add — the Delphi server gets the
# new size for free via SizeOf(...) at compile time, but this Python port has
# to be updated explicitly. See CLAUDE.md for the full table.
def _build_message_sizes(log_record_size: int) -> Dict[int, int]:
   net_qso_info_size = log_record_size + 8  # TNetQSOInformation: 2+CE+4+1+1
   return {
      NET_MESSAGESTATE_ID:    64,   # TMessageState (VC.pas:407)
      NET_STATIONSTATUS_ID:   46,   # TStationState (VC.pas:1362; +ssOperator from commit 6708783)
      NET_NETWORKDXSPOT_ID:   98,   # TNetDXSpot (VC.pas:1976) = 2 + SizeOf(TSpotRecord)=96
      NET_TIMESYN_ID:         20,   # TNetTimeSync (VC.pas:1995)
      NET_PARAMETER_ID:      514,   # TParameterToNetwork (VC.pas:2006) = 2 + 256 + 256
      NET_INTERCOMMESSAGE_ID: 84,   # TIntercomMessage (VC.pas:2013) = 2 + 1 + 81 (Str80)
      NET_EDITEDQSO_ID:       net_qso_info_size,
      NET_OFFLINEQSO_ID:      net_qso_info_size,
      NET_QSOINFO_ID:         net_qso_info_size,
      NET_CLIENTSTATUS_ID:     3,   # TClientStatus (VC.pas:1384) = 2 + 1
      NET_SPOTVIANETWORK_ID:  48,   # TSendSpotViaNetwork (VC.pas:1475) = 2 + 46
      NET_COMPUTERID_ID:       4,   # TComputerNetID (VC.pas:1483)
      NET_SERVERMESSAGE_ID:    8,   # TServerMessage (VC.pas:2020)
   }


# ============================================================================
# TR4W Server Implementation
# ============================================================================

class TR4WServer:
    """TR4W Network Server for multi-station ham radio logging"""

    def __init__(self, config_file: str = "tr4wserver.ini"):
        self.config_file = config_file
        self.port = DEFAULT_PORT
        self.password = "TR4WSERVER"
        self.allow_time_sync = True
        self.serial_number_lockout = False
        self.log_record_size = DEFAULT_LOG_RECORD_SIZE
        self.trace_rx = False  # set by --trace-rx; dumps raw recvs + frames

        self.clients: Dict[socket.socket, ClientEntry] = {}
        self.clients_lock = threading.Lock()

        self.server_socket: Optional[socket.socket] = None
        self.sync_socket: Optional[socket.socket] = None
        self.running = False
        self._stop_event = threading.Event()  # signals heartbeat/display loops

        self.log_file_path = "SERVERLOG.TRW"
        self.log_lock = threading.Lock()

        self.bytes_received = 0
        self.bytes_sent = 0

        self.server_crc32 = 0
        self.server_crc32_changed = True

        # Bounded thread pool keeps slow reverse-DNS off the accept hot path.
        self._resolver = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix='dns'
        )

        self.load_config()
        # Built after config so the QSO message size tracks log_record_size.
        self.message_sizes = _build_message_sizes(self.log_record_size)
        self.init_log_file()

    def load_config(self):
        """Load configuration from INI file. Bad INI ⇒ log + use defaults
        rather than refusing to start; the server will at least be reachable
        on the default port."""
        if not os.path.exists(self.config_file):
            self.save_config()
            logger.info(f"Created default configuration: {self.config_file}")
            return

        config = configparser.ConfigParser()
        try:
            config.read(self.config_file)
        except configparser.Error as e:
            logger.error(f"Cannot parse {self.config_file}: {e}. Using defaults.")
            return

        section = 'TR4WSERVER'
        if section not in config:
            logger.warning(f"{self.config_file} missing [{section}] section. Using defaults.")
            return

        try:
            self.port = config.getint(section, 'PORT', fallback=DEFAULT_PORT)
            self.password = config.get(section, 'SERVER PASSWORD', fallback='TR4WSERVER')
            self.allow_time_sync = config.getint(section, 'ALLOW TIME SYNCHRONIZING', fallback=1) == 1
            self.serial_number_lockout = config.getint(section, 'SERIAL NUMBER LOCKOUT', fallback=0) == 1
            self.log_record_size = config.getint(section, 'LOG RECORD SIZE', fallback=DEFAULT_LOG_RECORD_SIZE)
        except (ValueError, configparser.Error) as e:
            logger.error(f"Bad value in {self.config_file}: {e}. Using defaults for affected keys.")

        logger.info(f"Configuration loaded from {self.config_file}")

    def save_config(self):
        """Save configuration to INI file"""
        config = configparser.ConfigParser()
        config['TR4WSERVER'] = {
            'PORT': str(self.port),
            'SERVER PASSWORD': self.password,
            'ALLOW TIME SYNCHRONIZING': '1' if self.allow_time_sync else '0',
            'SERIAL NUMBER LOCKOUT': '1' if self.serial_number_lockout else '0',
            'LOG RECORD SIZE': str(self.log_record_size),
        }
        with open(self.config_file, 'w') as f:
            config.write(f)

    def init_log_file(self):
        """Initialize/validate the server log file.

        Refuses to start if an existing SERVERLOG.TRW is not a multiple of
        log_record_size — that almost always means the Delphi side grew a
        ContestExchange field and this Python port hasn't caught up. Same
        check Delphi does at tr4wserver.dpr:70."""
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, 'wb') as f:
                f.write(self.create_log_header())
            logger.info(f"Created new log file: {self.log_file_path} "
                        f"(record size {self.log_record_size})")
            return

        size = os.path.getsize(self.log_file_path)
        if size == 0:
            with open(self.log_file_path, 'wb') as f:
                f.write(self.create_log_header())
            logger.info(f"Wrote header to empty log file: {self.log_file_path}")
            return

        if size % self.log_record_size != 0:
            raise RuntimeError(
                f"{self.log_file_path} size {size} is not a multiple of the "
                f"configured LOG RECORD SIZE={self.log_record_size}. This "
                f"usually means the Delphi ContestExchange layout has changed. "
                f"Either update LOG RECORD SIZE in {self.config_file} to match "
                f"the current SizeOf(ContestExchange) from VC.pas, or delete "
                f"{self.log_file_path} to start fresh."
            )

    def create_log_header(self) -> bytes:
        """Create log file header (same byte size as ContestExchange).

        Layout from VC.pas:4023 (LogHeader constant): 8B version string +
        16B file desc + 36B warning + zero pad to log_record_size."""
        version_string = b'v1.7\x00 \r\n'           # LOGVERSION1..4 + pad (VC.pas:187-190)
        file_desc      = b'TR4W LOG FILE \r\n'      # 16 bytes
        warning        = b'WARNING: DO NOT EDIT THIS FILE!\r\n\r\n\x00'  # 36 bytes
        dummy          = b'\x00' * (self.log_record_size - 60)
        return version_string + file_desc + warning + dummy

    def get_log_size(self) -> int:
        """Get current log file size"""
        try:
            return os.path.getsize(self.log_file_path)
        except:
            return 0

    def get_qso_count(self) -> int:
        """Get number of QSOs in log"""
        size = self.get_log_size()
        if size <= self.log_record_size:
            return 0
        return (size - self.log_record_size) // self.log_record_size

    def calculate_log_crc32(self) -> int:
        """Streaming CRC32 of SERVERLOG.TRW. Cached until server_crc32_changed
        flips back to True. Streaming keeps RAM use bounded for multi-day
        contests on a Pi."""
        if not self.server_crc32_changed:
            return self.server_crc32

        crc = 0
        try:
            with open(self.log_file_path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    crc = zlib.crc32(chunk, crc)
            self.server_crc32 = crc & 0xFFFFFFFF
            self.server_crc32_changed = False
        except OSError as e:
            logger.error(f"CRC32 of {self.log_file_path} failed: {e}")
            self.server_crc32 = 0

        return self.server_crc32

    def check_password(self, data: bytes) -> bool:
        """Verify client password"""
        # Handle HTTP-style password (GET /PASS ...)
        if len(data) > 10 and data[:4] == b'GET ' and data[6:10] == b'PASS':
            password_bytes = data[11:21]
        else:
            password_bytes = data[:10]

        expected = self.password.encode('ascii').ljust(10, b'\x00')[:10]
        return password_bytes == expected

    def start(self):
        """Start the server. Bind/listen failures are surfaced loudly so
        systemd's restart loop has something useful in journalctl."""
        try:
            self.server_socket = self._make_listener(self.port, MAX_CLIENTS)
            self.sync_socket   = self._make_listener(self.port + 1, MAX_CLIENTS)
        except OSError as e:
            logger.critical(
                f"Cannot bind to port {self.port}/{self.port + 1}: {e}. "
                f"Is another tr4wserver already running?"
            )
            raise

        self.running = True
        self._stop_event.clear()

        # Server's own IP, just for the startup banner.
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip_address = "0.0.0.0"

        logger.info(f"{SERVER_VERSION}")
        logger.info(f"Server IP: {ip_address}")
        logger.info(f"Listening on port {self.port} (main) and {self.port + 1} (sync)")
        logger.info(f"Log file: {self.log_file_path} ({self.get_qso_count()} QSOs)")

        threading.Thread(target=self.accept_clients,      daemon=True, name='accept-main').start()
        threading.Thread(target=self.accept_sync_clients, daemon=True, name='accept-sync').start()
        threading.Thread(target=self._heartbeat_loop,     daemon=True, name='heartbeat').start()

    def _make_listener(self, port: int, backlog: int) -> socket.socket:
        """Create+bind+listen on a port. Caller handles OSError."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(backlog)
        return s

    def _heartbeat_loop(self):
        """Periodic single-line stats so a hung server is visible in journalctl
        even when no clients are talking. Uses Event.wait so it exits promptly
        on shutdown."""
        while self.running:
            if self._stop_event.wait(HEARTBEAT_INTERVAL):
                return
            with self.clients_lock:
                n = len(self.clients)
            logger.info(
                f"heartbeat clients={n}/{MAX_CLIENTS} "
                f"qsos={self.get_qso_count()} "
                f"rx={self.bytes_received} tx={self.bytes_sent}"
            )

    def accept_clients(self):
        """Accept incoming client connections on main port"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_new_client,
                    args=(client_socket, addr),
                    daemon=True,
                    name=f'client-{addr[0]}',
                ).start()
            except OSError as e:
                if self.running:
                    logger.error(f"Accept error: {e}")
                    # Brief backoff so a recurring EMFILE etc doesn't tight-loop.
                    time.sleep(0.5)

    def accept_sync_clients(self):
        """Accept incoming sync connections for log file transfer"""
        while self.running:
            try:
                client_socket, addr = self.sync_socket.accept()
                threading.Thread(
                    target=self.handle_sync_client,
                    args=(client_socket, addr),
                    daemon=True,
                    name=f'sync-{addr[0]}',
                ).start()
            except OSError as e:
                if self.running:
                    logger.error(f"Sync accept error: {e}")
                    time.sleep(0.5)

    def handle_new_client(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Authenticate a new client and hand it to handle_client.

        Authentication uses a short, separate timeout — we don't want a hung
        TCP-handshake-only attacker to occupy a client slot for 5 minutes.

        We deliberately receive EXACTLY the password length (10 bytes for the
        normal form, 21 if the client uses the legacy GET /PASS HTTP form).
        The Delphi server does the same. Reading more than that would drain
        the kernel TCP buffer of bytes that belong to the first post-handshake
        message — we'd silently lose them, since check_password discards
        anything past the password."""
        registered = False
        try:
            client_socket.settimeout(PASSWORD_RECV_TIMEOUT)
            time.sleep(0.2)  # mirrors the Delphi server's 200ms settle delay

            try:
                data = self._recv_exact(client_socket, 10)
            except _DEAD_CLIENT_ERRORS as e:
                logger.info(f"Client {addr[0]} disconnected during auth: {e}")
                return
            if data is None:
                return
            # Legacy "GET /PASS XXXXXXXXXX" form: pull the remaining 11 bytes.
            if data[:4] == b'GET ':
                tail = self._recv_exact(client_socket, 11)
                if tail is None:
                    return
                data += tail

            if not self.check_password(data):
                _safe_sendall(client_socket, PASS_TR4W)
                logger.info(f"Client {addr[0]} - invalid password")
                return

            if not _safe_sendall(client_socket, SEND_TR4W):
                return

            # Switch to operational timeouts (long recv, modest send).
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_socket.settimeout(SOCKET_RECV_TIMEOUT)
            self._set_send_timeout(client_socket, SOCKET_SEND_TIMEOUT)

            hostname = self._reverse_dns(addr[0])

            with self.clients_lock:
                if len(self.clients) >= MAX_CLIENTS:
                    logger.warning(f"Max clients reached, rejecting {addr[0]}")
                    return
                self.clients[client_socket] = ClientEntry(
                    conn=client_socket, ip_address=addr[0], hostname=hostname,
                )
                registered = True
                total = len(self.clients)

            logger.info(f"Client connected: {addr[0]} ({hostname}) - Total: {total}")
            self.send_log_file_info(client_socket)
            self.handle_client(client_socket)

        except _DEAD_CLIENT_ERRORS as e:
            logger.info(f"Client {addr[0]} dropped: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error handling new client {addr[0]}: {e}")
        finally:
            if registered:
                self.remove_client(client_socket)
            else:
                try:
                    client_socket.close()
                except OSError:
                    pass

    def _reverse_dns(self, ip: str) -> str:
        """Reverse-DNS lookup with a hard 2s ceiling. Slow resolvers used to
        block the per-connection thread for the full system DNS timeout
        (often 30s); this caps that without losing the hostname when it
        resolves quickly."""
        future = self._resolver.submit(socket.gethostbyaddr, ip)
        try:
            return future.result(timeout=HOSTNAME_LOOKUP_TIMEOUT)[0]
        except (concurrent.futures.TimeoutError, OSError, IndexError):
            return "?"

    @staticmethod
    def _set_send_timeout(sock: socket.socket, seconds: int):
        """Apply SO_SNDTIMEO without disturbing the recv timeout. Falls back
        silently on platforms (or platforms' Python builds) that don't expose
        the option — the recv timeout still bounds the worst case."""
        try:
            timeval = struct.pack('@ll', seconds, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, timeval)
        except (OSError, AttributeError):
            pass

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes or return None if the peer closed.

        Used for the password handshake where over-reading the kernel buffer
        would silently drop bytes from the first real message."""
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def handle_sync_client(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Send the full SERVERLOG.TRW to a sync client. Bounded by socket
        timeouts so a slow consumer can't hold log_lock indefinitely."""
        client_socket.settimeout(PASSWORD_RECV_TIMEOUT)
        self._set_send_timeout(client_socket, SOCKET_SEND_TIMEOUT)
        try:
            time.sleep(0.05)

            try:
                data = self._recv_exact(client_socket, 10)
            except _DEAD_CLIENT_ERRORS as e:
                logger.info(f"Sync client {addr[0]} dropped during auth: {e}")
                return
            if data is None:
                return
            if data[:4] == b'GET ':
                tail = self._recv_exact(client_socket, 11)
                if tail is None:
                    return
                data += tail
            if not self.check_password(data):
                return

            with self.log_lock:
                log_size = self.get_log_size()

                if not _safe_sendall(client_socket, struct.pack('<I', log_size)):
                    logger.warning(f"Sync client {addr[0]} disconnected before header")
                    return

                with open(self.log_file_path, 'rb') as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        if not _safe_sendall(client_socket, chunk):
                            logger.warning(f"Sync client {addr[0]} disconnected mid-transfer")
                            return
                        self.bytes_sent += len(chunk)

            logger.info(f"Sent log file to {addr[0]} ({log_size} bytes)")

        except OSError as e:
            logger.error(f"Sync client {addr[0]} I/O error: {e}")
        except Exception as e:
            logger.exception(f"Unexpected sync client error for {addr[0]}: {e}")
        finally:
            try:
                client_socket.close()
            except OSError:
                pass

    def handle_client(self, client_socket: socket.socket):
        """Drain messages from a connected client until it disconnects, times
        out, or sends garbage. Buffer is capped — if it grows past the cap
        we're out of sync with the client and trying to recover would risk
        log corruption."""
        buffer = b''
        peer = None
        if self.trace_rx:
            try: peer = client_socket.getpeername()[0]
            except OSError: peer = '?'

        while self.running:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break  # clean FIN from peer

                self.bytes_received += len(data)
                buffer += data

                if self.trace_rx:
                    logger.info(f"RX[{peer}] +{len(data)}B buf={len(buffer)}B "
                                f"head: {data[:64].hex(' ')}")

                if len(buffer) > MAX_CLIENT_BUFFER:
                    raise UnknownMessageError(
                        f"buffer overflow ({len(buffer)} bytes accumulated, cap "
                        f"{MAX_CLIENT_BUFFER}); message_sizes likely out of sync"
                    )

                buffer = self.process_buffer(client_socket, buffer)

            except UnknownMessageError as e:
                # Layout drift between this server and the client. Disconnect
                # rather than silently dropping bytes — a stale message_sizes
                # entry would otherwise cause an infinite reparse loop.
                logger.error(f"Disconnecting client: {e}")
                break
            except socket.timeout:
                logger.info(f"Client idle for >{SOCKET_RECV_TIMEOUT}s, disconnecting")
                break
            except _DEAD_CLIENT_ERRORS as e:
                logger.info(f"Client connection lost: {e}")
                break
            except Exception as e:
                logger.exception(f"Unexpected client handler error: {e}")
                break

    def process_buffer(self, client_socket: socket.socket, buffer: bytes) -> bytes:
        """Process received data buffer and return remaining data"""
        while len(buffer) >= 2:
            # NET_LOGINFO_MESSAGE is a 4-byte sentinel. Check it first because
            # its low Word doesn't collide with any real message ID.
            if len(buffer) >= 4:
                dword = struct.unpack('<I', buffer[:4])[0]
                if dword == NET_LOGINFO_MESSAGE:
                    self.send_log_file_info(client_socket)
                    buffer = buffer[4:]
                    continue

            msg_id = struct.unpack('<H', buffer[:2])[0]
            msg_size = self.message_sizes.get(msg_id)
            if msg_size is None or msg_size <= 0:
                # First 32 bytes (was 16) — gives more context for diagnosing
                # layout drift / mid-stream desync.
                preview = buffer[:32].hex(' ')
                raise UnknownMessageError(
                    f"unknown or zero-size message ID {msg_id} (0x{msg_id:04x}); "
                    f"buffer head: {preview}"
                )

            if len(buffer) < msg_size:
                break  # Wait for more data

            if self.trace_rx:
                logger.info(f"  frame id={msg_id} (0x{msg_id:04x}) size={msg_size}")

            message = buffer[:msg_size]
            buffer = buffer[msg_size:]
            self.process_message(client_socket, msg_id, message)

        return buffer

    def process_message(self, client_socket: socket.socket, msg_id: int, data: bytes):
        """Process a complete message"""
        try:
            if msg_id == NET_MESSAGESTATE_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=True)

            elif msg_id == NET_STATIONSTATUS_ID:
                self._update_station_state(client_socket, data)
                self.broadcast_to_clients(client_socket, data, include_sender=True)

            elif msg_id == NET_NETWORKDXSPOT_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=False)

            elif msg_id == NET_TIMESYN_ID:
                if self.allow_time_sync:
                    self.broadcast_to_clients(client_socket, data, include_sender=False)

            elif msg_id == NET_PARAMETER_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=False)

            elif msg_id == NET_INTERCOMMESSAGE_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=True)

            elif msg_id == NET_EDITEDQSO_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=False)
                # Update QSO in server log
                self.update_qso_in_log(data)
                self.send_confirm_message(client_socket)

            elif msg_id == NET_OFFLINEQSO_ID:
                # Add offline QSO to log
                self.add_qso_to_log(data)
                self.send_confirm_message(client_socket)

            elif msg_id == NET_QSOINFO_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=False)
                # Add QSO to log
                self.add_qso_to_log(data)

            elif msg_id == NET_CLIENTSTATUS_ID:
                self.update_client_status(client_socket, data)

            elif msg_id == NET_SPOTVIANETWORK_ID:
                self.forward_spot_to_telnet_client(client_socket, data)

            elif msg_id == NET_COMPUTERID_ID:
                self.set_computer_id(client_socket, data)

            elif msg_id == NET_SERVERMESSAGE_ID:
                self.handle_server_message(client_socket, data)

        except Exception as e:
            logger.error(f"Error processing message {msg_id}: {e}")

    def broadcast_to_clients(self, sender: socket.socket, data: bytes, include_sender: bool = False):
        """Send `data` to every connected client (optionally including sender).

        Failed sends mark the peer for cleanup AFTER the broadcast loop —
        we don't mutate self.clients while iterating it. SOCKET_SEND_TIMEOUT
        on each socket bounds the total broadcast latency at
        N_clients * SOCKET_SEND_TIMEOUT in the worst case."""
        dead: List[socket.socket] = []
        with self.clients_lock:
            targets = [s for s in self.clients.keys()
                       if include_sender or s != sender]

        for s in targets:
            if _safe_sendall(s, data):
                self.bytes_sent += len(data)
            else:
                dead.append(s)

        for s in dead:
            self.remove_client(s)

    def send_log_file_info(self, client_socket: socket.socket):
        """Send TLogFileInformation to client (called on connect and on each
        4-byte NET_LOGINFO_MESSAGE sentinel from a client)."""
        info = TLogFileInformation()
        info.li_sever_crc32 = self.calculate_log_crc32()
        info.li_server_log_size = self.get_log_size()
        info.li_contest = self.get_contest_type()
        # li_local_crc32 / li_local_log_size remain 0 — Delphi side reads
        # them only on the client; the server never populates them.

        if _safe_sendall(client_socket, info.pack()):
            self.bytes_sent += SIZE_OF_LOG_FILE_INFORMATION

    def get_contest_type(self) -> int:
        """Read ceContest from the first QSO in the log.

        Field offset within ContestExchange: see VC.pas:1604 — ceContest sits
        in the trailing tail of the record. Without parsing the whole record
        layout we don't know the exact offset, so until that's wired we return
        DUMMYCONTEST. The Delphi server reads TempCE.ceContest by Pascal field
        access; replicating that here would require per-field accessors."""
        return DUMMYCONTEST

    def add_qso_to_log(self, data: bytes):
        """Append the embedded ContestExchange to SERVERLOG.TRW.

        Inbound `data` is a TNetQSOInformation packet: 2-byte qiID followed
        by the ContestExchange record. We slice exactly log_record_size bytes."""
        with self.log_lock:
            try:
                qso_data = data[2:2 + self.log_record_size]

                with open(self.log_file_path, 'ab') as f:
                    f.write(qso_data)
                    f.flush()
                    os.fsync(f.fileno())

                self.server_crc32_changed = True
                logger.info(f"QSO added to log. Total: {self.get_qso_count()}")

            except Exception as e:
                logger.error(f"Error adding QSO to log: {e}")

    def update_qso_in_log(self, data: bytes):
        """Find a QSO by (ceQSOID1, ceQSOID2) and overwrite it in place.

        ContestExchange field offsets used here: tSysTime[0..5], Band[6],
        Mode[7], ceQSOID1[8..11], ceQSOID2[12..15]. These four fields are
        tightly packed because ceQSOID1 (Cardinal) lands on a natural 4-byte
        boundary under {$A8} — do not assume the same throughout the record."""
        with self.log_lock:
            try:
                qso_data = data[2:2 + self.log_record_size]
                qso_id1 = struct.unpack('<I', qso_data[8:12])[0]
                qso_id2 = struct.unpack('<I', qso_data[12:16])[0]

                with open(self.log_file_path, 'r+b') as f:
                    file_size = os.path.getsize(self.log_file_path)
                    pos = file_size - self.log_record_size

                    while pos >= self.log_record_size:  # stop at the header slot
                        f.seek(pos)
                        existing = f.read(self.log_record_size)

                        existing_id1 = struct.unpack('<I', existing[8:12])[0]
                        existing_id2 = struct.unpack('<I', existing[12:16])[0]

                        if existing_id1 == qso_id1 and existing_id2 == qso_id2:
                            f.seek(pos)
                            f.write(qso_data)
                            f.flush()
                            self.server_crc32_changed = True
                            logger.info(f"QSO updated in log")
                            return

                        pos -= self.log_record_size

            except Exception as e:
                logger.error(f"Error updating QSO: {e}")

    def send_confirm_message(self, client_socket: socket.socket):
        """Send confirmation message to client"""
        msg = TServerMessage(
            sm_id=NET_SERVERMESSAGE_ID,
            sm_message=SM_RECEIVED_UPDATED_QSO_MESSAGE,
            sm_param=0
        )
        if _safe_sendall(client_socket, msg.pack()):
            self.bytes_sent += 8

    def update_client_status(self, client_socket: socket.socket, data: bytes):
        """Update client status (telnet connection, etc)"""
        with self.clients_lock:
            if client_socket in self.clients:
                # TClientStatus has telnet flag
                if len(data) >= 3:
                    self.clients[client_socket].connected_to_telnet = (data[2] != 0)

    def set_computer_id(self, client_socket: socket.socket, data: bytes):
        """Set the displayable A..Z computer ID for a client.

        TR4W sends the ID as a small integer (1 for A, 2 for B, ...) — see
        uNet.pas:662 `ComputerNetID.ciComputerID := Char(Ord(ComputerID) -
        Ord('A') + 1)`. We translate back to the human letter so the status
        display shows 'A', not '\\x01'."""
        if len(data) < 3:
            return
        n = data[2]
        letter = chr(ord('A') + n - 1) if 1 <= n <= 26 else f"?{n}"
        with self.clients_lock:
            if client_socket in self.clients:
                self.clients[client_socket].computer_id = letter

    def _update_station_state(self, sender: socket.socket, data: bytes):
        """Parse a TStationState broadcast and update the sender's live state.

        Each packet (46 bytes) only carries the subset of fields relevant to
        its ssType — other field positions hold stale data from the sender's
        struct and must not be trusted. Mirrors how the TR4W client itself
        handles incoming station-state packets (uNet.pas:DisplayClientStatus).

        Field offsets within the packed TStationState record:
          [0..1] ssID, [2..3] ssQSOTotals, [4] ssComputerID, [5] ssCurrentBand,
          [6] ssCurrentMode, [7] ssStatusByte, [8..11] ssFreq,
          [12..24] ssCallsign(13), [25..33] ssName(9), [34] ssType,
          [35..45] ssOperator(11)."""
        if len(data) < 46:
            return
        ss_type = data[34]
        with self.clients_lock:
            entry = self.clients.get(sender)
            if entry is None:
                return

            if ss_type == SST_COMPUTER_NAME_AND_ID:
                entry.name = _cstring(data[25:34])
                # ssComputerID is the raw small-int form; convert to A..Z.
                n = data[4]
                if 1 <= n <= 26:
                    entry.computer_id = chr(ord('A') + n - 1)

            elif ss_type == SST_BAND_MODE_FREQ:
                entry.band = data[5]
                entry.mode = data[6]
                entry.freq_hz = struct.unpack('<i', data[8:12])[0]

            elif ss_type in (SST_PTT, SST_OP_MODE, SST_CALLSIGN):
                # All three carry a fresh ssStatusByte.
                sb = data[7]
                entry.ptt_on = bool(sb & STATUS_BIT_PTT)
                entry.sp_mode = bool(sb & STATUS_BIT_SP_MODE)
                entry.dupe = bool(sb & STATUS_BIT_DUPE)
                if ss_type == SST_CALLSIGN:
                    entry.callsign = _cstring(data[12:25])

            elif ss_type == SST_QSOS:
                entry.qsos = struct.unpack('<H', data[2:4])[0]

            elif ss_type == SST_OPERATOR:
                entry.operator = _cstring(data[35:46])

    def forward_spot_to_telnet_client(self, sender: socket.socket, data: bytes):
        """Forward DX spot to the (one) client connected to a telnet cluster.
        Mirrors the Delphi behavior: only the first matching peer receives it."""
        target = None
        with self.clients_lock:
            for client_socket, entry in self.clients.items():
                if entry.connected_to_telnet and client_socket != sender:
                    target = client_socket
                    break
        if target is None:
            return
        if _safe_sendall(target, data):
            self.bytes_sent += len(data)
        else:
            self.remove_client(target)

    def handle_server_message(self, client_socket: socket.socket, data: bytes):
        """Handle server control messages"""
        msg = TServerMessage.unpack(data)

        if msg.sm_message == SM_SERIAL_NUMBER_CHANGED:
            if self.serial_number_lockout:
                # Handle serial number updates
                pass

        elif msg.sm_message == SM_CLEARALLLOGS_MESSAGE:
            if self.clear_server_log():
                self.broadcast_to_clients(client_socket, data, include_sender=True)

        elif msg.sm_message == SM_CLEAR_DUPESHEET_MESSAGE:
            # Set clear dupesheet bit in all QSOs
            self.broadcast_to_clients(client_socket, data, include_sender=True)

        elif msg.sm_message == SM_CLEAR_MULTSHEET_MESSAGE:
            # Clear mult flags in all QSOs
            self.broadcast_to_clients(client_socket, data, include_sender=True)

        elif msg.sm_message == SM_SERVERLOG_CHANGED_MESSAGE:
            self.broadcast_to_clients(client_socket, data, include_sender=False)

        elif msg.sm_message == SM_GETSTATUS_MESSAGE:
            self.broadcast_to_clients(client_socket, data, include_sender=False)

    def clear_server_log(self) -> bool:
        """Clear the server log (keep header only)"""
        with self.log_lock:
            try:
                with open(self.log_file_path, 'r+b') as f:
                    f.seek(self.log_record_size)
                    f.truncate()
                self.server_crc32_changed = True
                logger.info("Server log cleared")
                return True
            except Exception as e:
                logger.error(f"Error clearing log: {e}")
                return False

    def send_disconnect_message(self, computer_id: str):
        """Notify all clients that a station disconnected"""
        msg = TServerMessage(
            sm_id=NET_SERVERMESSAGE_ID,
            sm_message=SM_DISCONECT_CLIENT_MESSAGE,
            sm_param=ord(computer_id) if computer_id else 0
        )
        data = msg.pack()

        with self.clients_lock:
            targets = list(self.clients.keys())
        for s in targets:
            if _safe_sendall(s, data):
                self.bytes_sent += 8

    def remove_client(self, client_socket: socket.socket):
        """Remove client from the server. Safe to call multiple times."""
        entry = None
        with self.clients_lock:
            if client_socket in self.clients:
                entry = self.clients[client_socket]
                del self.clients[client_socket]
                remaining = len(self.clients)

        if entry is not None:
            logger.info(f"Client disconnected: {entry.ip_address} ({entry.hostname}) - Total: {remaining}")
            if entry.computer_id:
                self.send_disconnect_message(entry.computer_id)

        try:
            client_socket.close()
        except OSError:
            pass

    def stop(self):
        """Stop the server. Idempotent — safe to call from a signal handler."""
        if not self.running:
            return
        self.running = False
        self._stop_event.set()

        with self.clients_lock:
            sockets = list(self.clients.keys())
            self.clients.clear()
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass

        for s in (self.server_socket, self.sync_socket):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

        try:
            self._resolver.shutdown(wait=False)
        except Exception:
            pass

        logger.info("Server stopped")

    # ------------------------------------------------------------------
    # Status display
    # ------------------------------------------------------------------

    def status_snapshot(self) -> Dict:
        """Cheap, lock-light read of current state for the display threads.

        Renders the same per-station fields TR4W's own Network window shows
        (Name / Id / Band+Mode / Freq / St. / PTT / Qs / Callsign / D / Op),
        plus the things only the server knows (IP, hostname, telnet flag)."""
        with self.clients_lock:
            clients = []
            for e in self.clients.values():
                if e.band is not None and 0 <= e.band < len(BAND_NAMES):
                    band_str = BAND_NAMES[e.band]
                else:
                    band_str = ""
                if e.mode is not None and 0 <= e.mode < len(MODE_NAMES):
                    mode_str = MODE_NAMES[e.mode]
                else:
                    mode_str = ""
                clients.append({
                    'ip':       e.ip_address,
                    'host':     e.hostname,
                    'comp_id':  e.computer_id or '-',
                    'telnet':   'yes' if e.connected_to_telnet else 'no',
                    'name':     e.name,
                    'band_mode': (band_str + mode_str) if band_str else "",
                    'freq':     f"{e.freq_hz/1000:.2f}" if e.freq_hz else "",
                    'st':       'SP' if e.sp_mode else 'CQ',
                    'ptt':      'ON' if e.ptt_on else 'OFF',
                    'qsos':     e.qsos,
                    'call':     e.callsign,
                    'dupe':     'D' if e.dupe else '',
                    'op':       e.operator,
                })
        return {
            'port':     self.port,
            'qsos':     self.get_qso_count(),
            'rx':       self.bytes_received,
            'tx':       self.bytes_sent,
            'clients':  clients,
        }

    # Column widths chosen to match TR4W's Network window labels while still
    # fitting in an 80-col terminal when possible. Total width = 105.
    _STATUS_FMT = (
        "{n:<3} {id:<2} {name:<8} {bm:<6} {freq:>8} {st:<2} {ptt:<3} "
        "{qs:>4} {call:<10} {d:<1} {op:<10} {ip:<15} {host}"
    )

    def _format_status(self, snap: Dict) -> str:
        header = self._STATUS_FMT.format(
            n="#", id="Id", name="Name", bm="B/M", freq="Freq",
            st="St", ptt="PTT", qs="Qs", call="Callsign", d="D",
            op="Op", ip="IP", host="Hostname",
        )
        rows = [
            f"{SERVER_VERSION}  port {snap['port']}  "
            f"clients {len(snap['clients'])}/{MAX_CLIENTS}  "
            f"qsos {snap['qsos']}  rx {snap['rx']:,}  tx {snap['tx']:,}",
            "-" * len(header),
            header,
            "-" * len(header),
        ]
        if not snap['clients']:
            rows.append("(no clients connected)")
        else:
            for i, c in enumerate(snap['clients'], 1):
                rows.append(self._STATUS_FMT.format(
                    n=i,
                    id=c['comp_id'][:2],
                    name=c['name'][:8],
                    bm=c['band_mode'][:6],
                    freq=c['freq'][:8],
                    st=c['st'],
                    ptt=c['ptt'],
                    qs=c['qsos'],
                    call=c['call'][:10],
                    d=c['dupe'],
                    op=c['op'][:10],
                    ip=c['ip'][:15],
                    host=c['host'],
                ))
        return "\n".join(rows)

    def print_status(self):
        """One-shot status print for the 's' interactive command."""
        print()
        print(self._format_status(self.status_snapshot()))
        print()

    def run_display_loop(self):
        """Refresh a status table on stdout every DISPLAY_REFRESH_INTERVAL
        seconds. ANSI clear-screen — terminal-only, do not enable when stdout
        is going to journald or a pipe."""
        # ANSI: clear screen + home cursor.
        clear = "\x1b[2J\x1b[H"
        try:
            while self.running:
                snap = self.status_snapshot()
                sys.stdout.write(clear)
                sys.stdout.write(self._format_status(snap))
                sys.stdout.write("\n\n(press Ctrl+C to stop the server)\n")
                sys.stdout.flush()
                if self._stop_event.wait(DISPLAY_REFRESH_INTERVAL):
                    return
        except Exception as e:
            logger.warning(f"display loop exited: {e}")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='TR4WSERVER - Ham Radio Logging Server for Raspberry Pi')
    parser.add_argument('-c', '--config', default='tr4wserver.ini', help='Configuration file')
    parser.add_argument('-p', '--port', type=int, help='Server port (overrides config)')
    parser.add_argument('--password', help='Server password (overrides config)')
    parser.add_argument('--display', action='store_true',
                        help='Refresh a status table on stdout every 2s. '
                             'Requires a TTY. Do not use under systemd.')
    parser.add_argument('--trace-rx', action='store_true',
                        help='Log every recv()d byte chunk and every framed '
                             'message ID. Verbose — use only for debugging '
                             'a protocol mismatch.')
    args = parser.parse_args()

    try:
        server = TR4WServer(args.config)
    except RuntimeError as e:
        # init_log_file refused because of an on-disk size mismatch — a clear
        # operator-actionable error. Re-raised here so systemd's exit code is
        # nonzero and the message lands in journalctl.
        logger.critical(str(e))
        sys.exit(2)

    if args.port:
        server.port = args.port
    if args.password:
        server.password = args.password
    if args.trace_rx:
        server.trace_rx = True

    # systemd sends SIGTERM on stop. Without a handler Python kills the
    # process immediately, leaving partial broadcasts in flight.
    def _signal_stop(signum, frame):
        logger.info(f"Received signal {signum}, shutting down")
        server.stop()
    signal.signal(signal.SIGTERM, _signal_stop)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, _signal_stop)

    try:
        server.start()
    except OSError:
        # already logged inside start(); systemd will retry.
        sys.exit(1)

    print("\nTR4WSERVER running. Press Ctrl+C to stop.\n")
    print("Commands: 's' = status, 'q' = quit\n")

    if args.display and sys.stdout.isatty():
        # Display thread reads state with light locks; safe to leave as a
        # daemon thread — it'll exit when self.running flips to False.
        threading.Thread(target=server.run_display_loop, daemon=True,
                         name='display').start()
    elif args.display:
        logger.warning("--display requires a TTY; falling back to log-only output")

    try:
        while server.running:
            try:
                cmd = input().strip().lower()
                if cmd == 'q':
                    break
                elif cmd == 's':
                    server.print_status()
            except EOFError:
                # No controlling terminal — sleep on the stop event so SIGTERM
                # wakes us immediately. Do NOT busy-poll.
                if server._stop_event.wait():
                    break
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()


if __name__ == '__main__':
    main()
