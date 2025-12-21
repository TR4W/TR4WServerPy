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
import os
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
NET_LOGINFO_MESSAGE = 0x52544847  # 'GHTR' as little-endian

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

# Size of ContestExchange record (from Delphi source)
# This is a complex packed record - we'll handle it as raw bytes for compatibility
SIZE_OF_CONTEST_EXCHANGE = 232  # Approximate size, adjust based on actual Delphi struct
SIZE_OF_LOG_HEADER = SIZE_OF_CONTEST_EXCHANGE


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
    """Log file information structure"""
    li_id: int = NET_LOGCOMPARE_ID  # Word
    li_server_log_size: int = 0  # Cardinal
    li_contest: int = 0  # Cardinal (Contest type)
    li_server_crc32: int = 0  # Cardinal

    def pack(self) -> bytes:
        return struct.pack('<HIII', self.li_id, self.li_server_log_size,
                           self.li_contest, self.li_server_crc32)


@dataclass
class ClientEntry:
    """Client connection entry"""
    conn: object = None  # socket.socket object
    ip_address: str = ""
    hostname: str = ""
    computer_id: str = ""
    connected_to_telnet: bool = False
    serial_number: int = 0
    serial_number_status: int = 0  # 0=Free, 1=Reserved


# ============================================================================
# Message Size Mapping (sizes from Delphi source)
# ============================================================================

# These sizes are approximate - adjust based on actual Delphi packed record sizes
MESSAGE_SIZES = {
    NET_MESSAGESTATE_ID: 64,  # TMessageState
    NET_STATIONSTATUS_ID: 36,  # TStationState
    NET_NETWORKDXSPOT_ID: 82,  # TNetDXSpot
    NET_TIMESYN_ID: 20,  # TNetTimeSync
    NET_PARAMETER_ID: 516,  # TParameterToNetwork (2 ShortStrings)
    NET_INTERCOMMESSAGE_ID: 128,  # TIntercomMessage
    NET_EDITEDQSO_ID: SIZE_OF_CONTEST_EXCHANGE + 10,  # TNetQSOInformation
    NET_OFFLINEQSO_ID: SIZE_OF_CONTEST_EXCHANGE + 10,  # TNetQSOInformation
    NET_QSOINFO_ID: SIZE_OF_CONTEST_EXCHANGE + 10,  # TNetQSOInformation
    NET_CLIENTSTATUS_ID: 4,  # TClientStatus
    NET_SPOTVIANETWORK_ID: 64,  # TSendSpotViaNetwork
    NET_COMPUTERID_ID: 4,  # TComputerNetID
    NET_SERVERMESSAGE_ID: 8,  # TServerMessage
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

        self.clients: Dict[socket.socket, ClientEntry] = {}
        self.clients_lock = threading.Lock()

        self.server_socket: Optional[socket.socket] = None
        self.sync_socket: Optional[socket.socket] = None
        self.running = False

        self.log_file_path = "SERVERLOG.TRW"
        self.log_lock = threading.Lock()

        self.bytes_received = 0
        self.bytes_sent = 0

        self.server_crc32 = 0
        self.server_crc32_changed = True

        self.load_config()
        self.init_log_file()

    def load_config(self):
        """Load configuration from INI file"""
        if os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config.read(self.config_file)

            section = 'TR4WSERVER'
            if section in config:
                self.port = config.getint(section, 'PORT', fallback=DEFAULT_PORT)
                self.password = config.get(section, 'SERVER PASSWORD', fallback='TR4WSERVER')
                self.allow_time_sync = config.getint(section, 'ALLOW TIME SYNCHRONIZING', fallback=1) == 1
                self.serial_number_lockout = config.getint(section, 'SERIAL NUMBER LOCKOUT', fallback=0) == 1

            logger.info(f"Configuration loaded from {self.config_file}")
        else:
            self.save_config()
            logger.info(f"Created default configuration: {self.config_file}")

    def save_config(self):
        """Save configuration to INI file"""
        config = configparser.ConfigParser()
        config['TR4WSERVER'] = {
            'PORT': str(self.port),
            'SERVER PASSWORD': self.password,
            'ALLOW TIME SYNCHRONIZING': '1' if self.allow_time_sync else '0',
            'SERIAL NUMBER LOCKOUT': '1' if self.serial_number_lockout else '0',
        }
        with open(self.config_file, 'w') as f:
            config.write(f)

    def init_log_file(self):
        """Initialize the server log file"""
        if not os.path.exists(self.log_file_path):
            # Create new log file with header
            with open(self.log_file_path, 'wb') as f:
                header = self.create_log_header()
                f.write(header)
            logger.info(f"Created new log file: {self.log_file_path}")
        else:
            # Verify log file integrity
            with open(self.log_file_path, 'rb') as f:
                data = f.read()
                if len(data) < SIZE_OF_LOG_HEADER:
                    logger.warning("Log file too small, reinitializing")
                    with open(self.log_file_path, 'wb') as f2:
                        f2.write(self.create_log_header())
                elif (len(data) - SIZE_OF_LOG_HEADER) % SIZE_OF_CONTEST_EXCHANGE != 0:
                    logger.warning("Log file size mismatch - may be corrupted")

    def create_log_header(self) -> bytes:
        """Create log file header (same size as ContestExchange)"""
        version_string = b'1.6.6\x00  \r\n'[:8]
        file_desc = b'TR4W LOG FILE \r\n'[:16]
        warning = b'WARNING: DO NOT EDIT THIS FILE!\r\n\r\n\x00'[:36]
        dummy = b'\x00' * (SIZE_OF_LOG_HEADER - 60)
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
        if size <= SIZE_OF_LOG_HEADER:
            return 0
        return (size - SIZE_OF_LOG_HEADER) // SIZE_OF_CONTEST_EXCHANGE

    def calculate_log_crc32(self) -> int:
        """Calculate CRC32 of the log file"""
        if not self.server_crc32_changed:
            return self.server_crc32

        try:
            with open(self.log_file_path, 'rb') as f:
                data = f.read()
                self.server_crc32 = zlib.crc32(data) & 0xFFFFFFFF
                self.server_crc32_changed = False
        except:
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
        """Start the server"""
        self.running = True

        # Start main server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(MAX_CLIENTS)

        # Start sync listener socket (for log file transfers)
        self.sync_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sync_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sync_socket.bind(('0.0.0.0', self.port + 1))
        self.sync_socket.listen(MAX_CLIENTS)

        # Get server IP
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "0.0.0.0"

        logger.info(f"{SERVER_VERSION}")
        logger.info(f"Server IP: {ip_address}")
        logger.info(f"Listening on port {self.port} (main) and {self.port + 1} (sync)")
        logger.info(f"Log file: {self.log_file_path} ({self.get_qso_count()} QSOs)")

        # Start accept threads
        threading.Thread(target=self.accept_clients, daemon=True).start()
        threading.Thread(target=self.accept_sync_clients, daemon=True).start()

    def accept_clients(self):
        """Accept incoming client connections on main port"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_new_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")

    def accept_sync_clients(self):
        """Accept incoming sync connections for log file transfer"""
        while self.running:
            try:
                client_socket, addr = self.sync_socket.accept()
                threading.Thread(
                    target=self.handle_sync_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except Exception as e:
                if self.running:
                    logger.error(f"Sync accept error: {e}")

    def handle_new_client(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle new client connection authentication"""
        try:
            time.sleep(0.2)  # Small delay as in original

            # Receive password
            data = client_socket.recv(50)
            if not data or len(data) < 10:
                client_socket.close()
                return

            if not self.check_password(data):
                client_socket.send(PASS_TR4W)
                client_socket.close()
                logger.info(f"Client {addr[0]} - invalid password")
                return

            # Send acknowledgment
            if client_socket.send(SEND_TR4W) != 4:
                client_socket.close()
                return

            # Disable Nagle algorithm for low latency
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Get hostname
            try:
                hostname = socket.gethostbyaddr(addr[0])[0]
            except:
                hostname = "?"

            # Add to clients list
            with self.clients_lock:
                if len(self.clients) >= MAX_CLIENTS:
                    client_socket.close()
                    logger.warning(f"Max clients reached, rejecting {addr[0]}")
                    return

                entry = ClientEntry(
                    conn=client_socket,
                    ip_address=addr[0],
                    hostname=hostname
                )
                self.clients[client_socket] = entry

            logger.info(f"Client connected: {addr[0]} ({hostname}) - Total: {len(self.clients)}")

            # Send log file information
            self.send_log_file_info(client_socket)

            # Handle client messages
            self.handle_client(client_socket)

        except Exception as e:
            logger.error(f"Error handling new client: {e}")
        finally:
            self.remove_client(client_socket)

    def handle_sync_client(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle sync client - send log file"""
        try:
            time.sleep(0.05)

            # Receive password
            data = client_socket.recv(50)
            if not data or not self.check_password(data):
                client_socket.close()
                return

            # Send log file
            with self.log_lock:
                log_size = self.get_log_size()

                # Send size first
                client_socket.send(struct.pack('<I', log_size))

                # Send file content
                with open(self.log_file_path, 'rb') as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        client_socket.send(chunk)
                        self.bytes_sent += len(chunk)

            logger.info(f"Sent log file to {addr[0]} ({log_size} bytes)")

        except Exception as e:
            logger.error(f"Sync client error: {e}")
        finally:
            client_socket.close()

    def handle_client(self, client_socket: socket.socket):
        """Handle messages from connected client"""
        buffer = b''

        while self.running:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break

                self.bytes_received += len(data)
                buffer += data

                # Process complete messages
                buffer = self.process_buffer(client_socket, buffer)

            except socket.error:
                break
            except Exception as e:
                logger.error(f"Client handler error: {e}")
                break

    def process_buffer(self, client_socket: socket.socket, buffer: bytes) -> bytes:
        """Process received data buffer and return remaining data"""
        while len(buffer) >= 2:
            # Get message ID (first 2 bytes)
            msg_id = struct.unpack('<H', buffer[:2])[0]

            # Check for log info request
            if len(buffer) >= 4:
                dword = struct.unpack('<I', buffer[:4])[0]
                if dword == NET_LOGINFO_MESSAGE:
                    self.send_log_file_info(client_socket)
                    buffer = buffer[4:]
                    continue

            # Get message size
            msg_size = MESSAGE_SIZES.get(msg_id)
            if msg_size is None:
                logger.warning(f"Unknown message ID: {msg_id}")
                break

            if len(buffer) < msg_size:
                break  # Wait for more data

            # Extract message
            message = buffer[:msg_size]
            buffer = buffer[msg_size:]

            # Process message
            self.process_message(client_socket, msg_id, message)

        return buffer

    def process_message(self, client_socket: socket.socket, msg_id: int, data: bytes):
        """Process a complete message"""
        try:
            if msg_id == NET_MESSAGESTATE_ID:
                self.broadcast_to_clients(client_socket, data, include_sender=True)

            elif msg_id == NET_STATIONSTATUS_ID:
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
        """Send message to all connected clients"""
        with self.clients_lock:
            for client_socket in list(self.clients.keys()):
                if not include_sender and client_socket == sender:
                    continue
                try:
                    client_socket.send(data)
                    self.bytes_sent += len(data)
                except:
                    pass

    def send_log_file_info(self, client_socket: socket.socket):
        """Send log file information to client"""
        info = TLogFileInformation()
        info.li_server_log_size = self.get_log_size()
        info.li_contest = self.get_contest_type()
        info.li_server_crc32 = self.calculate_log_crc32()

        try:
            client_socket.send(info.pack())
            self.bytes_sent += 14
        except:
            pass

    def get_contest_type(self) -> int:
        """Get contest type from first QSO in log"""
        try:
            with open(self.log_file_path, 'rb') as f:
                f.seek(SIZE_OF_LOG_HEADER)
                data = f.read(SIZE_OF_CONTEST_EXCHANGE)
                if len(data) >= 50:
                    # Contest type is somewhere in the record
                    # This is approximate - adjust based on actual offset
                    return 0  # Return default for now
        except:
            pass
        return DUMMYCONTEST

    def add_qso_to_log(self, data: bytes):
        """Add a QSO to the server log"""
        with self.log_lock:
            try:
                # Extract ContestExchange from TNetQSOInformation
                # Skip the 2-byte ID
                qso_data = data[2:2 + SIZE_OF_CONTEST_EXCHANGE]

                with open(self.log_file_path, 'ab') as f:
                    f.write(qso_data)
                    f.flush()
                    os.fsync(f.fileno())

                self.server_crc32_changed = True
                logger.info(f"QSO added to log. Total: {self.get_qso_count()}")

            except Exception as e:
                logger.error(f"Error adding QSO to log: {e}")

    def update_qso_in_log(self, data: bytes):
        """Update an existing QSO in the log"""
        with self.log_lock:
            try:
                # Extract ContestExchange and IDs
                qso_data = data[2:2 + SIZE_OF_CONTEST_EXCHANGE]

                # Get QSO IDs from the data (offsets based on ContestExchange structure)
                # After tSysTime (6 bytes), Band (1), Mode (1) = offset 8
                qso_id1 = struct.unpack('<I', qso_data[8:12])[0]
                qso_id2 = struct.unpack('<I', qso_data[12:16])[0]

                with open(self.log_file_path, 'r+b') as f:
                    # Search from end of file
                    file_size = os.path.getsize(self.log_file_path)
                    pos = file_size - SIZE_OF_CONTEST_EXCHANGE

                    while pos >= SIZE_OF_LOG_HEADER:
                        f.seek(pos)
                        existing = f.read(SIZE_OF_CONTEST_EXCHANGE)

                        # Check IDs
                        existing_id1 = struct.unpack('<I', existing[8:12])[0]
                        existing_id2 = struct.unpack('<I', existing[12:16])[0]

                        if existing_id1 == qso_id1 and existing_id2 == qso_id2:
                            f.seek(pos)
                            f.write(qso_data)
                            f.flush()
                            self.server_crc32_changed = True
                            logger.info(f"QSO updated in log")
                            return

                        pos -= SIZE_OF_CONTEST_EXCHANGE

            except Exception as e:
                logger.error(f"Error updating QSO: {e}")

    def send_confirm_message(self, client_socket: socket.socket):
        """Send confirmation message to client"""
        msg = TServerMessage(
            sm_id=NET_SERVERMESSAGE_ID,
            sm_message=SM_RECEIVED_UPDATED_QSO_MESSAGE,
            sm_param=0
        )
        try:
            client_socket.send(msg.pack())
            self.bytes_sent += 8
        except:
            pass

    def update_client_status(self, client_socket: socket.socket, data: bytes):
        """Update client status (telnet connection, etc)"""
        with self.clients_lock:
            if client_socket in self.clients:
                # TClientStatus has telnet flag
                if len(data) >= 3:
                    self.clients[client_socket].connected_to_telnet = (data[2] != 0)

    def set_computer_id(self, client_socket: socket.socket, data: bytes):
        """Set computer ID for client"""
        with self.clients_lock:
            if client_socket in self.clients:
                if len(data) >= 3:
                    self.clients[client_socket].computer_id = chr(data[2])

    def forward_spot_to_telnet_client(self, sender: socket.socket, data: bytes):
        """Forward DX spot to a client connected to telnet"""
        with self.clients_lock:
            for client_socket, entry in self.clients.items():
                if entry.connected_to_telnet and client_socket != sender:
                    try:
                        client_socket.send(data)
                        self.bytes_sent += len(data)
                    except:
                        pass
                    break  # Only send to first telnet-connected client

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
                    f.seek(SIZE_OF_LOG_HEADER)
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
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.send(data)
                    self.bytes_sent += 8
                except:
                    pass

    def remove_client(self, client_socket: socket.socket):
        """Remove client from the server"""
        with self.clients_lock:
            if client_socket in self.clients:
                entry = self.clients[client_socket]
                del self.clients[client_socket]
                logger.info(f"Client disconnected: {entry.ip_address} - Total: {len(self.clients)}")

                if entry.computer_id:
                    self.send_disconnect_message(entry.computer_id)

        try:
            client_socket.close()
        except:
            pass

    def stop(self):
        """Stop the server"""
        self.running = False

        # Close all client connections
        with self.clients_lock:
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()

        # Close server sockets
        if self.server_socket:
            self.server_socket.close()
        if self.sync_socket:
            self.sync_socket.close()

        logger.info("Server stopped")

    def print_status(self):
        """Print server status"""
        print(f"\n{'='*50}")
        print(f"{SERVER_VERSION}")
        print(f"{'='*50}")
        print(f"Port: {self.port}")
        print(f"Clients: {len(self.clients)}")
        print(f"QSOs in log: {self.get_qso_count()}")
        print(f"Bytes RX: {self.bytes_received:,}")
        print(f"Bytes TX: {self.bytes_sent:,}")
        print(f"{'='*50}\n")


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
    args = parser.parse_args()

    server = TR4WServer(args.config)

    if args.port:
        server.port = args.port
    if args.password:
        server.password = args.password

    try:
        server.start()
        print("\nTR4WSERVER running. Press Ctrl+C to stop.\n")
        print("Commands: 's' = status, 'q' = quit\n")

        while True:
            try:
                cmd = input().strip().lower()
                if cmd == 'q':
                    break
                elif cmd == 's':
                    server.print_status()
            except EOFError:
                # Running without terminal
                time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()


if __name__ == '__main__':
    main()
