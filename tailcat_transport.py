#!/usr/bin/env python3
"""
Optional Tailcat transport for TR4WSERVER (Python).

Tailcat (https://github.com/tailscale/tailcat) carries TCP over WireGuard with
NAT traversal and needs no account. With it a TR4W station on another network
can reach this server by pasting ONE string, the tailcat address, and nothing
has to be opened in a router.

This module embeds Tailcat through its C library (libtailcat, built from
cmd/libtailcat in the Tailcat repository) and ctypes. It adds no Python
dependency. If the library is missing the server reports it and carries on
serving plain TCP.

HOW A REMOTE STATION REACHES THE SERVER

   TR4W client --(Tailcat tunnel)--> libtailcat listener, inside this process
                                            |
                                     socket.socketpair()
                                            |
                              the server's ordinary connection handler

Each connection accepted inside the tunnel is joined to one end of a socket
pair and the other end is handed to the very handler a LAN connection gets.
The protocol code therefore cannot tell the two apart, and there is exactly
one implementation of the TR4W protocol. A socket pair, not a loopback
listener, so nothing new is opened that another process on this machine
could connect to.

THE ADDRESS IS A PASSWORD

A tailcat address contains a WireGuard pre-shared key. Anyone holding it can
reach the listeners, so this module never logs it. It is written to a file
readable only by the server's own account (ADDRESS_FILE_NAME beside the key
file), and the console command prints it on request.

THE KEY FILE KEEPS THE ADDRESS STABLE

The address is made of the server's key, its pre-shared key and a relay
region. All three are saved in the key file, so the address survives a
restart. To withdraw every invitation ever handed out, delete the key file
and restart: a new key means a new address, and the old one stops working.

Copyright 2026 Thomas M. Schaefer (NY4I). GPL v3, as the rest of TR4WSERVER.
libtailcat is Copyright (c) Tailscale Inc & contributors, BSD-3-Clause.
"""

import ctypes
import json
import logging
import os
import socket
import sys
import threading
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# The C ABI, from cmd/libtailcat/tailcat.h (ABI version 1).
# ----------------------------------------------------------------------------

TC_ABI_VERSION      = 1

TC_OK               = 0
TC_INVALID_ARGUMENT = 1
TC_CLOSED           = 2
TC_TIMEOUT          = 3
TC_CANCELLED        = 4
TC_FAILURE          = 5
TC_EOF              = 6

TC_TCP              = 1
TC_NO_CANCEL        = 0

_STATUS_NAMES = {
   TC_OK: 'ok', TC_INVALID_ARGUMENT: 'invalid argument', TC_CLOSED: 'closed',
   TC_TIMEOUT: 'timeout', TC_CANCELLED: 'cancelled', TC_FAILURE: 'failure',
   TC_EOF: 'end of stream',
}

STARTUP_TIMEOUT_SECONDS  = 60    # relay discovery and registration
RETRY_SECONDS            = 30    # between startup attempts (no network yet)
LINGER_SECONDS           = 10    # wait for the far end after we finish sending
CLOSE_WRITE_SECONDS      = 5
BRIDGE_BUFFER_BYTES      = 65536

KEY_FILE_NAME            = 'tailcat.key.json'
ADDRESS_FILE_NAME        = 'tailcat.address'


class TailcatError(Exception):
   """A libtailcat call failed. `status` is its TC_* code."""

   def __init__(self, what: str, status: int, message: Optional[str] = None):
      self.status = status
      name = _STATUS_NAMES.get(status, 'status %d' % status)
      text = '%s: %s' % (what, name)
      if message:
         text += ' (%s)' % message
      super().__init__(text)


class TailcatUnavailable(Exception):
   """The library cannot be loaded or is not the ABI this module speaks."""


def default_library_path(program_dir: str) -> str:
   """Where the library is expected when the INI names none: beside the
   program, never a bare name left to the loader's search path."""
   if sys.platform == 'win32':
      name = 'libtailcat.dll'
   elif sys.platform == 'darwin':
      name = 'libtailcat.dylib'
   else:
      name = 'libtailcat.so'
   return os.path.join(program_dir, name)


class TailcatLibrary:
   """The ctypes binding. Thin: one method per C function this server uses,
   with the library's allocations copied and released before returning."""

   def __init__(self, path: str):
      if not os.path.isfile(path):
         raise TailcatUnavailable('library not found: %s' % path)
      try:
         lib = ctypes.CDLL(path)
      except OSError as e:
         raise TailcatUnavailable('cannot load %s: %s' % (path, e))

      handle = ctypes.c_uint64
      text = ctypes.c_char_p
      out_ptr = ctypes.POINTER(ctypes.c_void_p)
      out_handle = ctypes.POINTER(handle)
      out_size = ctypes.POINTER(ctypes.c_size_t)

      try:
         lib.tc_abi_version.argtypes = []
         lib.tc_abi_version.restype = ctypes.c_uint32
         lib.tc_free.argtypes = [ctypes.c_void_p]
         lib.tc_free.restype = None
         signatures = {
            'tc_token_new':         [ctypes.c_int64, out_handle, out_ptr],
            'tc_close':             [handle, out_ptr],
            'tc_server_new':        [text, out_handle, out_ptr],
            'tc_server_listen':     [handle, handle, ctypes.c_uint16, ctypes.c_int32,
                                     out_handle, out_ptr],
            'tc_listener_accept':   [handle, handle, out_handle, out_ptr],
            'tc_conn_read':         [handle, handle, ctypes.c_void_p, ctypes.c_size_t,
                                     out_size, out_ptr],
            'tc_conn_write':        [handle, handle, ctypes.c_void_p, ctypes.c_size_t,
                                     out_size, out_ptr],
            'tc_conn_close_write':  [handle, handle, out_ptr],
            'tc_info':              [handle, handle, out_ptr, out_ptr],
            'tc_address_parse':     [text, out_ptr, out_ptr],
            'tc_key_generate':      [out_ptr, out_ptr],
         }
         for name, argtypes in signatures.items():
            function = getattr(lib, name)
            function.argtypes = argtypes
            function.restype = ctypes.c_int32
      except AttributeError as e:
         raise TailcatUnavailable('%s is not a libtailcat this server can use: %s' % (path, e))

      version = lib.tc_abi_version()
      if version != TC_ABI_VERSION:
         raise TailcatUnavailable(
            '%s is libtailcat ABI %d; this server speaks ABI %d'
            % (path, version, TC_ABI_VERSION))
      self._lib = lib
      self.path = path

   # -- allocations ---------------------------------------------------------

   def _take(self, pointer: ctypes.c_void_p) -> Optional[str]:
      """Copy a string the library allocated, then release it."""
      if not pointer.value:
         return None
      value = ctypes.string_at(pointer.value).decode('utf-8', 'replace')
      self._lib.tc_free(pointer)
      return value

   def _finish(self, what: str, status: int, error: ctypes.c_void_p):
      message = self._take(error)
      if status != TC_OK:
         raise TailcatError(what, status, message)

   def _handle_call(self, what: str, function, *args) -> int:
      out = ctypes.c_uint64(0)
      error = ctypes.c_void_p()
      status = function(*args, ctypes.byref(out), ctypes.byref(error))
      self._finish(what, status, error)
      return out.value

   def _text_call(self, what: str, function, *args) -> str:
      out = ctypes.c_void_p()
      error = ctypes.c_void_p()
      status = function(*args, ctypes.byref(out), ctypes.byref(error))
      value = self._take(out)
      self._finish(what, status, error)
      return value or ''

   # -- the calls -----------------------------------------------------------

   def token(self, seconds: float) -> int:
      """A deadline that starts NOW. Release it with close()."""
      return self._handle_call('token', self._lib.tc_token_new, int(seconds * 1e9))

   def close(self, resource: int) -> int:
      """Retire a handle. Closing one twice is harmless (handles are never
      reused), so this returns the status instead of raising."""
      error = ctypes.c_void_p()
      status = self._lib.tc_close(resource, ctypes.byref(error))
      self._take(error)
      return status

   def key_generate(self) -> Dict:
      return json.loads(self._text_call('key generation', self._lib.tc_key_generate))

   def server_new(self, config: Dict) -> int:
      return self._handle_call('server configuration', self._lib.tc_server_new,
                               json.dumps(config).encode('utf-8'))

   def server_listen(self, server: int, token: int, port: int) -> int:
      return self._handle_call('listen on port %d' % port, self._lib.tc_server_listen,
                               server, token, port, TC_TCP)

   def accept(self, listener: int) -> int:
      return self._handle_call('accept', self._lib.tc_listener_accept,
                               listener, TC_NO_CANCEL)

   def info(self, resource: int) -> Dict:
      return json.loads(self._text_call('info', self._lib.tc_info, resource, TC_NO_CANCEL))

   def address_parse(self, address: str) -> Dict:
      return json.loads(self._text_call('address', self._lib.tc_address_parse,
                                        address.encode('utf-8')))

   def read(self, connection: int, buffer) -> Tuple[int, bytes]:
      """One read. Returns (status, bytes): the bytes are valid even when the
      status is not TC_OK, and must be used before the status is acted on."""
      count = ctypes.c_size_t(0)
      error = ctypes.c_void_p()
      status = self._lib.tc_conn_read(connection, TC_NO_CANCEL, buffer, len(buffer),
                                      ctypes.byref(count), ctypes.byref(error))
      self._take(error)
      return status, buffer.raw[:count.value]

   def write_all(self, connection: int, data: bytes):
      """Write every byte or raise. A write may be short, so loop."""
      view = memoryview(data)
      sent = 0
      while sent < len(data):
         chunk = bytes(view[sent:])
         count = ctypes.c_size_t(0)
         error = ctypes.c_void_p()
         status = self._lib.tc_conn_write(connection, TC_NO_CANCEL, chunk, len(chunk),
                                          ctypes.byref(count), ctypes.byref(error))
         sent += count.value
         self._finish('write', status, error)

   def close_write(self, connection: int, seconds: float):
      """Send FIN but keep reading. Never raises: it is only a courtesy."""
      try:
         token = self.token(seconds)
      except TailcatError:
         return
      error = ctypes.c_void_p()
      self._lib.tc_conn_close_write(connection, token, ctypes.byref(error))
      self._take(error)
      self.close(token)


# ----------------------------------------------------------------------------
# Key material
# ----------------------------------------------------------------------------

def _write_private(path: str, text: str):
   """Write a secret so only this account can read it, replacing atomically.
   (On Windows the mode is not an access control; the file inherits the
   directory's ACL.)"""
   temporary = path + '.new'
   descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
   with os.fdopen(descriptor, 'w', encoding='utf-8') as f:
      f.write(text)
   os.replace(temporary, path)


def _load_key(path: str) -> Optional[Dict]:
   """The saved key, or None when there is none yet. A key file that exists
   but cannot be used is an ERROR, never a reason to mint a new key: that
   would silently change the address every station holds."""
   if not os.path.exists(path):
      return None
   with open(path, 'r', encoding='utf-8') as f:
      saved = json.load(f)
   for name in ('private_key', 'preshared_key'):
      if not isinstance(saved.get(name), str) or not saved[name]:
         raise ValueError('%s has no %s' % (path, name))
   return saved


# ----------------------------------------------------------------------------
# The transport
# ----------------------------------------------------------------------------

Handler = Callable[[socket.socket, Tuple[str, int]], None]


class TailcatTransport:
   """Listens inside a Tailcat tunnel and feeds the server's own handlers.

   `handlers` maps a port to the function that serves a connection on it; the
   function receives a connected socket and an (address, port) tuple, exactly
   as it does for a LAN connection, and owns the socket from then on.
   """

   def __init__(self, library_path: str, key_file: str, handlers: Dict[int, Handler]):
      self._library_path = library_path
      self._key_file = key_file
      self._address_file = os.path.join(os.path.dirname(os.path.abspath(key_file)),
                                        ADDRESS_FILE_NAME)
      self._handlers = dict(handlers)
      self._lib: Optional[TailcatLibrary] = None
      self._server = 0
      self._address = ''
      self._state = 'off'
      self._lock = threading.Lock()
      self._stopping = threading.Event()
      self._connections = 0

   # -- what the server asks ------------------------------------------------

   @property
   def state(self) -> str:
      """One word for the status display: off / starting / ready / failed."""
      return self._state

   @property
   def connections(self) -> int:
      return self._connections

   @property
   def address(self) -> str:
      """THE SECRET. Empty until the transport is ready. Never log it."""
      return self._address

   @property
   def address_file(self) -> str:
      return self._address_file

   def start(self):
      """Begin starting, in the background. Returns at once: relay discovery
      can take seconds, and a Pi that boots before its network is up must
      still serve the LAN meanwhile. A failed start is retried."""
      self._stopping.clear()
      self._state = 'starting'
      threading.Thread(target=self._start_loop, daemon=True, name='tailcat-start').start()

   def stop(self):
      """Close the tunnel and everything in it. Idempotent."""
      self._stopping.set()
      with self._lock:
         server, self._server = self._server, 0
         self._address = ''
         self._state = 'off'
      if server and self._lib is not None:
         # Closing the server closes its listeners and connections, which
         # interrupts every accept and read blocked on them.
         self._lib.close(server)

   # -- startup -------------------------------------------------------------

   def _start_loop(self):
      while not self._stopping.is_set():
         try:
            self._start_once()
            return
         except TailcatUnavailable as e:
            # Nothing a retry can fix: the file is absent or the wrong build.
            self._state = 'failed'
            logger.error('tailcat: %s. Remote stations cannot connect; '
                         'the LAN ports are unaffected.', e)
            return
         except (OSError, ValueError) as e:
            # The key file. Not retried either: minting a new key here would
            # change the address every station holds.
            self._state = 'failed'
            logger.error('tailcat: key file %s is unusable: %s. Remote stations '
                         'cannot connect; the LAN ports are unaffected.',
                         self._key_file, e)
            return
         except TailcatError as e:
            self._state = 'failed'
            logger.warning('tailcat: could not start: %s. Trying again in %d s.',
                           e, RETRY_SECONDS)
            if self._stopping.wait(RETRY_SECONDS):
               return
            self._state = 'starting'

   def _start_once(self):
      if self._lib is None:
         self._lib = TailcatLibrary(self._library_path)
      lib = self._lib

      saved = _load_key(self._key_file)
      created = saved is None
      if created:
         generated = lib.key_generate()
         saved = {'private_key': generated['private_key'],
                  'preshared_key': generated['preshared_key']}

      config = {'key': saved['private_key'], 'preshared_key': saved['preshared_key']}
      pinned = isinstance(saved.get('region'), dict)
      if pinned:
         # The relay region is PART OF THE ADDRESS (the address names the
         # relay's host). Handing back the saved one is what keeps the address
         # the same from one start to the next; left out, the library picks
         # the nearest relay at each start and the address can change.
         config['region'] = saved['region']

      server = lib.server_new(config)
      try:
         token = lib.token(STARTUP_TIMEOUT_SECONDS)
         try:
            listeners = {port: lib.server_listen(server, token, port)
                         for port in self._handlers}
         finally:
            lib.close(token)
         address = lib.info(server)['address']

         if not pinned:
            # First start with this key: the library picked the nearest
            # relay. Record it exactly as the address carries it, or the next
            # start may pick another one and every address already handed
            # out would stop working. (Deleting "region" from the key file
            # makes the next start pick afresh, which changes the address.)
            regions = lib.address_parse(address).get('regions') or []
            if regions:
               saved['region'] = regions[0]
            else:
               logger.warning('tailcat: the address names no relay region, so it '
                              'cannot be pinned and may change at the next start')
            _write_private(self._key_file, json.dumps(saved, indent=3) + '\n')
            if created:
               logger.info('tailcat: new server key saved to %s', self._key_file)
         _write_private(self._address_file, address + '\n')
      except Exception:
         lib.close(server)
         raise

      with self._lock:
         if self._stopping.is_set():
            lib.close(server)
            return
         self._server = server
         self._address = address
         self._state = 'ready'

      for port, listener in listeners.items():
         threading.Thread(target=self._accept_loop, args=(listener, port),
                          daemon=True, name='tailcat-accept-%d' % port).start()

      # The address itself is deliberately absent from this line.
      relay = ''
      nodes = (saved.get('region') or {}).get('Nodes') or []
      if nodes:
         relay = nodes[0].get('HostName', '')
      logger.info('tailcat: ready on ports %s (relay %s). The address to give '
                  'remote stations is in %s; treat it as a password.',
                  ', '.join(str(p) for p in sorted(self._handlers)),
                  relay or 'unknown', self._address_file)

   # -- connections ---------------------------------------------------------

   def _accept_loop(self, listener: int, port: int):
      lib = self._lib
      while not self._stopping.is_set():
         try:
            connection = lib.accept(listener)
         except TailcatError as e:
            if self._stopping.is_set() or e.status == TC_CLOSED:
               return
            logger.error('tailcat: accept on port %d failed: %s', port, e)
            if self._stopping.wait(0.5):
               return
            continue
         threading.Thread(target=self._serve, args=(connection, port),
                          daemon=True, name='tailcat-conn-%d' % port).start()

   def _peer_label(self, connection: int) -> Tuple[str, int]:
      """(label, port) for the server's logs and client list.

      Every Tailcat peer has its own address inside the tunnel, but they all
      share a long common prefix, and the client list shows 15 characters.
      The label keeps the part that differs: 'tc:' and the last two groups."""
      try:
         remote = self._lib.info(connection).get('remote_address', '')
         host, _, port = remote.rpartition(':')
         groups = host.strip('[]').split(':')
         return 'tc:' + ':'.join(groups[-2:]), int(port)
      except (TailcatError, ValueError):
         return 'tc:?', 0

   def _serve(self, connection: int, port: int):
      """Join one tunnel connection to the server's handler and pump bytes
      both ways until both directions have ended."""
      lib = self._lib
      peer = self._peer_label(connection)
      try:
         ours, theirs = socket.socketpair()
      except OSError as e:
         logger.error('tailcat: no socket pair for %s: %s', peer[0], e)
         lib.close(connection)
         return

      with self._lock:
         self._connections += 1
      logger.debug('tailcat: connection from %s on port %d', peer[0], port)

      # The handler owns `theirs` from here, as it owns an accepted socket.
      threading.Thread(target=self._handlers[port], args=(theirs, peer),
                       daemon=True, name='client-%s' % peer[0]).start()

      inbound = threading.Thread(target=self._pump_in, args=(connection, ours),
                                 daemon=True, name='tailcat-in-%s' % peer[0])
      inbound.start()
      try:
         self._pump_out(connection, ours)
         # The server has finished sending. Give the station a moment to
         # finish too, then close: a station that never closes its half must
         # not hold this connection open for ever.
         inbound.join(LINGER_SECONDS)
      finally:
         lib.close(connection)          # interrupts a read still blocked
         inbound.join()
         try:
            ours.close()
         except OSError:
            pass
         with self._lock:
            self._connections -= 1

   def _pump_in(self, connection: int, ours: socket.socket):
      """Tunnel to server. Ends at the station's FIN or any error, and tells
      the handler by half-closing, which it reads as an ordinary disconnect."""
      buffer = ctypes.create_string_buffer(BRIDGE_BUFFER_BYTES)
      try:
         while True:
            status, data = self._lib.read(connection, buffer)
            if data:
               ours.sendall(data)
            if status != TC_OK:
               break
      except OSError:
         pass
      finally:
         try:
            ours.shutdown(socket.SHUT_WR)
         except OSError:
            pass

   def _pump_out(self, connection: int, ours: socket.socket):
      """Server to tunnel. Ends when the handler closes its socket."""
      finished_cleanly = False
      try:
         while True:
            data = ours.recv(BRIDGE_BUFFER_BYTES)
            if not data:
               finished_cleanly = True
               break
            self._lib.write_all(connection, data)
      except (OSError, TailcatError):
         pass
      if finished_cleanly:
         # Everything was handed to the tunnel: send FIN so the station sees
         # the end of the log transfer rather than a reset.
         self._lib.close_write(connection, CLOSE_WRITE_SECONDS)
