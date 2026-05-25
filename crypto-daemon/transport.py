"""
transport.py — message-framed JSON transport for the crypto daemon.

POSIX: AF_UNIX stream socket, newline-delimited JSON.
Windows: multiprocessing.connection AF_PIPE (named pipe), length-prefixed
JSON messages (framing handled by the stdlib).

The wire format differs per platform, but both sides on the same machine
use the same module so the abstraction is symmetric.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

POSIX_SOCKET_PATH = "/tmp/securemsg-crypto.sock"
WINDOWS_PIPE_PATH = r"\\.\pipe\securemsg-crypto"


def default_address() -> str:
    return WINDOWS_PIPE_PATH if sys.platform == "win32" else POSIX_SOCKET_PATH


# ---------------------------------------------------------------------------
# POSIX implementation (AF_UNIX + newline-delimited JSON)
# ---------------------------------------------------------------------------

class _PosixConn:
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = b""

    def recv_message(self):
        while b"\n" not in self._buf:
            try:
                chunk = self._sock.recv(4096)
            except (ConnectionResetError, OSError):
                return None
            if not chunk:
                return None
            self._buf += chunk
        line, _, rest = self._buf.partition(b"\n")
        self._buf = rest
        if not line:
            return None
        return json.loads(line.decode("utf-8"))

    def send_message(self, obj) -> None:
        data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
        self._sock.sendall(data)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class _PosixListener:
    def __init__(self, address: str):
        self.address = address
        # Best-effort cleanup of stale socket file from a previous run.
        try:
            os.unlink(address)
        except FileNotFoundError:
            pass
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(address)
        # Owner-only — local socket files must not be world-accessible.
        try:
            os.chmod(address, 0o600)
        except OSError:
            pass
        self._sock.listen(8)

    def accept(self) -> _PosixConn:
        client, _ = self._sock.accept()
        return _PosixConn(client)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
        try:
            os.unlink(self.address)
        except FileNotFoundError:
            pass


def _posix_connect(address: str) -> _PosixConn:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(address)
    return _PosixConn(s)


# ---------------------------------------------------------------------------
# Windows implementation (multiprocessing.connection AF_PIPE)
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    from multiprocessing.connection import Client as _MPClient
    from multiprocessing.connection import Listener as _MPListener

    class _WinConn:
        def __init__(self, conn):
            self._conn = conn

        def recv_message(self):
            try:
                data = self._conn.recv_bytes()
            except (EOFError, OSError):
                return None
            return json.loads(data.decode("utf-8"))

        def send_message(self, obj) -> None:
            self._conn.send_bytes(json.dumps(obj, separators=(",", ":")).encode("utf-8"))

        def close(self) -> None:
            try:
                self._conn.close()
            except OSError:
                pass

    class _WinListener:
        def __init__(self, address: str):
            self.address = address
            self._listener = _MPListener(address=address, family="AF_PIPE")

        def accept(self) -> "_WinConn":
            return _WinConn(self._listener.accept())

        def close(self) -> None:
            try:
                self._listener.close()
            except OSError:
                pass

    def _win_connect(address: str) -> "_WinConn":
        return _WinConn(_MPClient(address=address, family="AF_PIPE"))


def listen(address: str | None = None):
    addr = address or default_address()
    if sys.platform == "win32":
        return _WinListener(addr)
    Path(addr).parent.mkdir(parents=True, exist_ok=True)
    return _PosixListener(addr)


def connect(address: str | None = None):
    addr = address or default_address()
    if sys.platform == "win32":
        return _win_connect(addr)
    return _posix_connect(addr)
