"""
transport.py — newline-delimited JSON transport for the crypto daemon.

Uses a TCP socket bound to 127.0.0.1 on both POSIX and Windows. A TCP
loopback socket is the smallest portable choice that lets QTcpSocket on
the C++ side talk to the daemon with identical framing on every platform.
The socket never leaves the loopback interface, so it is functionally
equivalent to a local IPC channel.

Wire format: one JSON object per line, terminated by '\n'.
"""

from __future__ import annotations

import json
import socket
import sys

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 47291

# Backwards-compatible address constants — kept so older docs still resolve.
POSIX_SOCKET_PATH = f"{DEFAULT_HOST}:{DEFAULT_PORT}"
WINDOWS_PIPE_PATH = f"{DEFAULT_HOST}:{DEFAULT_PORT}"


def default_address() -> str:
    """Return the default loopback address as 'host:port'."""
    return f"{DEFAULT_HOST}:{DEFAULT_PORT}"


def _parse_address(address: str) -> tuple[str, int]:
    """Parse a 'host:port' string. Plain integers are treated as ports."""
    if ":" in address:
        host, port = address.rsplit(":", 1)
        return host or DEFAULT_HOST, int(port)
    # Bare path (e.g. legacy '/tmp/securemsg-crypto.sock') — fall back to default.
    try:
        return DEFAULT_HOST, int(address)
    except ValueError:
        return DEFAULT_HOST, DEFAULT_PORT


# ---------------------------------------------------------------------------
# Connection wrapper — newline-delimited JSON over a TCP stream
# ---------------------------------------------------------------------------

class _TcpConn:
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


class _TcpListener:
    def __init__(self, address: str):
        host, port = _parse_address(address)
        self.address = f"{host}:{port}"
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow restart without TIME_WAIT delay on POSIX. On Windows
        # SO_REUSEADDR has different semantics; skipping it is safer.
        if sys.platform != "win32":
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)

    def accept(self) -> _TcpConn:
        client, _ = self._sock.accept()
        return _TcpConn(client)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def listen(address: str | None = None):
    return _TcpListener(address or default_address())


def connect(address: str | None = None):
    host, port = _parse_address(address or default_address())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return _TcpConn(s)
