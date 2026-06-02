"""
main.py — crypto-daemon entry point.

Accepts connections on a TCP loopback socket (127.0.0.1:47291 by default),
reads framed JSON requests, dispatches them through handlers.handle(), and
writes the JSON response back on the same connection. One connection may
issue many sequential requests.

Single-threaded: this is a local daemon for one user; concurrent connections
serialize. The C++ client is also single-threaded with respect to crypto.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys

import transport
from handlers import DaemonState, handle

logging.basicConfig(
    level=os.environ.get("SECUREMSG_LOG_LEVEL", "INFO").upper(),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def handle_connection(conn, state: DaemonState) -> None:
    try:
        while True:
            req = conn.recv_message()
            if req is None:
                return
            resp = handle(state, req)
            conn.send_message(resp)
    except (BrokenPipeError, ConnectionResetError):
        return
    except Exception as e:
        # Last-ditch: tell the client the transport choked, do not crash daemon.
        try:
            conn.send_message(
                {"status": "error", "code": "transport", "message": type(e).__name__}
            )
        except Exception:
            pass
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureMsg crypto daemon")
    parser.add_argument(
        "--address",
        help="TCP address as host:port (default: 127.0.0.1:47291)",
    )
    args = parser.parse_args()

    addr = args.address or transport.default_address()
    listener = transport.listen(addr)
    print(f"crypto-daemon: listening on {addr}", file=sys.stderr, flush=True)

    state = DaemonState()

    def _shutdown(signum, frame):  # noqa: ARG001
        listener.close()
        sys.exit(0)

    for sig_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig_name):
            try:
                signal.signal(getattr(signal, sig_name), _shutdown)
            except (ValueError, OSError):
                pass

    try:
        while True:
            try:
                conn = listener.accept()
            except (KeyboardInterrupt, SystemExit):
                break
            except OSError:
                break
            handle_connection(conn, state)
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
