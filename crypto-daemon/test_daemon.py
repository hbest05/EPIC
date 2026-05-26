"""
test_daemon.py — end-to-end test of the crypto daemon.

Spawns two daemon processes (Alice and Bob) with isolated home directories,
drives a complete X3DH handshake, exchanges five in-order messages, then
exercises out-of-order delivery, then a DH ratchet via Bob's first reply.

Run:  python crypto-daemon/test_daemon.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

import transport  # noqa: E402


_PORT_COUNTER = [47300]

def _addr_for(name: str) -> str:
    # Transport is now TCP/loopback on both platforms; hand out distinct
    # ports per test daemon so Alice and Bob don't collide.
    _PORT_COUNTER[0] += 1
    return f"127.0.0.1:{_PORT_COUNTER[0]}"


class DaemonProc:
    def __init__(self, address: str, home_dir: Path):
        env = os.environ.copy()
        env["HOME"] = str(home_dir)
        env["USERPROFILE"] = str(home_dir)  # Windows: Path.home() uses this
        self.address = address
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "main.py"), "--address", address],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 5.0
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                stderr = self.proc.stderr.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"daemon exited early: {stderr}")
            try:
                c = transport.connect(self.address)
                c.close()
                return
            except (FileNotFoundError, ConnectionRefusedError, OSError) as e:
                last_err = e
                time.sleep(0.05)
        raise RuntimeError(f"daemon did not become ready: {last_err}")

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:
                pass


class Client:
    def __init__(self, address: str):
        self.conn = transport.connect(address)

    def req(self, op: str, **params):
        self.conn.send_message({"op": op, "params": params})
        resp = self.conn.recv_message()
        if resp is None:
            raise RuntimeError(f"{op}: no response")
        if resp.get("status") != "ok":
            raise RuntimeError(f"{op}: {resp}")
        return resp["data"]

    def close(self) -> None:
        self.conn.close()


def run_tests() -> None:
    alice_home = Path(tempfile.mkdtemp(prefix="securemsg-alice-"))
    bob_home = Path(tempfile.mkdtemp(prefix="securemsg-bob-"))
    alice_addr = _addr_for("alice")
    bob_addr = _addr_for("bob")

    alice_d = DaemonProc(alice_addr, alice_home)
    bob_d = DaemonProc(bob_addr, bob_home)
    alice = bob = None
    try:
        alice = Client(alice_addr)
        bob = Client(bob_addr)

        print("[1] generate identities")
        alice_id = alice.req("generate_identity", passphrase="alice-pw")
        bob_id = bob.req("generate_identity", passphrase="bob-pw")
        assert {"ik_pub", "sign_pub"} <= alice_id.keys()
        assert {"ik_pub", "sign_pub"} <= bob_id.keys()

        print("[2] bob generates prekeys")
        bob_pre = bob.req("generate_prekeys")
        assert len(bob_pre["opks"]) == 10
        bundle = {
            "ik_pub": bob_id["ik_pub"],
            "sign_pub": bob_id["sign_pub"],
            "spk_pub": bob_pre["spk_pub"],
            "spk_sig": bob_pre["spk_sig"],
            "opk_pub": bob_pre["opks"][0],
        }

        print("[3] alice runs x3dh_send and emits the first ratchet message")
        first = alice.req(
            "x3dh_send", bundle=bundle, peer_user_id="bob", plaintext="hello bob"
        )
        alice_sid = first["session_id"]

        print("[4] bob runs x3dh_receive and decrypts the first message")
        bob_recv = bob.req(
            "x3dh_receive",
            peer_user_id="alice",
            header={
                "ik_a": first["ik_pub"],
                "ek_a": first["ek_pub"],
                "used_opk_pub": first.get("used_opk_pub"),
            },
        )
        bob_sid = bob_recv["session_id"]
        m = first["message"]
        d = bob.req(
            "decrypt_message",
            session_id=bob_sid,
            ciphertext=m["ciphertext"],
            nonce=m["nonce"],
            ratchet_pub=m["ratchet_pub"],
            pn=m["pn"],
            n=m["n"],
        )
        assert d["plaintext"] == "hello bob", d

        print("[5] four more in-order messages")
        for i in range(2, 6):
            m = alice.req("encrypt_message", session_id=alice_sid, plaintext=f"msg {i}")
            r = bob.req(
                "decrypt_message",
                session_id=bob_sid,
                ciphertext=m["ciphertext"],
                nonce=m["nonce"],
                ratchet_pub=m["ratchet_pub"],
                pn=m["pn"],
                n=m["n"],
            )
            assert r["plaintext"] == f"msg {i}", r

        print("[6] out-of-order: alice sends three, bob decrypts [middle, first, last]")
        out_msgs = [
            alice.req("encrypt_message", session_id=alice_sid, plaintext=f"oo {i}")
            for i in (6, 7, 8)
        ]
        for idx in (1, 0, 2):
            m = out_msgs[idx]
            r = bob.req(
                "decrypt_message",
                session_id=bob_sid,
                ciphertext=m["ciphertext"],
                nonce=m["nonce"],
                ratchet_pub=m["ratchet_pub"],
                pn=m["pn"],
                n=m["n"],
            )
            expected = f"oo {6 + idx}"
            assert r["plaintext"] == expected, f"wanted {expected}, got {r}"

        print("[7] bob replies, alice decrypts (DH ratchet on alice's side)")
        # Bob's send chain was bootstrapped during the first decrypt_message,
        # so he can encrypt immediately. Alice's session has dhr == SPK_pub,
        # so receiving Bob's new ratchet pub triggers a DH ratchet step.
        b1 = bob.req("encrypt_message", session_id=bob_sid, plaintext="hi alice")
        a1 = alice.req(
            "decrypt_message",
            session_id=alice_sid,
            ciphertext=b1["ciphertext"],
            nonce=b1["nonce"],
            ratchet_pub=b1["ratchet_pub"],
            pn=b1["pn"],
            n=b1["n"],
        )
        assert a1["plaintext"] == "hi alice", a1

        print("[8] alice replies under her new ratchet, bob auto-DH-ratchets to decrypt")
        a2 = alice.req("encrypt_message", session_id=alice_sid, plaintext="ack")
        b2 = bob.req(
            "decrypt_message",
            session_id=bob_sid,
            ciphertext=a2["ciphertext"],
            nonce=a2["nonce"],
            ratchet_pub=a2["ratchet_pub"],
            pn=a2["pn"],
            n=a2["n"],
        )
        assert b2["plaintext"] == "ack", b2

        print("[9] bad-tag rejection")
        m = alice.req("encrypt_message", session_id=alice_sid, plaintext="tampered")
        bad_ct = m["ciphertext"][:-4] + ("A" * 4)  # flip last 3 bytes of base64
        bad = bob.conn  # send manually to inspect error response
        bob.conn.send_message(
            {
                "op": "decrypt_message",
                "params": {
                    "session_id": bob_sid,
                    "ciphertext": bad_ct,
                    "nonce": m["nonce"],
                    "ratchet_pub": m["ratchet_pub"],
                    "pn": m["pn"],
                    "n": m["n"],
                },
            }
        )
        resp = bob.conn.recv_message()
        assert resp["status"] == "error" and resp["code"] == "decrypt_failed", resp

        print("ALL TESTS PASSED")
    finally:
        if alice:
            try:
                alice.close()
            except Exception:
                pass
        if bob:
            try:
                bob.close()
            except Exception:
                pass
        alice_d.stop()
        bob_d.stop()


if __name__ == "__main__":
    run_tests()
