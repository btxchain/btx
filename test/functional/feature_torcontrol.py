#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that the Tor controller starts every control connection clean.

A mock Tor control port drops the first connection while a reply is still
owed, or after a reply with too many lines. The node must set up its onion
service on the next connection.
"""
import base64
import hashlib
import socket
import threading

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
    tor_port,
)

MAX_LINE_COUNT = 1000


def onion_v3_service_id(seed):
    pubkey = hashlib.sha256(seed).digest()
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2]
    return base64.b32encode(pubkey + checksum + version).decode().lower()


class MockTorControl:
    """Tor control port stand-in. The first connection follows first_conn;
    every later connection gets the normal replies."""

    def __init__(self, port, first_conn):
        self.first_conn = first_conn
        self.service_id = onion_v3_service_id(b"feature_torcontrol")
        self.commands = []  # one list of received commands per connection
        self.lock = threading.Lock()
        self.sock = socket.create_server(("127.0.0.1", port))
        self.sock.settimeout(0.5)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join(timeout=10)
        self.sock.close()

    def connection_commands(self, index):
        with self.lock:
            return list(self.commands[index]) if index < len(self.commands) else []

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            with self.lock:
                index = len(self.commands)
                self.commands.append([])
            threading.Thread(target=self._handle, args=(conn, index), daemon=True).start()

    def _reply(self, command):
        if command == "PROTOCOLINFO 1":
            return '250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor="0.4.8.10"\r\n250 OK\r\n'
        if command == "AUTHENTICATE":
            return "250 OK\r\n"
        if command == "GETINFO net/listeners/socks":
            return '250-net/listeners/socks="127.0.0.1:9050"\r\n250 OK\r\n'
        if command.startswith("ADD_ONION "):
            key = base64.b64encode(hashlib.sha512(b"feature_torcontrol").digest()).decode()
            return f"250-ServiceID={self.service_id}\r\n250-PrivateKey=ED25519-V3:{key}\r\n250 OK\r\n"
        return "510 Unrecognized command\r\n"

    def _handle(self, conn, index):
        conn.settimeout(0.5)
        buf = b""
        try:
            while self.running:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    command = line.decode()
                    with self.lock:
                        self.commands[index].append(command)
                    if index == 0 and self.first_conn == "close_before_reply":
                        return
                    if index == 0 and self.first_conn == "close_mid_reply":
                        conn.sendall(b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n")
                        return
                    if index == 0 and self.first_conn == "too_many_lines":
                        conn.sendall(b"250-Continuing\r\n" * (MAX_LINE_COUNT + 1))
                        continue
                    conn.sendall(self._reply(command).encode())
        except OSError:
            pass
        finally:
            conn.close()


class TorControlTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_case(self, first_conn, port):
        self.log.info(f"First control connection: {first_conn}; the next one must set up the onion service")
        node = self.nodes[0]
        mock = MockTorControl(port, first_conn)
        self.restart_node(0, extra_args=[
            # Separate onion bind, so the node does not warn about a shared port.
            f"-bind=127.0.0.1:{tor_port(0)}=onion",
            f"-torcontrol=127.0.0.1:{port}",
            "-listenonion=1",
            # Never start a real tor from the test.
            "-torexecute=0",
            "-debug=tor",
        ])
        self.wait_until(lambda: len(mock.connection_commands(1)) >= 4, timeout=30)
        assert_equal(mock.connection_commands(0)[0], "PROTOCOLINFO 1")
        commands = mock.connection_commands(1)
        assert_equal(commands[:3], ["PROTOCOLINFO 1", "AUTHENTICATE", "GETINFO net/listeners/socks"])
        assert commands[3].startswith("ADD_ONION ")
        onion = f"{mock.service_id}.onion"
        self.wait_until(lambda: onion in [a["address"] for a in node.getnetworkinfo()["localaddresses"]], timeout=30)
        self.stop_node(0)
        mock.stop()

    def run_test(self):
        self.run_case("close_before_reply", p2p_port(self.num_nodes + 1))
        self.run_case("close_mid_reply", p2p_port(self.num_nodes + 2))
        self.run_case("too_many_lines", p2p_port(self.num_nodes + 3))


if __name__ == '__main__':
    TorControlTest(__file__).main()
