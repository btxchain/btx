#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The model helper's listener and port mapping, checked at the socket.

feature_modelnet_listen.py and feature_modelbind_privacy.py check what btxd
logs and what getmodelnetworkinfo reports. This test checks what the helper
process actually does:

- the TCP sockets btx-modeld holds in LISTEN state, read from /proc;
- the UDP datagrams it sends to a PCP / NAT-PMP gateway, caught by a local
  probe socket.

Each case where btxd soft-sets -modelbind=off (-listen=0, -proxy, a
loopback-only -bind) must leave the helper with no non-loopback listener
and must send no mapping request. -natpmp=0 must send no mapping request
either. A positive control shows the probe does catch a request, so a
silent probe means the helper stayed quiet, not that the probe is blind.

btxd's own PCP/NAT-PMP mapper asks the machine's real default gateway, and
BTX_MODEL_PCP_GATEWAY only redirects the helper. So btxd itself never runs
here with -natpmp=1: the positive control starts btx-modeld on its own, with
the arguments btxd gave it.
"""

import errno
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import MAX_NODES, PortSeed, assert_equal, p2p_port

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

# PCP and NAT-PMP both use this server port; the helper has no option to change it.
GATEWAY_PORT = 5351
# Ports the helper refuses to map before it sends anything
# (kForbidden in src/modelnet/model_nat.cpp). Keep in sync.
FORBIDDEN_MAP_PORTS = {
    8332, 18332, 18443, 18444, 28332, 28333, 8333, 18333, 38332, 38333,
    18766, 18445, 8334, 28334,
    19334, 19335, 19443, 19444,
    29334, 29335, 48332, 48333,
}
TCP_LISTEN = "0A"


def proc_tcp_listeners(pid):
    """Return the (address, port) pairs pid holds in LISTEN state, from /proc."""
    inodes = set()
    fd_dir = Path(f"/proc/{pid}/fd")
    for fd in fd_dir.iterdir():
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[len("socket:["):-1])
    found = []
    for table, family in (("/proc/net/tcp", socket.AF_INET), ("/proc/net/tcp6", socket.AF_INET6)):
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            local, state, inode = fields[1], fields[3], fields[9]
            if state != TCP_LISTEN or inode not in inodes:
                continue
            addr_hex, port_hex = local.split(":")
            raw = bytes.fromhex(addr_hex)
            # /proc prints each 32-bit word in host (little-endian) order.
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            found.append((socket.inet_ntop(family, raw), int(port_hex, 16)))
    return found


def is_loopback(addr):
    return addr.startswith("127.") or addr in ("::1", "::ffff:127.0.0.1") or addr.startswith("::ffff:127.")


class ModelNetListenSocketsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # -listen=0 refuses the harness's bind=127.0.0.1 config line.
        self.bind_to_localhost_only = False
        self.extra_args = [["-modelnet=0", *MATMUL_OFF_ARGS]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_linux()
        exeext = self.config["environment"].get("EXEEXT", "")
        modeld = Path(self.config["environment"]["BUILDDIR"]) / "bin" / f"btx-modeld{exeext}"
        if not (modeld.is_file() and os.access(modeld, os.X_OK)):
            raise SkipTest("btx-modeld missing")

    def helper_pid(self):
        """The btx-modeld process btxd spawned for node 0."""
        parent = self.nodes[0].process.pid
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
            except OSError:
                continue
            # The comm field may contain spaces; ppid is the 2nd field after its ')'.
            comm = stat[stat.index("(") + 1:stat.rindex(")")]
            ppid = int(stat[stat.rindex(")") + 2:].split()[1])
            if ppid == parent and comm.startswith("btx-modeld"):
                return int(entry.name)
        return None

    def helper_info(self):
        node = self.nodes[0]

        def ready():
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            # nat_status leaves "unknown" once the helper has made (or skipped) its mapping attempt.
            return info.get("helper_ready") is True and info.get("nat_status") not in (None, "unknown")

        self.wait_until(ready, timeout=60)
        return node.getmodelnetworkinfo()

    def start_with(self, args, env=None):
        self.stop_node(0)
        self.start_node(0, extra_args=args, env=env)
        info = self.helper_info()
        self.wait_until(lambda: self.helper_pid() is not None, timeout=30)
        return info

    def non_loopback_listeners(self):
        return [(a, p) for a, p in proc_tcp_listeners(self.helper_pid()) if not is_loopback(a)]

    def helper_argv(self):
        return Path(f"/proc/{self.helper_pid()}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")

    @staticmethod
    def mapping_port():
        """A harness port the helper is willing to map."""
        for n in range(2, MAX_NODES + 1):
            if p2p_port(n) not in FORBIDDEN_MAP_PORTS:
                return p2p_port(n)
        raise AssertionError("every candidate port is on the helper's denylist")

    @staticmethod
    def probe_socket():
        """Bind the gateway port on a loopback address of our own.

        Start from an address derived from the port seed and step on if
        another run holds it, so parallel runs never share the probe.
        """
        span = 200 * 256 * 254
        for i in range(1000):
            k = (PortSeed.n + i) % span
            addr = f"127.{20 + k // (256 * 254)}.{k // 254 % 256}.{1 + k % 254}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((addr, GATEWAY_PORT))
            except OSError as e:
                sock.close()
                if e.errno == errno.EADDRINUSE:
                    continue
                raise
            sock.setblocking(False)
            return addr, sock
        raise AssertionError("no free loopback address for the probe")

    def wait_for_datagrams(self, sock, timeout=30):
        datagrams = []

        def caught():
            datagrams.extend(self.drain(sock))
            return len(datagrams) > 0

        self.wait_until(caught, timeout=timeout)
        return datagrams

    @staticmethod
    def drain(sock):
        datagrams = []
        while True:
            try:
                datagrams.append(sock.recv(2048))
            except BlockingIOError:
                return datagrams

    def run_test(self):
        node = self.nodes[0]
        sock_path = node.chain_path / "modelnet" / "modeld.sock"
        if len(str(sock_path).encode()) >= 104 and not os.environ.get("XDG_RUNTIME_DIR"):
            raise SkipTest(f"tmpdir too deep for the helper's unix socket ({sock_path})")
        args = ["-modelnet=1", "-modelstorage=0", *MATMUL_OFF_ARGS]

        self.log.info("Control: an explicit loopback -modelbind shows up as a loopback listener")
        port = p2p_port(1)
        self.start_with([*args, f"-modelbind=127.0.0.1:{port}"])
        listeners = proc_tcp_listeners(self.helper_pid())
        assert ("127.0.0.1", port) in listeners, listeners
        assert_equal(self.non_loopback_listeners(), [])
        # btxd's own arguments for the helper, reused for the standalone positive control.
        helper_argv = self.helper_argv()

        # Without modelbind in the config the helper would default to
        # 0.0.0.0:29447, so each soft-set below is what closes the port.
        node.replace_in_config([("modelbind=0", "#modelbind=0")])
        unused_proxy = f"127.0.0.1:{p2p_port(3)}"
        soft_sets = [
            ("-listen=0", ["-listen=0"]),
            ("-proxy", [f"-proxy={unused_proxy}"]),
            ("a loopback-only -bind", [f"-bind=127.0.0.1:{p2p_port(4)}"]),
        ]
        for name, extra in soft_sets:
            self.log.info(f"{name}: the helper holds no non-loopback listener")
            info = self.start_with([*args, *extra])
            assert_equal(self.non_loopback_listeners(), [])
            assert_equal(info["nat_status"], "disabled")
        node.replace_in_config([("#modelbind=0", "modelbind=0")])

        gateway, probe = self.probe_socket()
        # BTX_MODEL_PCP_LAB lets the helper map a loopback bind, and
        # BTX_MODEL_PCP_GATEWAY points its requests at our probe.
        lab_env = {"BTX_MODEL_PCP_LAB": "1", "BTX_MODEL_PCP_GATEWAY": gateway}
        map_port = self.mapping_port()
        try:
            self.log.info("Control: a standalone helper with NAT-PMP on sends the probe a mapping request")
            # The node keeps running: its own helper has NAT-PMP off and no lab gateway.
            self.drain(probe)
            with tempfile.TemporaryDirectory(prefix="btxmd") as tmp:
                argv = [a for a in helper_argv if a != "-modelnatpmp=0"
                        and not a.startswith(("-modeldir=", "-modelrpcsocket=", "-modelbind="))]
                argv += [f"-modeldir={tmp}/d", f"-modelrpcsocket={tmp}/s", f"-modelbind=127.0.0.1:{map_port}"]
                helper = subprocess.Popen(argv, env={**os.environ, **lab_env},
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    caught = self.wait_for_datagrams(probe)
                finally:
                    helper.terminate()
                    helper.wait(timeout=30)
            assert len(caught) >= 1, "probe saw no PCP/NAT-PMP request, so the silent case below would prove nothing"

            self.log.info("-natpmp=0: no mapping request leaves the helper")
            self.drain(probe)
            info = self.start_with([*args, "-natpmp=0", f"-modelbind=127.0.0.1:{map_port}"], env=lab_env)
            assert_equal(info["nat_status"], "disabled")
            time.sleep(2)
            assert_equal(self.drain(probe), [])
        finally:
            probe.close()


if __name__ == '__main__':
    ModelNetListenSocketsTest(__file__).main()
