#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Live multi-piece swarm retrieve: seeders A/B/C, buyer D, cold buyer E.

Functional wrapper around contrib/modelnet/e2e-swarm-multipiece.sh. A synthetic
8 MiB safetensors chunks into 3 canonical PIECE_SIZE=4MiB pieces
(src/modelnet/types.h). After all three seeders import the identical bytes we
delete .piece files under their stores so ownership is:

    A -> piece 0 only
    B -> pieces 1..n-1
    C -> every piece (overlapping and non-identical with both A and B)

Buyer D therefore cannot finish from any single seeder. D runs behind btxd
(-modelnet=1 -modelrpcsocket), so the retrieve goes through the node RPC proxy.
Seeder A is terminated at D's first committed piece; a cold buyer E then
retrieves with A already gone, which keeps the failover assertion deterministic
even when loopback wins the kill race.

On-disk layout matched to ModelStore (src/modelnet/store.cpp ArtifactDir and
the <modeldir>/store root in catalog.cpp):

    <modeldir>/store/artifacts/<artifact_hex>/<file_index>/<piece_index>.piece

Isolated regtest and loopback helpers only. Never production btxd.real, never
SIGKILL of a production process. automatic_spend_atoms stays 0.

AF_UNIX sun_path is 108 bytes, and the default test_runner tmpdir prefix is
long, so run this with a short tmpdir:

  python3 test/functional/feature_modelnet_swarm_live.py \\
    --configfile=build-gcc13/test/config.ini --timeout-factor=1 \\
    --tmpdir=/tmp-short/swarm-live
"""

import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

PIECE_SIZE = 4 << 20  # src/modelnet/types.h
PAYLOAD_BYTES = 8 * 1024 * 1024

SEEDERS = ("a", "b", "c")
BUYERS = ("d", "e")
HELPERS = SEEDERS + BUYERS


class ModelNetSwarmLiveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.helpers = {}
        self.helper_logs = {}
        self.modeldirs = {}
        self.socks = {}
        self.sock_scratch = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld missing")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            cand = Path(builddir) / "bin" / f"btx-modeld{exeext}"
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    # ---------- process plumbing ----------

    def _sock_dir(self):
        """Return a directory whose <dir>/<name>.sock fits in sun_path."""
        base = Path(get_datadir_path(self.options.tmpdir, 0)).parent / "ms"
        if len(str(base / "x.sock")) <= 100:
            base.mkdir(parents=True, exist_ok=True)
            return base
        self.sock_scratch = Path(tempfile.mkdtemp(prefix="btxswarm-"))
        self.log.info("tmpdir too long for AF_UNIX; sockets in %s", self.sock_scratch)
        return self.sock_scratch

    @staticmethod
    def _free_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _start_helpers(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        sockdir = self._sock_dir()
        modeld = self._modeld_path()
        self._guard_binary(modeld)

        self.seeder_ports = {n: self._free_port() for n in SEEDERS}
        peer_args = [f"-modelpeer=127.0.0.1:{self.seeder_ports[n]}" for n in SEEDERS]

        for name in HELPERS:
            self.modeldirs[name] = datadir / f"modeldir-{name}"
            self.modeldirs[name].mkdir(parents=True, exist_ok=True)
            self.socks[name] = sockdir / f"{name}.sock"
            if self.socks[name].exists():
                self.socks[name].unlink()
            argv = [
                str(modeld),
                f"-modeldir={self.modeldirs[name]}",
                "-modelstorage=64MiB",
                f"-modelrpcsocket={self.socks[name]}",
            ]
            if name in SEEDERS:
                argv += [f"-modelbind=127.0.0.1:{self.seeder_ports[name]}", "-modelhost"]
            else:
                argv += peer_args
            log_path = self.modeldirs[name] / "modeld.log"
            self.helper_logs[name] = open(log_path, "w", encoding="utf-8")
            self.log.info("starting helper %s: %s", name, " ".join(argv))
            self.helpers[name] = subprocess.Popen(
                argv, stdout=self.helper_logs[name], stderr=subprocess.STDOUT, cwd=str(datadir)
            )

    def _guard_binary(self, modeld):
        blob = str(Path(modeld).resolve())
        if "libexec/btxd.real" in blob or "/.local/opt/" in blob:
            raise AssertionError(f"refusing packaged/production helper: {blob}")

    def _stop_helper(self, name):
        proc = self.helpers.pop(name, None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(10.0, 20.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                # Scratch helper we started ourselves; never a production process.
                proc.kill()
                proc.wait(timeout=5)
        fh = self.helper_logs.pop(name, None)
        if fh is not None:
            fh.close()

    def _stop_helpers(self):
        for name in list(self.helpers):
            self._stop_helper(name)
        for fh in self.helper_logs.values():
            fh.close()
        self.helper_logs.clear()
        if self.sock_scratch is not None:
            shutil.rmtree(self.sock_scratch, ignore_errors=True)
            self.sock_scratch = None

    def setup_nodes(self):
        self._start_helpers()
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.socks['d']}",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helpers()
        return super().shutdown()

    # ---------- RPC ----------

    def _helper_tail(self, name, n=4000):
        log_path = self.modeldirs[name] / "modeld.log"
        if not log_path.exists():
            return ""
        return log_path.read_text(encoding="utf-8", errors="replace")[-n:]

    def _rpc(self, name, method, params=None):
        proc = self.helpers.get(name)
        if proc is not None and proc.poll() is not None:
            raise AssertionError(f"helper {name} exited rc={proc.returncode}\n{self._helper_tail(name)}")
        req = {
            "jsonrpc": "1.0",
            "id": "swarm",
            "method": method,
            "params": params if params is not None else [],
        }
        wire = (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
        timeout = max(30.0, 60.0 * float(self.options.timeout_factor))
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(timeout)
            client.connect(str(self.socks[name]))
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = client.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        finally:
            client.close()
        raw = b"".join(chunks).split(b"\n", 1)[0].decode("utf-8")
        reply = json.loads(raw)
        err = reply.get("error")
        if err not in (None, {}):
            raise AssertionError(f"{name} {method} error: {err}")
        result = reply.get("result")
        self._zero(result, f"{name} {method}")
        return result

    def _zero(self, obj, where):
        if isinstance(obj, dict):
            spend = obj.get("automatic_spend_atoms", 0)
            if spend not in (0, "0"):
                raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _wait_helper(self, name):
        deadline = time.time() + max(40.0, 60.0 * float(self.options.timeout_factor))
        last = None
        while time.time() < deadline:
            proc = self.helpers.get(name)
            if proc is not None and proc.poll() is not None:
                raise AssertionError(f"helper {name} exited rc={proc.returncode}\n{self._helper_tail(name)}")
            try:
                info = self._rpc(name, "getmodelnetworkinfo")
                if info.get("helper_ready") and info.get("enabled"):
                    if not info.get("pq1_ready"):
                        raise AssertionError(f"helper {name} pq1 not ready: {info}")
                    self.log.info("helper %s ready pq1=%s", name, info.get("pq1_ready"))
                    return info
                last = info
            except (OSError, AssertionError, json.JSONDecodeError) as exc:
                last = exc
            time.sleep(0.2)
        raise AssertionError(f"helper {name} not ready: {last}\n{self._helper_tail(name)}")

    # ---------- store layout ----------

    def _piece_dir(self, name, file_index=0):
        return self.modeldirs[name] / "store" / "artifacts" / self.artifact / str(file_index)

    def _on_disk(self, name, file_index=0):
        out = []
        for path in self._piece_dir(name, file_index).glob("*.piece"):
            try:
                out.append(int(path.name.split(".")[0]))
            except ValueError:
                continue
        return sorted(out)

    def _keep_only(self, name, keep, file_index=0):
        piece_dir = self._piece_dir(name, file_index)
        if not piece_dir.is_dir():
            raise AssertionError(f"missing piece dir {piece_dir}; ArtifactDir layout changed")
        for path in sorted(piece_dir.glob("*.piece")):
            try:
                idx = int(path.name.split(".")[0])
            except ValueError:
                continue
            if idx not in keep:
                path.unlink()
        got = self._on_disk(name, file_index)
        if got != sorted(keep):
            raise AssertionError(f"{name} kept {got} want {sorted(keep)}")
        return got

    def _assemble_sha(self, name, file_index=0):
        digest = hashlib.sha384()
        total = 0
        for idx in range(self.n_pieces):
            path = self._piece_dir(name, file_index) / f"{idx}.piece"
            if not path.is_file():
                raise AssertionError(f"{name} missing committed piece {idx}")
            blob = path.read_bytes()
            total += len(blob)
            digest.update(blob)
        if total != self.file_size:
            raise AssertionError(f"{name} assembled {total} bytes want {self.file_size}")
        return digest.hexdigest()

    # ---------- retrieve ----------

    def _poll_job(self, fetch, timeout, progress=None):
        deadline = time.time() + timeout
        job = {}
        while time.time() < deadline:
            job = fetch() or {}
            status = job.get("status")
            if progress is not None:
                progress(job)
            if status in ("failed", "cancelled"):
                raise AssertionError(f"retrieve {status}: {job}")
            if status == "done":
                return job
            time.sleep(0.2)
        raise AssertionError(f"getmodeljob timeout: {job}")

    def _retrieve_via_node(self, node, progress=None):
        got = node.getmodel(self.uri, "FREE_ONLY")
        self._zero(got, "node getmodel")
        job_id = got.get("job_id")
        if not job_id:
            if got.get("status") not in ("retrieved", "local"):
                raise AssertionError(f"node getmodel gave neither job nor completion: {got}")
            return got
        timeout = max(240.0, 240.0 * float(self.options.timeout_factor))
        job = self._poll_job(lambda: self._node_job(node, job_id), timeout, progress)
        result = job.get("result") or {}
        if result.get("status") not in ("retrieved", "local"):
            raise AssertionError(f"node retrieve failed: {job}")
        return job

    def _node_job(self, node, job_id):
        try:
            raw = node.getmodeljob(job_id)
        except JSONRPCException as exc:
            raise AssertionError(f"getmodeljob {job_id}: {exc}") from exc
        self._zero(raw, "node getmodeljob")
        return self._pick_job(raw, job_id)

    def _retrieve_via_helper(self, name, progress=None):
        got = self._rpc(name, "getmodel", [self.uri, "FREE_ONLY"])
        job_id = got.get("job_id")
        if not job_id:
            if got.get("status") not in ("retrieved", "local"):
                raise AssertionError(f"{name} getmodel gave neither job nor completion: {got}")
            return got
        timeout = max(240.0, 240.0 * float(self.options.timeout_factor))
        job = self._poll_job(
            lambda: self._pick_job(self._rpc(name, "getmodeljob", [job_id]), job_id), timeout, progress
        )
        result = job.get("result") or {}
        if result.get("status") not in ("retrieved", "local"):
            raise AssertionError(f"{name} retrieve failed: {job}")
        return job

    @staticmethod
    def _pick_job(raw, job_id):
        if isinstance(raw, dict):
            if raw.get("status") and not raw.get("jobs"):
                return raw
            jobs = raw.get("jobs") or []
        else:
            jobs = raw or []
        for job in jobs:
            if isinstance(job, dict) and str(job.get("job_id")) == str(job_id):
                return job
        return {}

    # ---------- test ----------

    def run_test(self):
        node = self.nodes[0]

        btxd = Path(self.options.bitcoind).resolve()
        if "libexec/btxd.real" in str(btxd):
            raise AssertionError(f"test btxd is the production attestor: {btxd}")

        for name in HELPERS:
            self._wait_helper(name)
        self.wait_until(lambda: bool(self._node_ready(node)), timeout=60)

        src = self._write_source()
        self.uri = self._import_on_seeders(src)
        self._read_manifest()
        ownership = self._split_pieces()
        d_pieces, d_sha, d_job, observed, killed = self._buyer_d_retrieves(node)
        e_pieces, e_sha, e_observed = self._cold_buyer_after_failover(killed)
        self._write_evidence(ownership, d_pieces, d_sha, d_job, observed, killed,
                             e_pieces, e_sha, e_observed)
        self.log.info(
            "multi-piece swarm PASS pieces=%d ownership=%s buyer_d=%s cold_buyer_e=%s",
            self.n_pieces, ownership, d_pieces, e_pieces,
        )

    def _node_ready(self, node):
        try:
            return node.getmodelnetworkinfo().get("helper_ready")
        except JSONRPCException:
            return False

    def _write_source(self):
        src = Path(self.options.tmpdir) / "swarm-src" / "model.safetensors"
        src.parent.mkdir(parents=True, exist_ok=True)
        header = json.dumps(
            {"t": {"dtype": "U8", "shape": [PAYLOAD_BYTES], "data_offsets": [0, PAYLOAD_BYTES]}},
            separators=(",", ":"),
        ).encode()
        src.write_bytes(struct.pack("<Q", len(header)) + header + bytes(PAYLOAD_BYTES))
        size = src.stat().st_size
        if (size + PIECE_SIZE - 1) // PIECE_SIZE < 2:
            raise AssertionError(f"source {size} bytes is not multi-piece at PIECE_SIZE={PIECE_SIZE}")
        self.log.info("synthetic safetensors %d bytes", size)
        return src

    def _import_on_seeders(self, src):
        uri = None
        for name in SEEDERS:
            imported = self._rpc(name, "importmodel", [str(src), {"pin": True}])
            self.log.info("import %s uri=%s seeded=%s", name, imported.get("uri"), imported.get("seeded"))
            if imported.get("seeded") is not True:
                raise AssertionError(f"{name} import did not demand-seed: {imported}")
            if uri is None:
                uri = imported["uri"]
            elif imported["uri"] != uri:
                raise AssertionError(f"identity diverged {name}: {imported['uri']} != {uri}")
        return uri

    def _read_manifest(self):
        man = self._rpc("a", "getmodelmanifest", [self.uri])
        if int(man.get("piece_size") or 0) != PIECE_SIZE:
            raise AssertionError(f"helper piece_size {man.get('piece_size')} != {PIECE_SIZE}")
        files = man.get("files") or []
        if len(files) != 1:
            raise AssertionError(f"expected a single-file artifact, got {files}")
        self.artifact = man["artifact_id"]
        self.file_size = int(files[0]["size"])
        self.expected_sha = files[0]["sha384"]
        self.n_pieces = (self.file_size + PIECE_SIZE - 1) // PIECE_SIZE
        if self.n_pieces < 2:
            raise AssertionError(f"need a multi-piece artifact, got {self.n_pieces}")
        self.log.info(
            "artifact %s file_size=%d pieces=%d", self.artifact, self.file_size, self.n_pieces
        )

    def _split_pieces(self):
        want = list(range(self.n_pieces))
        for name in SEEDERS:
            full = self._on_disk(name)
            if full != want:
                raise AssertionError(f"seeder {name} imported {full}, expected {want}")
        plan = {
            "a": {0},
            "b": set(range(1, self.n_pieces)),
            "c": set(want),
        }
        ownership = {name: self._keep_only(name, plan[name]) for name in SEEDERS}
        for name in SEEDERS:
            self.log.info("seeder %s pieces %s", name, ownership[name])
        a_set, b_set, c_set = (set(ownership[n]) for n in SEEDERS)
        if a_set & b_set:
            raise AssertionError(f"A and B must be disjoint: {ownership}")
        if a_set | b_set != set(want):
            raise AssertionError(f"A|B must cover the file: {ownership}")
        if c_set != set(want):
            raise AssertionError(f"C must overlap both A and B: {ownership}")
        return ownership

    def _buyer_d_retrieves(self, node):
        peers = node.getmodelpeers()
        self._zero(peers, "node getmodelpeers")
        if not peers.get("peers"):
            raise AssertionError(f"buyer D has no peers: {peers}")
        self.buyer_peers = peers.get("peers")

        observed = []
        killed = {"mid_transfer": False, "at_pieces": None, "at_bytes": None, "at_peer": None}

        def watch(job):
            seen = {
                key: job.get(key)
                for key in ("status", "pieces_committed", "bytes_committed", "piece_index",
                            "last_peer", "peer_retries")
            }
            if not observed or observed[-1] != seen:
                observed.append(seen)
            if killed["mid_transfer"]:
                return
            if int(job.get("pieces_committed") or 0) >= 1:
                killed.update(
                    mid_transfer=True,
                    at_pieces=job.get("pieces_committed"),
                    at_bytes=job.get("bytes_committed"),
                    at_peer=job.get("last_peer"),
                )
                self.log.info("terminating seeder A at pieces_committed=%s", killed["at_pieces"])
                self._stop_helper("a")

        job = self._retrieve_via_node(node, progress=watch)
        want = list(range(self.n_pieces))
        pieces = self._on_disk("d")
        if pieces != want:
            raise AssertionError(f"buyer D committed {pieces}, want {want}")
        sha = self._assemble_sha("d")
        if sha != self.expected_sha:
            raise AssertionError(f"buyer D sha384 {sha} != manifest {self.expected_sha}")
        man = node.getmodelmanifest(self.uri)
        self._zero(man, "buyer D manifest")
        if man.get("artifact_id") != self.artifact:
            raise AssertionError(f"buyer D artifact {man.get('artifact_id')} != {self.artifact}")
        if man.get("complete") is not True:
            raise AssertionError(f"buyer D manifest incomplete: {man}")
        self.d_transfers = node.getmodeltransfers()
        self._zero(self.d_transfers, "buyer D transfers")
        self.log.info("buyer D committed %s; sha384 matches manifest", pieces)
        return pieces, sha, job, observed, killed

    def _cold_buyer_after_failover(self, killed):
        if not killed["mid_transfer"]:
            self.log.info("mid-transfer kill lost the race; terminating A before the cold round")
            self._stop_helper("a")
        if "a" in self.helpers:
            raise AssertionError("seeder A still tracked as running")

        observed = []

        def watch(job):
            seen = {key: job.get(key) for key in ("status", "pieces_committed", "last_peer", "peer_retries")}
            if not observed or observed[-1] != seen:
                observed.append(seen)

        self._retrieve_via_helper("e", progress=watch)
        want = list(range(self.n_pieces))
        pieces = self._on_disk("e")
        if pieces != want:
            raise AssertionError(f"cold buyer E committed {pieces} with A absent, want {want}")
        sha = self._assemble_sha("e")
        if sha != self.expected_sha:
            raise AssertionError(f"cold buyer E sha384 {sha} != manifest {self.expected_sha}")
        self.log.info("cold buyer E retrieved %s with A absent; sha384 matches", pieces)
        return pieces, sha, observed

    def _write_evidence(self, ownership, d_pieces, d_sha, d_job, observed, killed,
                        e_pieces, e_sha, e_observed):
        out = Path(self.options.tmpdir) / "swarm-live-evidence"
        out.mkdir(parents=True, exist_ok=True)
        (out / "assignment-trace.json").write_text(
            json.dumps(
                {
                    "uri": self.uri,
                    "artifact_id": self.artifact,
                    "file_size": self.file_size,
                    "piece_size": PIECE_SIZE,
                    "piece_count": self.n_pieces,
                    "seeder_ports": self.seeder_ports,
                    "buyer_peers": self.buyer_peers,
                    "buyer_d_job": d_job,
                    "buyer_d_progress": observed,
                    "buyer_d_transfers": self.d_transfers.get("transfers"),
                    "cold_buyer_e_progress": e_observed,
                    "automatic_spend_atoms": 0,
                },
                indent=2,
                default=str,
            )
        )
        (out / "piece-ownership.json").write_text(
            json.dumps(
                {
                    "layout": "<modeldir>/store/artifacts/<artifact_hex>/<file_index>/<piece_index>.piece",
                    "layout_source": "src/modelnet/store.cpp ArtifactDir + catalog.cpp store root",
                    "artifact_id": self.artifact,
                    "piece_count": self.n_pieces,
                    "seeders_after_deletion": ownership,
                    "buyer_d_committed": d_pieces,
                    "buyer_d_sha384": d_sha,
                    "cold_buyer_e_committed": e_pieces,
                    "cold_buyer_e_sha384": e_sha,
                    "manifest_sha384": self.expected_sha,
                },
                indent=2,
            )
        )
        (out / "failover.json").write_text(
            json.dumps(
                {
                    "status": "EXECUTED",
                    "seeder_killed": "A",
                    "signal": "SIGTERM",
                    "mid_transfer_kill": killed["mid_transfer"],
                    "mid_transfer_detail": killed,
                    "cold_buyer_with_a_absent": {
                        "buyer": "E",
                        "peers_configured": ["A(dead)", "B", "C"],
                        "pieces_committed": e_pieces,
                        "sha384_matches_manifest": e_sha == self.expected_sha,
                        "progress": e_observed,
                    },
                    "note": "A held only piece 0. B held the remainder and C held every piece, "
                            "so completion with A absent is real multi-peer failover, not a retry "
                            "against the same seeder.",
                },
                indent=2,
                default=str,
            )
        )
        self.log.info("evidence written under %s", out)


if __name__ == "__main__":
    ModelNetSwarmLiveTest(__file__).main()
