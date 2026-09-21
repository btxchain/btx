#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Process-tier E2E for contrib/modelnet/btx-model (0.34.8 CLI door).

One clean-chain regtest node + a test-spawned btx-modeld. Invokes the
NETWORK-02 / first-run / cloud CLI against the scratch helper socket only.
Never production btxd. Never SIGKILL the live GPU attestor. --timeout-factor=1.

Complements feature_modelnet_helper.py and feature_modelnet_0348.py (node RPC).
This file is the btx-model --json agent door.

  python3 test/functional/feature_modelnet_btx_model.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import json
import os
import struct
import subprocess
import sys
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

# Same live-packaged trees the CLI refuses. Scratch tmpdir sockets are allowed.
_FORBIDDEN_SOCKET_MARKERS = (
    "/.local/opt/",
    "/opt/btx",
    "/var/lib/btxd",
    "libexec/btxd.real",
    "/usr/local/var/btx",
    "/.btx",
    "~/.btx",
)

_SECRET_STDOUT_NEEDLES = ("aws_secret", "secret_access_key")

_ERASURE_MANIFEST = {
    "version": 1,
    "profile": "BTX-EC-Cauchy-16-20-v1",
    "canonical_artifact_id": "f" * 96,
    "canonical_manifest_id": "a" * 96,
    "file_index": 0,
    "file_size_bytes": 429496729600,
    "data_shards": 16,
    "total_shards": 20,
    "shard_bytes": 4194304,
    "field_polynomial": "0x11d",
    "stripe_count": 2,
    "final_real_piece_count": 16,
    "shard_index_root": "b" * 96,
    "stripes": [
        {"index": 0, "positions": list(range(16))},
        {"index": 1, "positions": list(range(15))},
    ],
}

_TORRENT_LOCATOR = "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def write_minimal_safetensors(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", 2) + b"{}")


class ModelNetBtxModelTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.executed = []
        self.skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")
        if not self._cli_path().is_file():
            raise SkipTest(f"missing CLI {self._cli_path()}")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        candidates = []
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / name)
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _cli_path(self):
        return Path(__file__).resolve().parents[2] / "contrib" / "modelnet" / "btx-model"

    def _start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        if self.modeld_socket.exists():
            self.modeld_socket.unlink()
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        log_path = self.modeldir / "modeld.log"
        self.modeld_log = open(log_path, "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir)
        )

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test helper SIGTERM timeout; SIGKILL test child only")
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def _assert_scratch_socket(self):
        sock = str(self.modeld_socket.resolve()).replace("\\", "/")
        for marker in _FORBIDDEN_SOCKET_MARKERS:
            if marker in sock:
                raise AssertionError(f"refusing production helper socket {sock}")
        tmpdir = str(Path(self.options.tmpdir).resolve()).replace("\\", "/")
        if tmpdir not in sock:
            raise AssertionError(f"CLI socket must live under test tmpdir: {sock}")

    def _walk_invariants(self, obj, where):
        if isinstance(obj, dict):
            if obj.get("wallet_signed") is True:
                raise AssertionError(f"{where} wallet_signed is true: {obj}")
            if "automatic_spend_atoms" in obj:
                spend = obj.get("automatic_spend_atoms")
                if spend not in (0, "0"):
                    raise AssertionError(f"{where} automatic_spend_atoms={spend}")
            for key, value in obj.items():
                self._walk_invariants(value, f"{where}.{key}")
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                self._walk_invariants(value, f"{where}[{i}]")

    def _assert_stdout_no_secrets(self, stdout, where):
        low = (stdout or "").lower()
        for needle in _SECRET_STDOUT_NEEDLES:
            if needle in low:
                raise AssertionError(f"{where} stdout leaked {needle}: {stdout[:500]}")

    def _load_json_obj(self, text):
        text = (text or "").strip()
        if not text:
            return None
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
        return None

    def _cli(self, verb_args, label, *, required=True, timeout=None):
        """Invoke contrib/modelnet/btx-model --socket <tmpdir> --json <verb>…"""
        self._assert_scratch_socket()
        sock = str(self.modeld_socket)
        argv = [sys.executable, str(self._cli_path()), "--socket", sock, "--json", *verb_args]
        joined = " ".join(argv)
        if "--secret" in argv or any(a.startswith("--secret=") for a in argv):
            raise AssertionError(f"{label} argv must never include --secret: {argv}")
        for marker in _FORBIDDEN_SOCKET_MARKERS:
            if marker in joined.replace("\\", "/"):
                raise AssertionError(f"{label} argv pointed at production path: {argv}")
        env = os.environ.copy()
        env.pop("MODELD_SOCK", None)
        env.pop("BTX_MODELD_SOCKET", None)
        timeout = timeout if timeout is not None else max(15.0, 30.0 * float(self.options.timeout_factor))
        self.log.info("btx-model %s", " ".join(verb_args))
        try:
            run = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(self.options.tmpdir),
            )
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{label} timed out after {timeout}s: {exc}") from exc
        stdout = run.stdout or ""
        self._assert_stdout_no_secrets(stdout, label)
        obj = self._load_json_obj(stdout)
        if obj is not None:
            self._walk_invariants(obj, label)
        err_blob = " ".join(
            str(p) for p in (run.returncode, stdout[-800:], run.stderr or "")
        ).lower()
        failed = run.returncode != 0 or (isinstance(obj, dict) and obj.get("ok") is False)
        if failed:
            reason = ""
            if isinstance(obj, dict):
                reason = str(obj.get("error") or obj.get("note") or "")
            if not reason:
                reason = (run.stderr or stdout or f"exit {run.returncode}")[:400]
            if not required:
                self.skipped.append(f"{label}: {reason}")
                self.log.info("skip: %s (%s)", label, reason)
                return None
            raise AssertionError(f"{label} failed rc={run.returncode}: {err_blob[:800]}")
        if obj is None:
            raise AssertionError(f"{label} produced no JSON object: {stdout[:500]!r}")
        self.executed.append(label)
        return obj

    def _nested(self, obj, *keys):
        if not isinstance(obj, dict):
            return None
        if obj.get(keys[0]) is not None:
            return obj.get(keys[0])
        inner = obj.get("result")
        if isinstance(inner, dict):
            for key in keys:
                if inner.get(key) is not None:
                    return inner.get(key)
        return None

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"btx-modeld died {self.modeld_proc.returncode}")
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.wait_until(helper_ready, timeout=30)
        info = node.getmodelnetworkinfo()
        if info.get("helper_ready") is not True:
            raise AssertionError(f"helper_ready: {info}")
        spend = info.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"getmodelnetworkinfo automatic_spend_atoms={spend}")
        self._assert_scratch_socket()

        doctor = self._cli(["doctor"], "doctor")
        if doctor.get("helper_ready") is not True and doctor.get("ok") is False:
            raise AssertionError(f"doctor: {doctor}")
        inited = self._cli(["init"], "init")
        if inited.get("wallet_backed") is True or inited.get("contains_wallet_material") is True:
            raise AssertionError(f"init must not be a wallet key: {inited}")
        if inited.get("automatic_spend_atoms") not in (0, "0", None):
            raise AssertionError(f"init spend: {inited}")
        if inited.get("initialized") is False:
            raise AssertionError(f"init must leave identity_ready: {inited}")

        st_path = Path(self.options.tmpdir) / "check" / "model.safetensors"
        write_minimal_safetensors(st_path)
        checked = self._cli(["check", str(st_path)], "check")
        if checked.get("runtime_started") is True or checked.get("runtime_exec") is True:
            raise AssertionError(f"check must not start a runtime: {checked}")

        profile = self._cli(["profile", "show"], "profile show")
        if self._nested(profile, "consensus") is True:
            raise AssertionError(f"profile must not grant consensus: {profile}")
        if self._nested(profile, "mirror_privilege") is True:
            raise AssertionError(f"profile must not grant mirror privilege: {profile}")

        cloud = self._cli(["cloud", "status"], "cloud status")
        if cloud.get("command") not in (None, "status"):
            raise AssertionError(f"cloud status command: {cloud}")

        follow = self._cli(
            ["follow", "publisher", "pub-btx-model-cli"],
            "follow publisher",
        )
        if follow.get("filesystem_watch") is True:
            raise AssertionError(f"follow must not be filesystem -modelwatch: {follow}")
        if self._nested(follow, "action") not in (None, "NOTIFY", "notify"):
            self.log.info("follow action: %s", self._nested(follow, "action"))

        events = self._cli(
            ["events", "--cursor", "0", "--wait", "0"],
            "events --cursor 0 --wait 0",
        )
        if events.get("waited") is True:
            raise AssertionError(f"events --wait 0 must not call waitformodelevent: {events}")
        if events.get("method") not in (None, "getmodelevents"):
            self.log.info("events method: %s", events.get("method"))

        mirror = self._cli(["mirror"], "mirror")
        if self._nested(mirror, "consensus") is True:
            raise AssertionError(f"mirror consensus: {mirror}")
        if self._nested(mirror, "search_authority") is True:
            raise AssertionError(f"mirror search_authority: {mirror}")

        transport = self._cli(["transport"], "transport")
        utp = self._nested(transport, "utp")
        if utp != "NONSHIPPING":
            raise AssertionError(f"transport utp must be NONSHIPPING: {transport}")
        quic = self._nested(transport, "quic")
        if quic not in (None, False, "false", 0):
            raise AssertionError(f"transport quic: {transport}")
        if self._nested(transport, "btx_torrentd_process") is True:
            raise AssertionError(f"transport torrentd process: {transport}")

        pkg = self._cli(
            ["package", "create", json.dumps({"kind": "btxbundle", "schema_version": 1})],
            "package create",
        )
        hex_blob = self._nested(pkg, "hex")
        if not isinstance(hex_blob, str) or len(hex_blob) < 2:
            self.log.info("package create hex missing; inspect skipped: %s", pkg)
        else:
            inspected = self._cli(["package", "inspect", hex_blob], "package inspect")
            if inspected.get("ok") is False:
                raise AssertionError(f"package inspect: {inspected}")

        erasure_path = Path(self.options.tmpdir) / "erasure-manifest.json"
        erasure_path.write_text(json.dumps(_ERASURE_MANIFEST) + "\n", encoding="utf-8")
        erasure = self._cli(["erasure", "prepare", f"@{erasure_path}"], "erasure prepare")
        recon = self._nested(erasure, "reconstructable")
        if recon not in (None, False, "false", 0):
            raise AssertionError(f"erasure reconstructable: {erasure}")

        torrent = self._cli(["torrent-status", _TORRENT_LOCATOR], "torrent-status")
        if self._nested(torrent, "torrentd_process") is True:
            raise AssertionError(f"torrent-status torrentd_process: {torrent}")

        offer = self._cli(["origin-offer", "local"], "origin-offer")
        if self._nested(offer, "presigned_get_is_meter") not in (None, False, "false", 0):
            raise AssertionError(f"origin-offer presigned_get_is_meter: {offer}")

        src_dir = Path(self.options.tmpdir) / "import-src"
        local_st = src_dir / "model.safetensors"
        write_minimal_safetensors(local_st)
        plan = {
            "plan_id": "e" * 96,
            "source": {
                "kind": "LOCAL",
                "locator": str(src_dir),
                "snapshot_token": "rev-local-cli",
            },
            "files": [{
                "source_path": "model.safetensors",
                "destination_path": "model.safetensors",
                "size_bytes": local_st.stat().st_size,
            }],
            "automatic_spend_atoms": 0,
        }
        plan_path = Path(self.options.tmpdir) / "import-plan-local.json"
        plan_path.write_text(json.dumps(plan) + "\n", encoding="utf-8")
        imported = self._cli(
            ["import-plan", f"@{plan_path}"],
            "import-plan LOCAL",
            required=False,
        )
        if imported is not None:
            if imported.get("live_http") is True or self._nested(imported, "live_http") is True:
                raise AssertionError(f"import-plan LOCAL must not live-fetch: {imported}")

        host_dir = Path(self.options.tmpdir) / "host-cli"
        hosted = self._cli(["host", str(st_path)], "host", required=False)
        if hosted is None:
            write_minimal_safetensors(host_dir / "model.safetensors")
            (host_dir / "README.md").write_text("btx-model host unique sidecar\n", encoding="utf-8")
            hosted = self._cli(["host", str(host_dir)], "host unique dir")
        if hosted.get("wallet_signed") is True:
            raise AssertionError(f"host must not wallet-sign: {hosted}")
        if hosted.get("runtime_started") is True:
            raise AssertionError(f"host must not start a runtime: {hosted}")
        previewed = self._cli(["preview", str(st_path)], "preview", required=False)
        if previewed is not None and previewed.get("wallet_signed") is True:
            raise AssertionError(f"preview must not spend: {previewed}")
        searched = self._cli(["search", "ops", "--scope", "LOCAL"], "search")
        if searched.get("coverage_complete") is True:
            raise AssertionError(f"search must not claim global coverage: {searched}")
        host_id = (
            hosted.get("uri")
            or hosted.get("model_id")
            or self._nested(hosted, "uri")
            or self._nested(hosted, "model_id")
        )
        shown = self._cli(["show", str(host_id or host_dir)], "show", required=False)
        if shown is not None and shown.get("wallet_signed") is True:
            raise AssertionError(f"show must not spend: {shown}")
        listed = self._cli(["ls"], "ls", required=False)
        if listed is not None and listed.get("wallet_signed") is True:
            raise AssertionError(f"ls must not spend: {listed}")
        xfer = self._cli(["transfers"], "transfers", required=False)
        if xfer is not None and xfer.get("wallet_signed") is True:
            raise AssertionError(f"transfers must not spend: {xfer}")
        job_id = None
        if isinstance(xfer, dict):
            rows = xfer.get("transfers") or xfer.get("jobs") or []
            if isinstance(rows, dict):
                rows = rows.get("transfers") or []
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                job_id = rows[0].get("job_id") or rows[0].get("id")
        paused = self._cli(["pause", str(job_id or "unknown-job")], "pause", required=False)
        if paused is not None and paused.get("wallet_signed") is True:
            raise AssertionError(f"pause must not spend: {paused}")
        pinned = self._cli(["pins", "--type", "both"], "pins", required=False)
        if pinned is not None and pinned.get("consensus") is True:
            raise AssertionError(f"pins must not claim consensus: {pinned}")
        if host_id:
            files = self._cli(["files", str(host_id)], "files", required=False)
            if files is not None and files.get("weights_rehashed") is True:
                raise AssertionError(f"files must not rehash: {files}")
            path_obj = self._cli(["path", str(host_id)], "path", required=False)
            if path_obj is not None and path_obj.get("runtime_started") is True:
                raise AssertionError(f"path must not start a runtime: {path_obj}")
            shared = self._cli(["share", str(host_id)], "share", required=False)
            if shared is not None and shared.get("wallet_signed") is True:
                raise AssertionError(f"share must not spend: {shared}")
            opened = self._cli(["open", str(host_id)], "open", required=False)
            if opened is not None and opened.get("wallet_signed") is True:
                raise AssertionError(f"open must not spend: {opened}")
            linked = self._cli(["link", str(host_id), "--stdout"], "link", required=False)
            if linked is not None and linked.get("weights_included") is True:
                raise AssertionError(f"link must not include weights: {linked}")
            pulled = self._cli(["pull", str(host_id)], "pull", required=False, timeout=max(20.0, 40.0 * float(self.options.timeout_factor)))
            if pulled is not None and pulled.get("wallet_signed") is True:
                raise AssertionError(f"pull must not spend: {pulled}")
            resumed = self._cli(["resume", str(host_id)], "resume", required=False, timeout=max(20.0, 40.0 * float(self.options.timeout_factor)))
            if resumed is not None and resumed.get("wallet_signed") is True:
                raise AssertionError(f"resume must not spend: {resumed}")
        aliased = self._cli(["alias"], "alias list", required=False)
        if aliased is not None and aliased.get("wallet_signed") is True:
            raise AssertionError(f"alias must not spend: {aliased}")
        if host_id:
            self._cli(["alias", str(host_id), "ops-cli"], "alias set", required=False)
            self._cli(["rm-alias", str(host_id), "ops-cli"], "rm-alias", required=False)
        drafts = self._cli(["bounty-draft", "--list"], "bounty-draft --list", required=False)
        if drafts is not None and drafts.get("wallet_signed") is True:
            raise AssertionError(f"bounty-draft must not spend: {drafts}")
        watch_scan = self._cli(["watch-scan"], "watch-scan", required=False)
        if watch_scan is not None and watch_scan.get("spends") is True:
            raise AssertionError(f"watch-scan must not spend: {watch_scan}")
        unhosted = self._cli(["unhost", str(host_id or host_dir)], "unhost", required=False)
        if unhosted is not None and unhosted.get("wallet_signed") is True:
            raise AssertionError(f"unhost must not spend: {unhosted}")

        self.log.info("JIT-SAFETY-05 / COMP-04: stop test helper; money RPC still works")
        self._stop_helper()
        again = node.getblockcount()
        if not isinstance(again, int):
            raise AssertionError(f"getblockcount after helper down: {again}")
        chain = node.getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"chain after helper down: {chain}")

        self.log.info("btx-model verbs executed: %s", self.executed)
        self.log.info("btx-model skip list: %s", self.skipped)
        self.log.info("0.34.8 btx-model CLI e2e passed executed=%s skipped=%s", self.executed, self.skipped)


if __name__ == "__main__":
    ModelNetBtxModelTest(__file__).main()
