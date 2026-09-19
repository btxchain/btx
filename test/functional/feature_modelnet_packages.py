#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Process-tier E2E for the .btx package vectors in src/test/data/btx-package-vectors.

Three offline lanes over one clean-chain regtest node plus a test-spawned
btx-modeld. No wallet is created or imported, nothing is downloaded, and
automatic_spend_atoms stays 0 everywhere.

  1. btx-open. A btx:// URI or a local .btx/.btxbundle produces an inspection
     preview and nothing else: the wallet stays closed, storage consent is a
     separate step, and a hostile package cannot forge an install line.
  2. Helper package RPCs. inspectbtxpackage reads the same vector files without
     installing, signing, spending, mutating the catalog, or writing AGENTS.md;
     verifybtxpackage fails closed on an unsigned package; the codec-divergence
     pair proves package_core_id, not the file hash, is package identity.
  3. Economy. A release campaign observed with no wallet and no chain
     observation must report its state as an explicit unknown labelled
     helper_observation, never as confirmed funding.

The invalid/ vectors record findings that are open in this tree, so the two
ledgers below name the vectors that are still previewed or still abort today.
A vector that leaves a ledger is a fixed finding and the ledger must be
tightened; a vector that enters one is a regression and fails the test.

  python3 test/functional/feature_modelnet_packages.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import hashlib
import json
import os
import shutil
import subprocess
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

# MODEL_FAMILY has no ResourceKind of its own, so its URI carries the
# COLLECTION kind byte and btx-open prints COLLECTION (finding R7-09).
URI_KIND_TODAY = {"MODEL_FAMILY": "COLLECTION"}

# btx-open's local inspect neither runs the magnet-analog parser nor the
# public-export secret scan: every .btx JSON vector and every well-framed
# .btxbundle previews with an unparseable core, hostile or not. These vectors
# are therefore previewed rather than refused today, and each one still has to
# produce an inert preview that leaks nothing.
PREVIEWED_TODAY = frozenset({
    "control-chars-in-copy-text.btx",
    "dn-in-uri.btx",
    "dup-key-shadowed-float.btxbundle",
    "dup-key-shadowed-secret.btxbundle",
    "dup-key-toplevel-secret.btxbundle",
    "int-overflow-auto-spend.btx",
    "non-btx-uri.btx",
    "nonzero-auto-spend.btx",
    "presigned-url.btx",
    "unknown-schema-version.btx",
})

# getInt<int>() throws past the isNum() guard and btx-open terminates. It
# refuses to preview, which is the invariant this test enforces, but it dies on
# a signal instead of printing an error.
ABORTS_TODAY = frozenset({"int-overflow-core-version.btx"})

# Economy vectors, not package frames: they are cached-observation payloads.
ECONOMY_VECTORS = frozenset({
    "cross-unit-amount-match.json",
    "stale-percent-funded-no-state.json",
})

# The bidi override the control-chars vector uses to dress copy_text up as an
# install line, the presigned capability the mirror vector embeds, and the
# sentinel hidden in the shadowed api_key. None may reach stdout.
BIDI_OVERRIDE = "\u202e"
LEAK_NEEDLES = ("X-Amz-Signature", "BTX_R7_SECRET_SENTINEL")


def write_minimal_safetensors(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")


def parse_kv(stdout):
    """btx-open prints one key=value per line."""
    kv = {}
    for line in (stdout or "").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        kv[key] = value
    return kv


def sha384_file(path):
    return hashlib.sha384(Path(path).read_bytes()).hexdigest()


class ModelNetPackagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.rpc_skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")
        if self._open_path() is None:
            raise SkipTest("btx-open not found")
        if not (self._vectors_src() / "manifest.json").is_file():
            raise SkipTest(f"missing package vectors {self._vectors_src()}")

    def _src_root(self):
        return Path(__file__).resolve().parents[2]

    def _vectors_src(self):
        return self._src_root() / "src" / "test" / "data" / "btx-package-vectors"

    def _bin_path(self, name):
        exeext = self.config["environment"].get("EXEEXT", "")
        candidates = []
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / f"{name}{exeext}")
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / f"{name}{exeext}")
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _modeld_path(self):
        return self._bin_path("btx-modeld")

    def _open_path(self):
        return self._bin_path("btx-open")

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

    # -- btx-open ----------------------------------------------------------

    def _run_open(self, args, storage_budget=None):
        env = os.environ.copy()
        env.pop("BTX_MODEL_STORAGE", None)
        if storage_budget is not None:
            env["BTX_MODEL_STORAGE"] = storage_budget
        timeout = max(15.0, 30.0 * float(self.options.timeout_factor))
        run = subprocess.run(
            [str(self._open_path()), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(self.open_cwd),
        )
        return run

    def _assert_inert_preview(self, kv, stdout, where):
        """Every btx-open preview, hostile input included, promises nothing."""
        if kv.get("action") != "preview-only":
            raise AssertionError(f"{where} action must be preview-only: {kv}")
        if kv.get("wallet") != "not-opened":
            raise AssertionError(f"{where} wallet must stay closed: {kv}")
        # A package cannot forge a second action line to spoof consent.
        if stdout.count("action=") != 1 or "action=install" in stdout:
            raise AssertionError(f"{where} emitted a forged action line: {stdout!r}")
        for key in ("install", "network", "agents_md_write"):
            if key in kv and kv[key] != "false":
                raise AssertionError(f"{where} {key}={kv[key]}: {kv}")
        if "automatic_spend_atoms" in kv and kv["automatic_spend_atoms"] != "0":
            raise AssertionError(f"{where} automatic_spend_atoms={kv['automatic_spend_atoms']}")
        if BIDI_OVERRIDE in stdout:
            raise AssertionError(f"{where} echoed a bidi override: {stdout!r}")
        for needle in LEAK_NEEDLES:
            if needle.lower() in stdout.lower():
                raise AssertionError(f"{where} echoed {needle}: {stdout!r}")

    def _assert_open_cwd_clean(self, where):
        leaked = sorted(p.name for p in self.open_cwd.iterdir())
        if leaked:
            raise AssertionError(f"{where} wrote files next to the caller: {leaked}")

    def _open_uri_lane(self, manifest):
        for name, spec in sorted(manifest["valid"].items()):
            if not name.endswith(".btx"):
                continue
            uri = spec["uri"]
            kind = spec["kind"]
            run = self._run_open([uri])
            if run.returncode != 0:
                raise AssertionError(f"btx-open {kind} URI rc={run.returncode}: {run.stderr}")
            kv = parse_kv(run.stdout)
            self._assert_inert_preview(kv, run.stdout, f"uri {kind}")
            if kv.get("canonical") != uri or kv.get("copy") != uri:
                raise AssertionError(f"uri {kind} did not round-trip: {kv}")
            expected_kind = URI_KIND_TODAY.get(kind, kind)
            if kv.get("kind") != expected_kind:
                raise AssertionError(
                    f"uri {kind} decoded as {kv.get('kind')}, ledger says {expected_kind}"
                )
            if len(kv.get("digest", "")) != 96:
                raise AssertionError(f"uri {kind} digest: {kv}")
            # Preview-first: with no storage budget, consent is still owed.
            if kv.get("storage_consent_required") != "true" or kv.get("storage_bytes") != "0":
                raise AssertionError(f"uri {kind} must ask for storage consent: {kv}")
            self._assert_open_cwd_clean(f"uri {kind}")

        # A granted budget changes the consent answer and nothing else.
        uri = manifest["valid"]["MODEL.btx"]["uri"]
        run = self._run_open([uri], storage_budget="8MiB")
        kv = parse_kv(run.stdout)
        if run.returncode != 0 or kv.get("storage_consent_required") != "false":
            raise AssertionError(f"granted budget: rc={run.returncode} {kv}")
        if kv.get("storage_bytes") != str(8 * 1024 * 1024):
            raise AssertionError(f"granted budget bytes: {kv}")
        self._assert_inert_preview(kv, run.stdout, "uri with budget")
        self._assert_open_cwd_clean("uri with budget")

        # One argv, one subject: no shell, no mixed URI and path.
        for args in ([uri, "extra"], [f"{uri} {self.vectors / 'valid' / 'MODEL.btx'}"]):
            run = self._run_open(args)
            if run.returncode == 0:
                raise AssertionError(f"btx-open accepted {args}: {run.stdout!r}")
            if "action=" in run.stdout:
                raise AssertionError(f"btx-open previewed {args}: {run.stdout!r}")
        self.log.info("btx-open URI previews are preview-only and consent-gated")

    def _open_valid_file_lane(self, manifest):
        for name in sorted(manifest["valid"]):
            path = self.vectors / "valid" / name
            before = sha384_file(path)
            run = self._run_open([str(path)])
            if run.returncode != 0:
                raise AssertionError(f"btx-open {name} rc={run.returncode}: {run.stderr}")
            kv = parse_kv(run.stdout)
            self._assert_inert_preview(kv, run.stdout, f"valid {name}")
            bundle = name.endswith(".btxbundle")
            if kv.get("looks_like_btxbundle") != ("true" if bundle else "false"):
                raise AssertionError(f"valid {name} framing: {kv}")
            # Neither framing of these vectors carries a core, so no package
            # identity is claimed and no core version is asserted.
            if kv.get("core_version") != "unparseable":
                raise AssertionError(
                    f"valid {name} now reports core_version={kv.get('core_version')}; "
                    "the vectors have no core, so update this lane"
                )
            if "package_core_id" in kv:
                raise AssertionError(f"valid {name} invented a core id: {kv}")
            if sha384_file(path) != before:
                raise AssertionError(f"btx-open mutated {name}")
            self._assert_open_cwd_clean(f"valid {name}")
        self.log.info("btx-open local inspect of valid/ is read-only and preview-only")

        # Identify a package by package_core_id, never by the file hash: the
        # same logical package under both framings has two frame digests and
        # one core id.
        core_ids, frame_hashes = set(), set()
        for name in sorted(manifest["codec_divergence"]):
            if not name.endswith(".btxbundle"):
                continue
            path = self.vectors / "codec-divergence" / name
            run = self._run_open([str(path)])
            if run.returncode != 0:
                raise AssertionError(f"btx-open {name} rc={run.returncode}: {run.stderr}")
            kv = parse_kv(run.stdout)
            self._assert_inert_preview(kv, run.stdout, f"divergence {name}")
            # R7 codec-divergence vectors are one logical core v1 package under
            # BTXPKG\\x00\\x01 magic. Frame bytes differ; package_core_id does not.
            # Do not require core v2 — that is a different package family.
            if kv.get("core_version") != "1":
                raise AssertionError(f"divergence {name} core_version: {kv}")
            core_ids.add(kv.get("package_core_id"))
            frame_hashes.add(sha384_file(path))
            self._assert_open_cwd_clean(f"divergence {name}")
        if len(core_ids) != 1 or None in core_ids:
            raise AssertionError(f"codec divergence changed package identity: {core_ids}")
        if len(frame_hashes) != 2:
            raise AssertionError(f"codec divergence vectors are not distinct bytes: {frame_hashes}")
        self.log.info("codec divergence: 2 frame digests, one package_core_id %s", core_ids)

    def _open_invalid_lane(self, manifest):
        previewed, refused, aborted = [], [], []
        for name, spec in sorted(manifest["invalid"].items()):
            if name in ECONOMY_VECTORS:
                continue
            path = self.vectors / "invalid" / name
            before = sha384_file(path)
            run = self._run_open([str(path)])
            if sha384_file(path) != before:
                raise AssertionError(f"btx-open mutated {name}")
            self._assert_open_cwd_clean(f"invalid {name}")
            note = str(spec.get("note", ""))
            refused_by_frame_check = "rejected today" in note.lower()

            if run.returncode == 0:
                if name not in PREVIEWED_TODAY:
                    raise AssertionError(f"{name} must be refused, got: {run.stdout!r}")
                # It previews, so the preview has to be inert.
                self._assert_inert_preview(parse_kv(run.stdout), run.stdout, f"invalid {name}")
                previewed.append(name)
                continue

            if name in PREVIEWED_TODAY:
                raise AssertionError(
                    f"{name} is now refused (rc={run.returncode}); drop it from PREVIEWED_TODAY"
                )
            if "action=" in run.stdout:
                raise AssertionError(f"{name} refused but still previewed: {run.stdout!r}")
            if run.returncode < 0 or run.returncode > 128:
                if name not in ABORTS_TODAY:
                    raise AssertionError(
                        f"{name} killed btx-open (rc={run.returncode}): {run.stderr!r}"
                    )
                aborted.append(name)
                continue
            if name in ABORTS_TODAY:
                raise AssertionError(
                    f"{name} now fails cleanly (rc={run.returncode}); drop it from ABORTS_TODAY"
                )
            if not (run.stderr or "").strip():
                raise AssertionError(f"{name} refused without saying why")
            if refused_by_frame_check:
                refused.append(name)

        expected_refusals = sorted(
            n for n, s in manifest["invalid"].items()
            if "rejected today" in str(s.get("note", "")).lower()
        )
        if refused != expected_refusals:
            raise AssertionError(f"frame refusals {refused} != manifest {expected_refusals}")
        if sorted(previewed) != sorted(PREVIEWED_TODAY):
            raise AssertionError(f"previewed {previewed} != ledger {sorted(PREVIEWED_TODAY)}")
        if sorted(aborted) != sorted(ABORTS_TODAY):
            raise AssertionError(f"aborted {aborted} != ledger {sorted(ABORTS_TODAY)}")
        self.log.info(
            "btx-open refused %s, previewed inertly %s, aborted %s",
            refused, previewed, aborted,
        )

    # -- helper package RPCs ----------------------------------------------

    def _walk_invariants(self, obj, where):
        if isinstance(obj, dict):
            if obj.get("wallet_signed") is True:
                raise AssertionError(f"{where} wallet_signed: {obj}")
            spend = obj.get("automatic_spend_atoms", 0)
            if spend not in (0, "0"):
                raise AssertionError(f"{where} automatic_spend_atoms={spend}")
            for key, value in obj.items():
                self._walk_invariants(value, f"{where}.{key}")
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                self._walk_invariants(value, f"{where}[{i}]")

    def _rpc_missing(self, exc):
        blob = exc.error if isinstance(exc.error, dict) else {}
        msg = str(blob.get("message", exc)).lower()
        return blob.get("code") in (-32601, -32600) or "method not found" in msg

    def _call_or_skip(self, node, method, payload, where):
        """payload=None calls the RPC with no argument at all."""
        try:
            got = getattr(node, method)() if payload is None else getattr(node, method)(payload)
        except JSONRPCException as exc:
            if self._rpc_missing(exc):
                self.log.info("skip missing RPC %s: %s", method, exc)
                self.rpc_skipped.append(method)
                return None
            raise
        self._walk_invariants(got, where)
        return got

    def _rpc_package_lane(self, node, manifest):
        caps = self._call_or_skip(node, "getbtxpackagecapabilities", {}, "capabilities")
        if caps is not None:
            if caps.get("BTXPKG_CORE_V2") is not True:
                raise AssertionError(f"capabilities: {caps}")
            for key in ("wallet_sign", "remote_inference", "writes_project_agents_md"):
                if caps.get(key) is True:
                    raise AssertionError(f"capabilities {key} must stay false: {caps}")

        for name in sorted(manifest["valid"]):
            if not name.endswith(".btxbundle"):
                continue
            path = str(self.vectors / "valid" / name)
            got = self._call_or_skip(node, "inspectbtxpackage", {"path": path}, f"inspect {name}")
            if got is None:
                return
            if got.get("ok") is not True or got.get("frame_integrity") != "PASS":
                raise AssertionError(f"inspect {name}: {got}")
            # These vectors have no core, so they decode as a public bundle
            # rather than a BTX-PJSON1 package.
            if got.get("package_codec") != "BUNDLE_WRITE":
                raise AssertionError(f"inspect {name} codec: {got}")
            for key in ("model_bytes_verified", "installed_software", "executed_runtime",
                        "workspace_agents_written", "imported_catalog"):
                if got.get(key) is True:
                    raise AssertionError(f"inspect {name} claimed {key}: {got}")
            if got.get("signature_status") not in ("UNSIGNED", "NOT_EVALUATED"):
                raise AssertionError(f"inspect {name} signature: {got}")
            # Unsigned is a verification failure, not a pass with a caveat.
            try:
                verified = node.verifybtxpackage({"path": path})
                raise AssertionError(f"verifybtxpackage accepted unsigned {name}: {verified}")
            except JSONRPCException as exc:
                if self._rpc_missing(exc):
                    self.rpc_skipped.append("verifybtxpackage")
                    continue
                blob = str(exc.error if isinstance(exc.error, dict) else exc)
                if "UNSIGNED_PACKAGE" not in blob and "signature" not in blob.lower():
                    raise AssertionError(f"verify {name} wrong error: {blob}") from exc

        for name, spec in sorted(manifest["invalid"].items()):
            if name in ECONOMY_VECTORS or "rejected today" not in str(spec.get("note", "")).lower():
                continue
            path = str(self.vectors / "invalid" / name)
            try:
                got = node.inspectbtxpackage({"path": path})
                raise AssertionError(f"inspectbtxpackage accepted {name}: {got}")
            except JSONRPCException as exc:
                self.log.debug("inspect refused %s: %s", name, exc)

        # Both framings of the one logical package are accepted under the one
        # BTXPKG magic. Only the canonical BTX-PJSON1 byte order decodes as a
        # package, so only that side reports a core_id here; the btx-open lane
        # is where both sides are shown to share one package_core_id.
        codecs, core_ids = {}, set()
        for name in sorted(manifest["codec_divergence"]):
            if not name.endswith(".btxbundle"):
                continue
            path = self.vectors / "codec-divergence" / name
            got = self._call_or_skip(node, "inspectbtxpackage", {"path": str(path)}, f"div {name}")
            if got is None:
                return
            if got.get("ok") is not True or got.get("frame_integrity") != "PASS":
                raise AssertionError(f"inspect {name}: {got}")
            codecs[name] = got.get("package_codec")
            if got.get("core_id") is not None:
                core_ids.add(got["core_id"])
        if len(core_ids) > 1:
            raise AssertionError(f"codec divergence changed package identity: {core_ids}")
        self.log.info("package RPC inspect is inert; divergent codecs %s share id %s", codecs, core_ids)

    # -- economy: explicit offline ----------------------------------------

    def _assert_no_funding_claimed(self, card, where):
        """Offline, a release card states an unknown rather than a funded one."""
        if card.get("chain_observation") is True:
            raise AssertionError(f"{where} claimed a chain observation: {card}")
        if card.get("funding_source") == "CHAIN_OBSERVATION":
            raise AssertionError(f"{where} funding_source: {card}")
        if not str(card.get("state") or "").strip():
            raise AssertionError(f"{where} left state blank instead of explicit: {card}")
        for key in ("confirmed_funded_atoms", "funded_atoms", "pending_funded_atoms"):
            if key in card and card[key] not in (0, "0"):
                raise AssertionError(f"{where} invented {key}: {card}")
        if card.get("funded_percent") not in (None, 0, "0", 0.0):
            raise AssertionError(f"{where} published a funded percent: {card}")

    def _economy_lane(self, node):
        try:
            wallets = node.listwallets()
        except JSONRPCException:
            wallets = []
        if wallets:
            raise AssertionError(f"this test observes with no wallet, found {wallets}")

        # An id nobody published: the answer is an explicit unknown state, not a
        # blank card and not an invented number.
        unknown = self._call_or_skip(node, "getmodelreleaseeconomics", "b" * 96, "unknown release")
        if unknown is None:
            return
        self._assert_no_funding_claimed(unknown, "unknown release")

        src = Path(self.options.tmpdir) / "economy-src" / "model.safetensors"
        write_minimal_safetensors(src)
        hosted = self._call_or_skip(node, "hostmodel", str(src), "hostmodel")
        uri = (hosted or {}).get("uri") or (hosted or {}).get("model_id")
        release_id = None
        if uri:
            try:
                rel = node.createmodelrelease({
                    "uri": uri,
                    "secret32_hex": "a" * 64,
                    "refund_height": 100000,
                })
                self._walk_invariants(rel, "createmodelrelease")
                release_id = rel.get("release_id") or rel.get("id")
            except JSONRPCException as exc:
                self.log.info("no campaign to observe, staying on the unknown-release path: %s", exc)

        card = unknown
        if release_id:
            card = self._call_or_skip(node, "getmodelreleaseeconomics", release_id, "releaseeconomics")
            if card is None:
                return
            # A real campaign, observed with no wallet and no chain
            # observation: every economic number is labelled with its source,
            # and the source is not the chain.
            if card.get("helper_observation") is not True:
                raise AssertionError(f"offline card must be labelled helper_observation: {card}")
            self._assert_no_funding_claimed(card, "campaign offline")
            # cross-unit-amount-match.json: a percentage is a different unit
            # from atoms, so with no known target no percentage is published.
            if card.get("value_known") is True:
                raise AssertionError(f"unfunded campaign claimed a known value: {card}")
            if card.get("secret_disclosed") is True or card.get("plaintext_verified") is True:
                raise AssertionError(f"offline card claimed disclosure: {card}")

        entry = self._call_or_skip(node, "getmodeleconomyentry", release_id or "b" * 96, "economyentry")
        if entry is not None:
            inner = entry.get("release") if isinstance(entry.get("release"), dict) else {}
            if inner.get("chain_observation") is True:
                raise AssertionError(f"economy entry claimed chain observation: {entry}")
            if not str(entry.get("lifecycle_state") or "").strip():
                raise AssertionError(f"economy entry lifecycle_state blank: {entry}")

        status = self._call_or_skip(node, "getmodelfeedstatus", None, "feedstatus")
        if status is not None and status.get("coverage_complete") is True:
            raise AssertionError(f"feed must not claim complete coverage: {status}")

        # stale-percent-funded-no-state.json is a cached observation with a
        # funding number and no state. The live card always carries a state, so
        # such a cache can never be mistaken for the current one.
        stale = json.loads((self.vectors / "invalid" / "stale-percent-funded-no-state.json").read_text())
        if "state" in stale:
            raise AssertionError("stale vector changed shape; it must have no state field")
        if "percent_funded" not in stale:
            raise AssertionError("stale vector must carry a bare funding number")
        self.log.info(
            "offline economy state is explicit: state=%s funding_source=%s",
            card.get("state"), card.get("funding_source"),
        )

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
        self._walk_invariants(info, "getmodelnetworkinfo")

        # Work on copies so the lane can prove btx-open never writes.
        self.vectors = Path(self.options.tmpdir) / "btx-package-vectors"
        if self.vectors.exists():
            shutil.rmtree(self.vectors)
        shutil.copytree(self._vectors_src(), self.vectors)
        self.open_cwd = Path(self.options.tmpdir) / "open-cwd"
        self.open_cwd.mkdir(parents=True, exist_ok=True)
        manifest = json.loads((self.vectors / "manifest.json").read_text(encoding="utf-8"))

        self._open_uri_lane(manifest)
        self._open_valid_file_lane(manifest)
        self._open_invalid_lane(manifest)
        self._rpc_package_lane(node, manifest)
        self._economy_lane(node)

        # Model-plane failures never reach the chain: drop the helper and the
        # node keeps answering.
        self._stop_helper()
        if node.getblockchaininfo().get("chain") != "regtest":
            raise AssertionError("chain after helper down")
        if not isinstance(node.getblockcount(), int):
            raise AssertionError("getblockcount after helper down")
        self.log.info("package vector e2e passed; skipped RPCs=%s", self.rpc_skipped)


if __name__ == "__main__":
    ModelNetPackagesTest(__file__).main()
