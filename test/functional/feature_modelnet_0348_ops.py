#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest E2E for remaining 0.34.8 first-run / cloud / watch / import RPCs.

Complements feature_modelnet_0348.py (AHP + NETWORK-02) and
feature_modelnet_helper.py (import/list/get). Never production btxd.
Never SIGKILL the live GPU attestor. --timeout-factor=1.

  python3 test/functional/feature_modelnet_0348_ops.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import os
import struct
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


def write_minimal_safetensors(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", 2) + b"{}")


class ModelNet0348OpsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        candidates = []
        for env_name in ("BTXMODELD", "BTX_MODELD"):
            env_val = os.environ.get(env_name)
            if env_val:
                candidates.append(Path(env_val))
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

    def _zero_spend(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not an object: {obj}")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")
        dumped = str(obj).lower()
        for needle in ("aws_secret_access_key", "secret_access_key", "id_ed25519"):
            if needle in dumped and "***" not in dumped:
                raise AssertionError(f"{where} leaked secret needle {needle}")

    def _rpc_name(self, fn):
        inner = getattr(fn, "auth_service_proxy_instance", fn)
        name = getattr(inner, "_service_name", None)
        if isinstance(name, str) and name:
            return name.split(".")[-1]
        got = getattr(fn, "__name__", None)
        if isinstance(got, str) and got:
            return got
        return "unknown_rpc"

    def _skip_method_name(self, entry):
        text = str(entry).strip()
        head = text.split(":", 1)[0].strip().split()[0] if text else ""
        if head and head.replace("_", "").isalnum() and head[0].isalpha():
            return head
        return text or "unknown_rpc"

    def _rpc_or_skip(self, fn, *args, **kwargs):
        name = self._rpc_name(fn)
        try:
            return fn(*args, **kwargs)
        except JSONRPCException as exc:
            err = exc.error if isinstance(exc.error, dict) else {}
            if err.get("code") in (-32601, -32602, -32600, -1, -3, -8) or "not found" in str(exc).lower() or "unavailable" in str(exc).lower():
                self.skipped.append(f"{name}: {exc.error}")
                return None
            raise

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
        self._zero_spend(info, "getmodelnetworkinfo")

        setup = node.getsetupstatus()
        if setup.get("automatic_spend_atoms") not in (0, "0"):
            raise AssertionError(f"getsetupstatus spend: {setup}")
        if not isinstance(setup.get("money"), dict):
            raise AssertionError(f"getsetupstatus money: {setup}")
        if setup.get("money", {}).get("chain") != "regtest":
            raise AssertionError(f"getsetupstatus chain: {setup}")
        models = setup.get("models")
        if not isinstance(models, dict):
            raise AssertionError(f"getsetupstatus models: {setup}")
        self._zero_spend(setup, "getsetupstatus")

        check = node.checkmodelsetup()
        self._zero_spend(check, "checkmodelsetup")

        watch_dir = Path(self.options.tmpdir) / "modelwatch"
        watch_dir.mkdir(parents=True, exist_ok=True)
        wstatus = self._rpc_or_skip(node.getmodelwatchstatus)
        if isinstance(wstatus, dict):
            self._zero_spend(wstatus, "getmodelwatchstatus")
        scanned = self._rpc_or_skip(node.scanmodelwatch)
        if isinstance(scanned, dict):
            self._zero_spend(scanned, "scanmodelwatch")

        host_src = Path(self.options.tmpdir) / "host-src" / "model.safetensors"
        write_minimal_safetensors(host_src)
        preview = node.previewmodelimport(str(host_src))
        self._zero_spend(preview, "previewmodelimport")
        hosted = node.hostmodel(str(host_src))
        self._zero_spend(hosted, "hostmodel")
        uri = hosted.get("uri") or hosted.get("model_id")
        if uri:
            shown = self._rpc_or_skip(node.showmodel, uri)
            if isinstance(shown, dict):
                self._zero_spend(shown, "showmodel")
            link = self._rpc_or_skip(node.exportmodellink, uri)
            if isinstance(link, dict):
                self._zero_spend(link, "exportmodellink")
                if link.get("weights_included") is True:
                    raise AssertionError(f"exportmodellink must not include weights: {link}")
            card = self._rpc_or_skip(node.getmodelsharecard, uri)
            if isinstance(card, dict):
                self._zero_spend(card, "getmodelsharecard")
            xfer = self._rpc_or_skip(node.getmodeltransfers)
            if isinstance(xfer, dict):
                self._zero_spend(xfer, "getmodeltransfers")
            aliased = self._rpc_or_skip(node.setmodelalias, uri, "ops-local")
            if isinstance(aliased, dict):
                self._zero_spend(aliased, "setmodelalias")
                aliases = self._rpc_or_skip(node.getmodelaliases)
                if isinstance(aliases, dict):
                    self._zero_spend(aliases, "getmodelaliases")
            copy_text = None
            if isinstance(link, dict):
                share = link.get("share") if isinstance(link.get("share"), dict) else link
                copy_text = share.get("copy_text") if isinstance(share, dict) else None
            if not copy_text and isinstance(shown, dict):
                share = shown.get("share") if isinstance(shown.get("share"), dict) else {}
                copy_text = share.get("copy_text")
            opened = self._rpc_or_skip(node.openmodelshare, copy_text or uri)
            if isinstance(opened, dict):
                self._zero_spend(opened, "openmodelshare")
                if opened.get("wallet_signed") is True:
                    raise AssertionError(f"openmodelshare must not spend: {opened}")

        mining = node.getmininginfo()
        fr = mining.get("first_run")
        if not isinstance(fr, dict):
            raise AssertionError(f"getmininginfo first_run missing: {mining}")
        if fr.get("automatic_spend_atoms") not in (0, "0"):
            raise AssertionError(f"getmininginfo first_run spend: {fr}")
        if not isinstance(fr.get("template_issuable"), bool):
            raise AssertionError(f"getmininginfo first_run template_issuable: {fr}")
        self._zero_spend(fr, "getmininginfo.first_run")

        searched = self._rpc_or_skip(node.searchmodels, {"text": "ops", "scope": "LOCAL"})
        if isinstance(searched, dict):
            self._zero_spend(searched, "searchmodels")
            if searched.get("coverage_complete") is True:
                raise AssertionError(f"searchmodels must not claim global coverage: {searched}")
        listed_models = self._rpc_or_skip(node.listmodels)
        if isinstance(listed_models, dict):
            self._zero_spend(listed_models, "listmodels")
        crypto = self._rpc_or_skip(node.getmodelcryptoinfo)
        if isinstance(crypto, dict):
            self._zero_spend(crypto, "getmodelcryptoinfo")
            dumped = str(crypto).lower()
            if "secret_access_key" in dumped or "id_ed25519" in dumped:
                raise AssertionError(f"getmodelcryptoinfo leaked secret: {crypto}")

        ids = self._rpc_or_skip(node.listmodelidentities)
        if isinstance(ids, dict):
            self._zero_spend(ids, "listmodelidentities")
            dumped = str(ids).lower()
            if "wallet_seed" in dumped or "\"secret\"" in dumped:
                raise AssertionError(f"listmodelidentities leaked secret: {ids}")
        setpol = self._rpc_or_skip(node.setmodelpolicy, {"seed": "off", "preserve_rare": True})
        if isinstance(setpol, dict):
            self._zero_spend(setpol, "setmodelpolicy")
            if setpol.get("wallet_signed") is True:
                raise AssertionError(f"setmodelpolicy wallet_signed: {setpol}")
        gotpol = self._rpc_or_skip(node.getmodelpolicy)
        if isinstance(gotpol, dict):
            self._zero_spend(gotpol, "getmodelpolicy")
        recip = self._rpc_or_skip(node.getmodelreciprocity)
        if isinstance(recip, dict):
            self._zero_spend(recip, "getmodelreciprocity")
        mid = None
        if isinstance(hosted, dict):
            mid = hosted.get("model_id") or hosted.get("uri")
        if uri and not mid:
            mid = uri
        if mid:
            joined = self._rpc_or_skip(node.joinmodelcircle, mid)
            if isinstance(joined, dict):
                self._zero_spend(joined, "joinmodelcircle")
                if joined.get("on_chain_membership") is True:
                    raise AssertionError(f"joinmodelcircle must not claim chain membership: {joined}")
            left = self._rpc_or_skip(node.leavemodelcircle, mid)
            if isinstance(left, dict):
                self._zero_spend(left, "leavemodelcircle")
        coll = self._rpc_or_skip(node.subscribemodelcollection, "ab" * 48)
        if isinstance(coll, dict):
            self._zero_spend(coll, "subscribemodelcollection")
            if coll.get("wallet_signed") is True:
                raise AssertionError(f"subscribemodelcollection wallet: {coll}")
        uncoll = self._rpc_or_skip(node.unsubscribemodelcollection, "ab" * 48)
        if isinstance(uncoll, dict):
            self._zero_spend(uncoll, "unsubscribemodelcollection")
        contacts = self._rpc_or_skip(node.exportmodelcontacts)
        if isinstance(contacts, dict):
            self._zero_spend(contacts, "exportmodelcontacts")
        rules = self._rpc_or_skip(node.listmodelrules)
        if isinstance(rules, dict):
            self._zero_spend(rules, "listmodelrules")
        rel = None
        if uri:
            rel = self._rpc_or_skip(node.createmodelrelease, {
                "uri": uri,
                "secret32_hex": "a" * 64,
                "refund_height": 100000,
            })
        if isinstance(rel, dict):
            self._zero_spend(rel, "createmodelrelease")
            if rel.get("wallet_signed") is True:
                raise AssertionError(f"createmodelrelease wallet_signed: {rel}")
            rid = rel.get("release_id") or rel.get("id")
            if rid:
                gotrel = self._rpc_or_skip(node.getmodelrelease, rid)
                if isinstance(gotrel, dict):
                    self._zero_spend(gotrel, "getmodelrelease")

        prof = node.getmodelprofile({})
        self._zero_spend(prof, "getmodelprofile")
        if prof.get("mirror_privilege") is True or prof.get("consensus") is True:
            raise AssertionError(f"profile must not grant consensus: {prof}")

        setp = node.setmodelprofile({"profile": "personal"})
        self._zero_spend(setp, "setmodelprofile")
        if setp.get("applied") is not True and "personal" not in str(setp).lower():
            self.log.warning("setmodelprofile shape: %s", setp)

        cloud = node.getcloudstorageinfo({})
        self._zero_spend(cloud, "getcloudstorageinfo")
        listed = node.listmodelstorage({})
        if isinstance(listed, dict):
            self._zero_spend(listed, "listmodelstorage")

        try:
            node.setcloudstorage({
                "endpoint": "https://acct.r2.cloudflarestorage.com",
                "bucket": "btx-models",
                "aws_secret_access_key": "supersecretvalue",
                "idempotency_key": "ops-cloud-secret-reject",
            })
            raise AssertionError("setcloudstorage must reject raw secrets in JSON")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "credential" not in blob and "secret" not in blob and "invalid" not in blob:
                raise AssertionError(f"setcloudstorage secret reject text: {exc}") from exc

        creds = Path(self.options.tmpdir) / "cloud-creds.ini"
        creds.write_text("access_key_id=AKIAFAKE\nsecret_access_key=fake-secret-not-used\n", encoding="utf-8")
        os.chmod(creds, 0o600)
        applied = self._rpc_or_skip(node.setcloudstorage, {
            "endpoint": "https://acct.r2.cloudflarestorage.com",
            "bucket": "btx-models",
            "prefix": "v1",
            "provider": "AUTO",
            "layout": "AUTO",
            "credential_ref": str(creds),
            "use_fake": True,
            "idempotency_key": "ops-cloud-fake",
        })
        if isinstance(applied, dict):
            self._zero_spend(applied, "setcloudstorage fake")
            if applied.get("layout") not in (None, "SOURCE_FILES", "AUTO"):
                self.log.info("cloud layout: %s", applied.get("layout"))

        probe = self._rpc_or_skip(node.testcloudstorage, {})
        if isinstance(probe, dict):
            self._zero_spend(probe, "testcloudstorage")
            if probe.get("live_r2_wan") is True:
                raise AssertionError(f"testcloudstorage must not claim live WAN: {probe}")

        mirror = node.getmodelmirror({})
        self._zero_spend(mirror, "getmodelmirror")
        if mirror.get("consensus") is True or mirror.get("search_authority") is True:
            raise AssertionError(f"mirror privilege: {mirror}")
        try:
            node.setmodelmirror({"publisher_id": "pub-ops", "keep_latest": 1, "automatic_spend_atoms": 1, "idempotency_key": "ops-mirror-spend-reject"})
            raise AssertionError("setmodelmirror must reject nonzero automatic_spend_atoms")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "automatic_spend" not in blob and "must remain 0" not in blob:
                raise AssertionError(f"setmodelmirror spend reject: {exc}") from exc
        setm = node.setmodelmirror({"publisher_id": "pub-ops", "keep_latest": 1, "automatic_spend_atoms": 0, "idempotency_key": "ops-mirror-ok"})
        self._zero_spend(setm, "setmodelmirror")

        watch = node.watchmodelpublisher({"publisher_id": "pub-ops", "action": "NOTIFY"})
        self._zero_spend(watch, "watchmodelpublisher")
        if not watch.get("watch_id"):
            raise AssertionError(f"watch missing watch_id: {watch}")
        coll = self._rpc_or_skip(node.watchmodelcollection, {"collection_id": "ab" * 48, "action": "NOTIFY"})
        if isinstance(coll, dict):
            self._zero_spend(coll, "watchmodelcollection")
        qwatch = self._rpc_or_skip(node.watchmodelquery, {"text": "ops", "action": "NOTIFY"})
        if isinstance(qwatch, dict):
            self._zero_spend(qwatch, "watchmodelquery")
        mw = self._rpc_or_skip(node.watchmodel, {"model_id": "e" * 96, "action": "NOTIFY"})
        if isinstance(mw, dict):
            self._zero_spend(mw, "watchmodel")
            one = self._rpc_or_skip(node.getmodelwatch, {"watch_id": mw.get("watch_id")})
            if isinstance(one, dict):
                self._zero_spend(one, "getmodelwatch")
        watches = node.listmodelwatches({})
        if isinstance(watches, dict):
            self._zero_spend(watches, "listmodelwatches")
        seq = node.getmodeleventsequence({})
        self._zero_spend(seq, "getmodeleventsequence")
        events = node.getmodelevents({"cursor": 0})
        self._zero_spend(events, "getmodelevents")
        waited = node.waitformodelevent({"cursor": 0, "timeout_ms": 0})
        self._zero_spend(waited, "waitformodelevent")
        acts = node.getmodelwatchactions({})
        self._zero_spend(acts, "getmodelwatchactions")
        if acts.get("spends") is True:
            raise AssertionError(f"watch actions must not spend: {acts}")

        mandate = {
            "mandate_version": 1,
            "owner_identity": "a" * 96,
            "network_id": "0" * 64,
            "publisher_id": "b" * 96,
            "allowed_kinds": ["MODEL", "RELEASE"],
            "allowed_actions": ["FUND_WITH_MANDATE"],
            "per_action_principal_limit_atoms": "50",
            "total_principal_limit_atoms": "100",
            "total_fee_limit_atoms": "20",
            "outstanding_exposure_limit_atoms": "200",
            "max_actions": 16,
            "max_concurrent_reservations": 8,
            "expires_at_ms": "4000000000000",
            "refund_key_policy": "OWNER_CONTROLLED_ONLY",
            "minimum_confirmations": 1,
            "assurance_mode_restrictions": [],
            "revocation_counter": "0",
        }
        created = self._rpc_or_skip(node.createsubscriptionmandate, mandate)
        if isinstance(created, dict):
            self._zero_spend(created, "createsubscriptionmandate")
            if created.get("wallet_signed") is True:
                raise AssertionError(f"F2 wallet_signed must stay false: {created}")
            if not created.get("mandate_id"):
                raise AssertionError(f"createsubscriptionmandate mandate_id: {created}")
            gotm = self._rpc_or_skip(node.getsubscriptionmandate, {"mandate_id": created.get("mandate_id")})
            if isinstance(gotm, dict):
                self._zero_spend(gotm, "getsubscriptionmandate")
                if gotm.get("wallet_signed") is True:
                    raise AssertionError(f"getsubscriptionmandate wallet_signed: {gotm}")
            reserve_req = {
                "mandate_id": created.get("mandate_id"),
                "event_id": "e-ops-reserve",
                "publisher_id": "b" * 96,
                "object_kind": "RELEASE",
                "action": "FUND_WITH_MANDATE",
                "signed_terms": {
                    "terms_id": "d" * 96,
                    "publisher_id": "b" * 96,
                    "network_id": "0" * 64,
                    "principal_atoms": "1",
                    "fee_atoms": "0",
                    "object_kind": "RELEASE",
                    "confirmations": 1,
                },
            }
            reserved = node.reservesubscriptionmandate(reserve_req)
            if not isinstance(reserved, dict):
                raise AssertionError(f"reservesubscriptionmandate: {reserved}")
            self._zero_spend(reserved, "reservesubscriptionmandate")
            if reserved.get("wallet_signed") is True:
                raise AssertionError(f"reservesubscriptionmandate wallet_signed: {reserved}")
            activity = node.getsubscriptionactivity({"mandate_id": created.get("mandate_id"), "limit": 10})
            if not isinstance(activity, dict):
                raise AssertionError(f"getsubscriptionactivity: {activity}")
            self._zero_spend(activity, "getsubscriptionactivity")
            if activity.get("wallet_signed") is True:
                raise AssertionError(f"getsubscriptionactivity wallet_signed: {activity}")
            if activity.get("telemetry") is True:
                raise AssertionError(f"getsubscriptionactivity telemetry: {activity}")
            actions = activity.get("actions")
            if not isinstance(actions, list) or not actions:
                raise AssertionError(f"getsubscriptionactivity actions: {activity}")
            if actions[0].get("event_id") != "e-ops-reserve":
                raise AssertionError(f"getsubscriptionactivity event_id: {actions[0]}")
            revoked = self._rpc_or_skip(node.revokesubscriptionmandate, {"mandate_id": created.get("mandate_id")})
            if isinstance(revoked, dict):
                self._zero_spend(revoked, "revokesubscriptionmandate")
        else:
            raise AssertionError(f"createsubscriptionmandate required for reservesubscriptionmandate: {created}")

        src_dir = Path(self.options.tmpdir) / "import-src"
        st = src_dir / "imported" / "model.safetensors"
        st_header = b'{"__metadata__":{}}'
        st.parent.mkdir(parents=True, exist_ok=True)
        st.write_bytes(struct.pack("<Q", len(st_header)) + st_header)
        plan = {
            "plan_id": "c" * 96,
            "source": {
                "kind": "LOCAL",
                "locator": str(src_dir),
                "snapshot_token": "rev-local",
            },
            "files": [{
                "source_path": "imported/model.safetensors",
                "destination_path": "imported/model.safetensors",
                "size_bytes": st.stat().st_size,
            }],
            "idempotency_key": "ops-import-local",
        }
        imported = node.executemodelimport(plan)
        if not isinstance(imported, dict):
            raise AssertionError(f"executemodelimport: {imported}")
        self._zero_spend(imported, "executemodelimport")
        authorship = str(imported.get("authorship", "")).lower()
        if "not implied" not in authorship and "authorship" in imported:
            self.log.warning("import authorship text: %s", imported.get("authorship"))
        if imported.get("wallet_signed") is True:
            raise AssertionError(f"import must not wallet-sign: {imported}")
        got_imp = self._rpc_or_skip(node.getmodelimport, {"plan_id": "c" * 96})
        if isinstance(got_imp, dict):
            self._zero_spend(got_imp, "getmodelimport")
        resumed = self._rpc_or_skip(node.resumemodelimport, {"plan_id": "c" * 96})
        if isinstance(resumed, dict):
            self._zero_spend(resumed, "resumemodelimport")
        published = self._rpc_or_skip(node.publishmodelimport, {"plan_id": "c" * 96})
        if isinstance(published, dict):
            self._zero_spend(published, "publishmodelimport")
            if published.get("wallet_signed") is True:
                raise AssertionError(f"publishmodelimport must not wallet-sign: {published}")
        cancelled = self._rpc_or_skip(node.cancelmodelimport, {"plan_id": "c" * 96})
        if isinstance(cancelled, dict):
            self._zero_spend(cancelled, "cancelmodelimport")

        hf_plan = {
            "plan_id": "d" * 96,
            "source": {
                "kind": "HUGGINGFACE",
                "locator": "https://huggingface.co/example/model",
                "snapshot_token": "rev-abc",
            },
            "files": [{
                "source_path": "model.safetensors",
                "destination_path": "model.safetensors",
                "size_bytes": 5,
            }],
            "idempotency_key": "ops-import-hf",
        }
        try:
            hf = node.executemodelimport(hf_plan)
        except JSONRPCException as exc:
            self.log.info("HF import fail-closed: %s", exc)
            hf = None
        if isinstance(hf, dict):
            self._zero_spend(hf, "executemodelimport HF")
            if hf.get("live_http") is True:
                raise AssertionError(f"HF import must not live-fetch: {hf}")
            note = str(hf.get("authorship", "")).lower()
            if "not implied" not in note and imported.get("authorship"):
                self.log.info("HF authorship: %s", hf.get("authorship"))

        channels = self._rpc_or_skip(node.listmodelchannels, {})
        if isinstance(channels, dict):
            self._zero_spend(channels, "listmodelchannels")
        try:
            unsigned_ch = node.observemodelchannel({
                "publisher_id": "pub-ops",
                "name": "coder",
                "channel": "stable",
                "target_uri": "btx://" + ("a" * 96),
                "sequence": 1,
            })
            if isinstance(unsigned_ch, dict) and unsigned_ch.get("signature_ok") is True:
                raise AssertionError(
                    f"unsigned observemodelchannel must not be signature_ok: {unsigned_ch}"
                )
            raise AssertionError(
                f"unsigned observemodelchannel must be rejected, not accepted: {unsigned_ch}"
            )
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if isinstance(exc.error, dict) and exc.error.get("code") in (-32601,):
                self.skipped.append(f"observemodelchannel: {exc.error}")
            elif "reject" not in blob and "sign" not in blob and "sequence" not in blob and "channel" not in blob:
                raise AssertionError(f"observemodelchannel unsigned reject text: {exc}") from exc
        seeded = None
        try:
            seeded = node.seedlabmodelchannel({})
        except JSONRPCException as exc:
            err = exc.error if isinstance(exc.error, dict) else {}
            if err.get("code") in (-32601,):
                self.skipped.append(f"seedlabmodelchannel: {exc.error}")
                try:
                    node.observemodelchannel({
                        "publisher_id": "pub-ops",
                        "name": "coder",
                        "channel": "stable",
                        "target_uri": "btx://" + ("a" * 96),
                        "sequence": 1,
                    })
                except JSONRPCException:
                    pass
                raise AssertionError(
                    "seedlabmodelchannel must exist (GenerateMlDsa, sign, ApplySignedChannel) "
                    f"so getmodelchannel can return signature_ok: {exc}"
                ) from exc
            raise
        if not isinstance(seeded, dict):
            raise AssertionError(f"seedlabmodelchannel: {seeded}")
        self._zero_spend(seeded, "seedlabmodelchannel")
        get_ch_req = {
            "publisher_id": seeded.get("publisher_id"),
            "name": seeded.get("name"),
            "channel": seeded.get("channel"),
        }
        got_ch = node.getmodelchannel(get_ch_req)
        if not isinstance(got_ch, dict):
            raise AssertionError(f"getmodelchannel: {got_ch}")
        self._zero_spend(got_ch, "getmodelchannel")
        if got_ch.get("signature_ok") is not True:
            raise AssertionError(f"getmodelchannel signature_ok: {got_ch}")

        boot_set = self._rpc_or_skip(node.setbootstrapdistributor, {"file_size_bytes": 4096, "idempotency_key": "ops-boot"})
        if isinstance(boot_set, dict):
            self._zero_spend(boot_set, "setbootstrapdistributor")
            if boot_set.get("false_missing_advertised") is True:
                raise AssertionError(f"setbootstrapdistributor false missing: {boot_set}")
        route = self._rpc_or_skip(node.getmodelroutingstatus, {})
        if isinstance(route, dict):
            self._zero_spend(route, "getmodelroutingstatus")
            if route.get("throughput_is_ranking") is True:
                raise AssertionError(f"routing throughput_is_ranking: {route}")
            if route.get("delegated_routing_is_consensus") is True:
                raise AssertionError(f"routing consensus: {route}")
        disc = self._rpc_or_skip(node.setmodeldiscoverypolicy, {"idempotency_key": "ops-disc"})
        if isinstance(disc, dict):
            self._zero_spend(disc, "setmodeldiscoverypolicy")
            if disc.get("throughput_is_ranking") is True:
                raise AssertionError(f"setmodeldiscoverypolicy ranking: {disc}")
        residency = self._rpc_or_skip(node.getmodelresidency, {})
        if isinstance(residency, dict):
            self._zero_spend(residency, "getmodelresidency")
            if residency.get("remote_existence_implies_verified_remote") is True:
                raise AssertionError(f"HeadObject is not VERIFIED_REMOTE: {residency}")
        dedup = self._rpc_or_skip(node.getmodeldedupinfo, {})
        if isinstance(dedup, dict):
            self._zero_spend(dedup, "getmodeldedupinfo")
            if dedup.get("content_defined_dedup") is True:
                raise AssertionError(f"CDC must stay NONSHIPPING: {dedup}")
            if dedup.get("cross_tenant") is True:
                raise AssertionError(f"cross-tenant dedup: {dedup}")
        lan = self._rpc_or_skip(node.getmodellandiscovery, {"endpoint": "192.168.1.20:8334"})
        if isinstance(lan, dict):
            self._zero_spend(lan, "getmodellandiscovery")
            if lan.get("delegated_routing_is_consensus") is True:
                raise AssertionError(f"LAN delegated consensus: {lan}")
        filesel = self._rpc_or_skip(node.getmodelfileselection, {"files": [1]})
        if isinstance(filesel, dict):
            self._zero_spend(filesel, "getmodelfileselection")
            if filesel.get("advertise_unselected") is True:
                raise AssertionError(f"unselected files must not be HAVE: {filesel}")
        mpu = self._rpc_or_skip(node.getmultipartjournal, {
            "initiate": True,
            "object_key": "staging/obj",
            "upload_id": "up-1",
            "planned_parts": 1,
        })
        if isinstance(mpu, dict):
            self._zero_spend(mpu, "getmultipartjournal")
            if mpu.get("etag_is_canonical_identity") is True:
                raise AssertionError(f"ETag is not SHA-384 identity: {mpu}")

        agent_man = self._rpc_or_skip(node.createagentmandate, {
            "total_atoms": "100",
            "per_action_atoms": "40",
            "owner_approval_ref": "user-1",
            "all_recipients": False,
        })
        if isinstance(agent_man, dict):
            self._zero_spend(agent_man, "createagentmandate")
            if agent_man.get("wallet_signed") is True:
                raise AssertionError(f"createagentmandate must not wallet-sign: {agent_man}")
            watched_b = self._rpc_or_skip(node.watchbounty, {
                "bounty_id": agent_man.get("mandate_id") or ("b" * 64),
            })
            if isinstance(watched_b, dict):
                self._zero_spend(watched_b, "watchbounty")
        try:
            wild = node.createagentmandate({
                "total_atoms": "100",
                "per_action_atoms": "40",
                "owner_approval_ref": "user-1",
                "all_recipients": True,
            })
            raise AssertionError(f"createagentmandate all_recipients must reject: {wild}")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "recipient" in blob or "unbounded" in blob or "wildcard" in blob or "all_recipients" in blob:
                pass
            elif isinstance(exc.error, dict) and exc.error.get("code") in (-32601,):
                self.skipped.append(f"createagentmandate wildcard: {exc.error}")
            else:
                self.skipped.append(f"createagentmandate wildcard reject text: {exc}")

        origin = self._rpc_or_skip(node.getmodeloriginstatus, {})
        if isinstance(origin, dict):
            self._zero_spend(origin, "getmodeloriginstatus")
        bulk = self._rpc_or_skip(node.getmodelbulkstatus, {})
        if isinstance(bulk, dict):
            self._zero_spend(bulk, "getmodelbulkstatus")

        boot = self._rpc_or_skip(node.getbootstrapstatus, {})
        if isinstance(boot, dict):
            self._zero_spend(boot, "getbootstrapstatus")
        upl = self._rpc_or_skip(node.getmodeluploadinfo, {})
        if isinstance(upl, dict):
            self._zero_spend(upl, "getmodeluploadinfo")
        self._rpc_or_skip(node.setmodeluploadpolicy, {"max_slots": 2, "idempotency_key": "ops-upload"})
        healer = self._rpc_or_skip(node.setmodelswarmhealer, {"enabled": False, "idempotency_key": "ops-healer"})
        if isinstance(healer, dict):
            self._zero_spend(healer, "setmodelswarmhealer")
        tsp = self._rpc_or_skip(node.settorrentsourcepolicy, {"s3_credentials": False, "idempotency_key": "ops-torrent"})
        if isinstance(tsp, dict):
            self._zero_spend(tsp, "settorrentsourcepolicy")
            if tsp.get("torrent_worker_s3_credentials") is True:
                raise AssertionError(f"torrent worker must not get S3 creds: {tsp}")
        caps_alias = self._rpc_or_skip(node.getmodelcapabilities, {})
        if isinstance(caps_alias, dict):
            self._zero_spend(caps_alias, "getmodelcapabilities")
        inspect_st = self._rpc_or_skip(node.inspectmodelstorage, {})
        if isinstance(inspect_st, dict):
            self._zero_spend(inspect_st, "inspectmodelstorage")
        test_st = self._rpc_or_skip(node.testmodelstorage, {})
        if isinstance(test_st, dict):
            self._zero_spend(test_st, "testmodelstorage")
        req_off = self._rpc_or_skip(node.requestmodelorigin, {
            "artifact_id": "local",
            "file_index": 0,
            "offset_bytes": 0,
            "length_bytes": 4096,
        })
        if isinstance(req_off, dict):
            self._zero_spend(req_off, "requestmodelorigin")
            if req_off.get("presigned_get_is_meter") is True:
                raise AssertionError(f"requestmodelorigin meter: {req_off}")
        oh = self._rpc_or_skip(node.getmodeloriginhealth, {})
        if isinstance(oh, dict):
            self._zero_spend(oh, "getmodeloriginhealth")
        ms = self._rpc_or_skip(node.getmodelmirrorstatus, {})
        if isinstance(ms, dict):
            self._zero_spend(ms, "getmodelmirrorstatus")
        mig = self._rpc_or_skip(node.planmodelstoragemigration, {"mode": "DETACH", "idempotency_key": "ops-mig-plan"})
        if isinstance(mig, dict):
            self._zero_spend(mig, "planmodelstoragemigration")
        emig = self._rpc_or_skip(node.executemodelstoragemigration, {"mode": "DETACH", "idempotency_key": "ops-mig-exec"})
        if isinstance(emig, dict):
            self._zero_spend(emig, "executemodelstoragemigration")
            if emig.get("bulk_io") is True:
                raise AssertionError(f"storage migration must not bulk copy: {emig}")
        erasure_obj = {
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
            "idempotency_key": "ops-erasure",
            "stripes": [
                {"index": 0, "positions": list(range(16))},
                {"index": 1, "positions": list(range(15))},
            ],
        }
        exe = self._rpc_or_skip(node.executemodelerasure, erasure_obj)
        if isinstance(exe, dict):
            self._zero_spend(exe, "executemodelerasure")
            if exe.get("reconstructable") is True:
                raise AssertionError(f"executemodelerasure reconstructable: {exe}")
        repair = self._rpc_or_skip(node.repairmodel, erasure_obj)
        if isinstance(repair, dict):
            self._zero_spend(repair, "repairmodel")
            if repair.get("auto_spend") is True:
                raise AssertionError(f"repairmodel must not auto-spend: {repair}")

        if uri:
            unpinned = self._rpc_or_skip(node.unpinmodel, uri)
            if isinstance(unpinned, dict):
                self._zero_spend(unpinned, "unpinmodel")
            pinned = self._rpc_or_skip(node.pinmodel, uri)
            if isinstance(pinned, dict):
                self._zero_spend(pinned, "pinmodel")
            unseeded = self._rpc_or_skip(node.unseedmodel, uri)
            if isinstance(unseeded, dict):
                self._zero_spend(unseeded, "unseedmodel")
            seeded = self._rpc_or_skip(node.seedmodel, uri)
            if isinstance(seeded, dict):
                self._zero_spend(seeded, "seedmodel")
            jobs = self._rpc_or_skip(node.getmodeljob)
            if isinstance(jobs, dict):
                self._zero_spend(jobs, "getmodeljob")
            cancelled_job = self._rpc_or_skip(node.cancelmodeljob, "no-such-job")
            if isinstance(cancelled_job, dict):
                self._zero_spend(cancelled_job, "cancelmodeljob unknown")
            rm_alias = self._rpc_or_skip(node.removemodelalias, uri, "ops-local")
            if isinstance(rm_alias, dict):
                self._zero_spend(rm_alias, "removemodelalias")
            unhosted = self._rpc_or_skip(node.unhostmodel, uri)
            if isinstance(unhosted, dict):
                self._zero_spend(unhosted, "unhostmodel")
                if unhosted.get("wallet_signed") is True:
                    raise AssertionError(f"unhostmodel must not spend: {unhosted}")

        obs_chain = self._rpc_or_skip(node.observebountychain, {
            "outpoint": "0" * 64 + ":0",
            "bounty_id": "ops-observe",
            "confirmations": 1,
        })
        if isinstance(obs_chain, dict):
            self._zero_spend(obs_chain, "observebountychain")
            if obs_chain.get("consensus") is True or obs_chain.get("wallet_signed") is True:
                raise AssertionError(f"observebountychain must not be consensus/spend: {obs_chain}")
        reorg_ch = self._rpc_or_skip(node.reorgbountychain, {"bounty_id": "ops-observe"})
        if isinstance(reorg_ch, dict):
            self._zero_spend(reorg_ch, "reorgbountychain")
            if reorg_ch.get("silent_delete") is True:
                raise AssertionError(f"reorgbountychain silent_delete: {reorg_ch}")
        recov = self._rpc_or_skip(node.exportbountyrecovery, {"bounty_id": "ops-observe"})
        if isinstance(recov, dict):
            self._zero_spend(recov, "exportbountyrecovery")
            if recov.get("wallet_seed") not in (None, False, "false", 0, ""):
                raise AssertionError(f"exportbountyrecovery leaked wallet_seed: {recov}")
            if recov.get("private_keys") not in (None, False, "false", 0, "", []):
                raise AssertionError(f"exportbountyrecovery leaked private_keys: {recov}")
            if recov.get("secrets") not in (None, False, "false", 0, ""):
                raise AssertionError(f"exportbountyrecovery leaked secrets: {recov}")
            imported_rec = self._rpc_or_skip(node.importbountyrecovery, recov)
            if isinstance(imported_rec, dict):
                self._zero_spend(imported_rec, "importbountyrecovery")
                if imported_rec.get("broadcast") is True or imported_rec.get("wallet_signed") is True:
                    raise AssertionError(f"importbountyrecovery must not broadcast: {imported_rec}")
        try:
            funded = node.preparebountyfunding({
                "principal_atoms": "1",
                "refund_key": "00" * 32,
            })
            if isinstance(funded, dict):
                self._zero_spend(funded, "preparebountyfunding")
                if funded.get("wallet_signed") is True or funded.get("broadcast") is True:
                    raise AssertionError(f"preparebountyfunding must stay unsigned: {funded}")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "wallet" in blob or "unsigned" in blob or "refund" in blob or "helper" in blob or "unavailable" in blob:
                pass
            elif isinstance(exc.error, dict) and exc.error.get("code") in (-32601, -1, -3):
                self.skipped.append(f"preparebountyfunding: {exc.error}")
            else:
                self.skipped.append(f"preparebountyfunding: {exc}")

        transport = self._rpc_or_skip(node.getevaluatedtransport, {})
        if isinstance(transport, dict):
            self._zero_spend(transport, "getevaluatedtransport")
            if transport.get("utp") not in (None, "NONSHIPPING") and transport.get("utp") is True:
                raise AssertionError(f"uTP must stay NONSHIPPING: {transport}")
        srcpol = self._rpc_or_skip(node.getsourcepolicy, {})
        if isinstance(srcpol, dict):
            self._zero_spend(srcpol, "getsourcepolicy")
            if srcpol.get("torrent_worker_s3_credentials") is True:
                raise AssertionError(f"torrent worker S3 creds: {srcpol}")
        layout = self._rpc_or_skip(node.getmodelobjectlayout, {"file_size_bytes": 4096})
        if isinstance(layout, dict):
            self._zero_spend(layout, "getmodelobjectlayout")
        ioexec = self._rpc_or_skip(node.getmodelioexecutor, {})
        if isinstance(ioexec, dict):
            self._zero_spend(ioexec, "getmodelioexecutor")
            if ioexec.get("io_uring") is True:
                raise AssertionError(f"io_uring must not be claimed: {ioexec}")
        summary = self._rpc_or_skip(node.querymodelsummary, {})
        if isinstance(summary, dict):
            self._zero_spend(summary, "querymodelsummary")
            if summary.get("complete") is True:
                raise AssertionError(f"querymodelsummary must not claim complete: {summary}")
        rec = self._rpc_or_skip(node.reconcilemodelindex, {"remote_ids": ["id-1"]})
        if isinstance(rec, dict):
            self._zero_spend(rec, "reconcilemodelindex")
            if rec.get("digest_authorizes_insert") is True:
                raise AssertionError(f"reconcile digest must not authorize insert: {rec}")
        sub = self._rpc_or_skip(node.validatesubpiece, {
            "offset": 0,
            "length": 256 * 1024,
            "piece_index": 0,
            "file_size_bytes": 4 * 1024 * 1024,
        })
        if isinstance(sub, dict):
            self._zero_spend(sub, "validatesubpiece")
        storpol = self._rpc_or_skip(node.setmodelstoragepolicy, {"idempotency_key": "ops-storpol"})
        if isinstance(storpol, dict):
            self._zero_spend(storpol, "setmodelstoragepolicy")
            if storpol.get("bulk_io") is True:
                raise AssertionError(f"setmodelstoragepolicy bulk_io: {storpol}")
        pkgcaps = self._rpc_or_skip(node.getbtxpackagecapabilities, {})
        if isinstance(pkgcaps, dict):
            self._zero_spend(pkgcaps, "getbtxpackagecapabilities")
            if pkgcaps.get("remote_inference") is True:
                raise AssertionError(f"getbtxpackagecapabilities inference: {pkgcaps}")

        self.log.info("COMP-04/JIT-SAFETY-05: stop test helper; money RPC still works")
        self._stop_helper()
        again = node.getblockcount()
        if not isinstance(again, int):
            raise AssertionError(f"getblockcount after helper down: {again}")
        chain = node.getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"chain after helper down: {chain}")
        try:
            node.executemodelimport({"plan_id": "aa" * 48, "idempotency_key": "ops-import-helper-down"})
            raise AssertionError("executemodelimport after helper down must fail closed")
        except JSONRPCException as exc:
            msg = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "helper" not in msg and "unavailable" not in msg and "unix" not in msg:
                raise AssertionError(f"helper-down error text: {exc}") from exc

        # HONEST_NOT_RUN only for methods that are truly missing (-32601).
        # A NEW skip name fails the test.
        honest_rpc = frozenset()
        unexpected = []
        for s in self.skipped:
            name = self._skip_method_name(s)
            self.log.info("HONEST_NOT_RUN %s: %s", name, s)
            if name not in honest_rpc:
                unexpected.append(name)
        if unexpected:
            raise AssertionError(
                f"NEW skip not in HONEST_NOT_RUN catalog allowlist: {unexpected}; skipped={self.skipped}"
            )
        self.log.info("0.34.8 ops e2e passed skipped=%s", self.skipped)


if __name__ == "__main__":
    ModelNet0348OpsTest(__file__).main()
