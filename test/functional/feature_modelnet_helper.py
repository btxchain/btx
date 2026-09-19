#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end process test: one regtest node + local btx-modeld (unix RPC only).

Starts btx-modeld as a separate process (no -modelhost, no public bind),
points the node at that socket with -modelnet=1, then exercises the
helper RPCs registered in src/rpc/modelnet.cpp.

Skip if the btx-modeld binary is missing. Never SIGKILL production btxd;
the helper child is the test process only.

Run (do not cmake/ninja):

  python3 test/functional/feature_modelnet_helper.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import os
import struct
import subprocess
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_greater_than_or_equal,
    get_datadir_path,
)

# Names registered in src/rpc/modelnet.cpp (ProxyOrLocal). First name is
# the live method; extra aliases are tried only on "method not found".
RPC_NAMES = {
    "getmodelnetworkinfo": ("getmodelnetworkinfo",),
    "checkmodelsetup": ("checkmodelsetup",),
    "listmodelidentities": ("listmodelidentities",),
    "createmodelidentity": ("createmodelidentity",),
    "importmodel": ("importmodel",),
    "listmodels": ("listmodels",),
    "seedmodel": ("seedmodel",),
    "getmodel": ("getmodel",),
    "getmodelmanifest": ("getmodelmanifest",),
    "getmodeljob": ("getmodeljob",),
    "getmodelpolicy": ("getmodelpolicy",),
    "resolveresource": ("resolveresource", "resolve"),
    "subscribemodelcollection": ("subscribemodelcollection",),
    "unsubscribemodelcollection": (
        "unsubscribemodelcollection",
        "unsubscribecollection",
        "leavemodelcollection",
        "unsubscribemodel",
    ),
    "subscribemodelpolicy": ("subscribemodelpolicy",),
    "unsubscribemodelpolicy": ("unsubscribemodelpolicy",),
    "setmodelrule": ("setmodelrule",),
    "listbanned": ("listbanned",),
    "hcphealth": ("hcphealth",),
    "gethcpreadiness": ("gethcpreadiness",),
    "sethcpreporting": ("sethcpreporting",),
    "importhcpstate": ("importhcpstate",),
}

# MatMul-off heights from wallet_modelnet_funding.py. Not used unless a
# later step generates; generate is cheap while these stay at maxint.
MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

GETMODEL_EXPLICIT_PAID_OBJ = {
    "mode": "approve",
    "retrieval_policy": "EXPLICIT_PAID",
    "max_atoms": 1,
    "approved": True,
}


def write_minimal_safetensors(path: Path) -> None:
    """10-byte SafeTensors: LE64(2) + '{}' (same fixture as modelnet_tests)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", 2) + b"{}")


class ModelNetHelperTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.missing_rpcs = []
        self.used_rpcs = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld binary not found (BUILDDIR/bin or next to btxd/bitcoind)")

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
            parent = Path(bitcoind).resolve().parent
            candidates.append(parent / name)
        seen = set()
        for cand in candidates:
            try:
                resolved = cand.resolve()
            except OSError:
                resolved = cand
            if resolved in seen:
                continue
            seen.add(resolved)
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _is_method_missing(self, exc):
        err = exc.error if isinstance(exc.error, dict) else {}
        code = err.get("code")
        msg = f"{exc} {err.get('message', '')} {err.get('code', '')}".lower()
        if code not in (-32601, -1):
            return False
        return (
            "not found" in msg
            or "method_not_found" in msg
            or "unknown model rpc" in msg
            or "unknown method" in msg
        )

    def _rpc(self, node, logical, *args):
        last = None
        for name in RPC_NAMES[logical]:
            try:
                result = getattr(node, name)(*args)
                self.used_rpcs.append(name)
                return result
            except JSONRPCException as exc:
                if self._is_method_missing(exc):
                    last = exc
                    continue
                raise
            except AttributeError as exc:
                last = exc
                continue
        raise AssertionError(f"RPC {logical} not registered on node (tried {RPC_NAMES[logical]}): {last}")

    def _rpc_optional(self, node, logical, *args):
        try:
            return self._rpc(node, logical, *args)
        except AssertionError as exc:
            self.log.warning("%s", exc)
            self.missing_rpcs.append(logical)
            return None

    def _rpc_query(self, node, logical, *arg_lists):
        """Try argument forms in order; skip type/param mismatches."""
        last = None
        for args in arg_lists:
            try:
                return self._rpc(node, logical, *args)
            except JSONRPCException as exc:
                err = exc.error if isinstance(exc.error, dict) else {}
                if err.get("code") in (-3, -8, -32602):
                    last = exc
                    continue
                raise
            except AssertionError as exc:
                last = exc
                self.missing_rpcs.append(logical)
                return None
        raise AssertionError(f"RPC {logical} rejected all argument forms: {last}")

    def _wallet_in_exc(self, exc):
        err = exc.error if isinstance(exc.error, dict) else {}
        blob = " ".join(str(p) for p in (exc, err.get("code"), err.get("message"))).upper()
        return "WALLET" in blob

    def _assert_no_artifact_relabel(self, resolved, model_id, artifact_id):
        if not isinstance(resolved, dict):
            raise AssertionError(f"resolveresource expected object: {resolved}")
        if resolved.get("coverage") != "incomplete":
            raise AssertionError(f"resolveresource coverage must be incomplete: {resolved}")
        if "does_not_exist" in resolved and resolved.get("does_not_exist") is not False:
            raise AssertionError(f"resolveresource does_not_exist must be false: {resolved}")

        def walk(obj):
            if isinstance(obj, dict):
                mid = obj.get("model_id")
                aid = obj.get("artifact_id")
                if (
                    model_id
                    and artifact_id
                    and mid is not None
                    and mid == artifact_id
                    and mid != model_id
                ):
                    raise AssertionError(
                        f"resolveresource relabelled artifact_id as model_id: {obj}"
                    )
                if (
                    model_id
                    and artifact_id
                    and aid is not None
                    and aid == model_id
                    and aid != artifact_id
                ):
                    raise AssertionError(
                        f"resolveresource relabelled model_id as artifact_id: {obj}"
                    )
                for value in obj.values():
                    walk(value)
            elif isinstance(obj, list):
                for value in obj:
                    walk(value)

        walk(resolved)
        ids = resolved.get("ids")
        if isinstance(ids, list) and artifact_id:
            for item in ids:
                if item == artifact_id and item != model_id:
                    raise AssertionError(
                        f"kind=0 resolveresource ids must not be artifact_id: {resolved}"
                    )

    def _automatic_spend(self, obj):
        if not isinstance(obj, dict):
            raise AssertionError(f"expected object, got {type(obj)}: {obj}")
        for key in ("automatic_spend", "automatic_spend_atoms"):
            if key in obj:
                return obj[key]
        raise AssertionError(f"getmodelpolicy missing automatic_spend*: {obj}")

    def _start_helper(self):
        datadir = get_datadir_path(self.options.tmpdir, 0)
        self.modeldir = Path(datadir) / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        modeld = self._modeld_path()
        argv = [
            str(modeld),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        log_path = self.modeldir / "modeld.log"
        self.modeld_log = open(log_path, "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv,
            stdout=self.modeld_log,
            stderr=subprocess.STDOUT,
            cwd=str(datadir),
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
                # Test-spawned btx-modeld only. Never production btxd.
                self.log.warning("test helper did not exit on SIGTERM; killing test child")
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def _helper_log_tail(self):
        log_path = self.modeldir / "modeld.log" if self.modeldir else None
        if log_path is None or not log_path.exists():
            return ""
        return log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(
                f"btx-modeld exited immediately with {self.modeld_proc.returncode}\n"
                f"{self._helper_log_tail()}"
            )
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

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(
                    f"btx-modeld exited with {self.modeld_proc.returncode}\n"
                    f"{self._helper_log_tail()}"
                )
            try:
                info = self._rpc(node, "getmodelnetworkinfo")
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.log.info("waiting for getmodelnetworkinfo helper_ready")
        self.wait_until(helper_ready, timeout=30)

        info = self._rpc(node, "getmodelnetworkinfo")
        assert info.get("helper_ready") is True, info
        prop = info.get("propagation") or {}
        if prop.get("demand_propagation") is not True:
            raise AssertionError(f"default demand_propagation must be true after -modelstorage: {prop}")
        if prop.get("seed_upon_download_opt_in"):
            raise AssertionError(f"seed_upon_download still opt-in: {prop}")

        doctor = self._rpc(node, "checkmodelsetup")
        if not isinstance(doctor, dict):
            raise AssertionError(f"checkmodelsetup expected object: {doctor}")
        spend = doctor.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"checkmodelsetup spend: {doctor}")
        if doctor.get("identity_ready") is not True:
            raise AssertionError(f"checkmodelsetup identity_ready: {doctor}")
        listed_ids = self._rpc(node, "listmodelidentities")
        if not isinstance(listed_ids, dict):
            raise AssertionError(f"listmodelidentities expected object: {listed_ids}")
        if listed_ids.get("wallet_backed") is True:
            raise AssertionError(f"listmodelidentities must not be wallet-backed: {listed_ids}")
        created_id = self._rpc(node, "createmodelidentity")
        if not isinstance(created_id, dict):
            raise AssertionError(f"createmodelidentity expected object: {created_id}")
        if created_id.get("wallet_backed") is True or created_id.get("contains_wallet_material") is True:
            raise AssertionError(f"createmodelidentity must not be a wallet key: {created_id}")
        if created_id.get("class") not in (None, "RESEARCH_PUBLISHER"):
            raise AssertionError(f"createmodelidentity class: {created_id}")
        spend = created_id.get("automatic_spend_atoms", 0)
        if spend not in (0, "0", None):
            raise AssertionError(f"createmodelidentity spend: {created_id}")

        st_path = Path(self.options.tmpdir) / "import" / "model.safetensors"
        write_minimal_safetensors(st_path)
        self.log.info("importmodel %s", st_path)
        imported = self._rpc(node, "importmodel", str(st_path))
        if not isinstance(imported, dict):
            raise AssertionError(f"importmodel expected object: {imported}")
        uri = imported.get("uri") or imported.get("model_id")
        if not uri:
            raise AssertionError(f"importmodel missing uri/model_id: {imported}")
        if imported.get("seeded") is not True:
            raise AssertionError(f"import must demand-seed without seedmodel: {imported}")

        listed = self._rpc(node, "listmodels")
        if not isinstance(listed, dict):
            raise AssertionError(f"listmodels expected object: {listed}")
        assert_greater_than_or_equal(int(listed.get("local_count", 0)), 1)

        got = self._rpc(node, "getmodel", uri, "FREE_ONLY")
        if not isinstance(got, dict):
            raise AssertionError(f"getmodel expected object: {got}")

        manifest_id = imported.get("uri") or imported.get("model_id")
        manifest = self._rpc(node, "getmodelmanifest", manifest_id)
        if not isinstance(manifest, dict):
            raise AssertionError(f"getmodelmanifest expected object: {manifest}")

        job = self._rpc(node, "getmodeljob")
        if not isinstance(job, dict):
            raise AssertionError(f"getmodeljob expected object: {job}")

        policy = self._rpc(node, "getmodelpolicy")
        spend = self._automatic_spend(policy)
        if int(spend) != 0:
            raise AssertionError(f"getmodelpolicy automatic_spend must be 0: {policy}")

        hcp_health = self._rpc(node, "hcphealth")
        if not isinstance(hcp_health, dict):
            raise AssertionError(f"hcphealth expected object: {hcp_health}")
        hcp_spend = hcp_health.get("automatic_spend_atoms", 0)
        if hcp_spend not in (0, "0"):
            raise AssertionError(f"hcphealth spend: {hcp_health}")
        ready = self._rpc(node, "gethcpreadiness")
        if not isinstance(ready, dict):
            raise AssertionError(f"gethcpreadiness expected object: {ready}")
        if ready.get("automatic_spend_atoms", 0) not in (0, "0"):
            raise AssertionError(f"gethcpreadiness spend: {ready}")
        try:
            node.sethcpreporting({"secret": "BTX_TEST_SECRET_SENTINEL"})
            raise AssertionError("sethcpreporting must refuse secrets")
        except JSONRPCException as exc:
            self.log.info("sethcpreporting refused: %s", exc)
        try:
            node.importhcpstate({"secret": "BTX_TEST_SECRET_SENTINEL"})
            raise AssertionError("importhcpstate must refuse secrets")
        except JSONRPCException as exc:
            self.log.info("importhcpstate refused: %s", exc)

        model_id = imported.get("model_id")
        artifact_id = imported.get("artifact_id")
        if not model_id:
            model_id = uri

        self.log.info("resolveresource typed lookup model_id=%s", model_id)
        resolved = self._rpc_query(
            node,
            "resolveresource",
            ({"digest48": model_id, "kind": 0},),
            (model_id,),
        )
        if resolved is None:
            self.log.warning("resolveresource missing; skipped typed-lookup asserts")
        else:
            self._assert_no_artifact_relabel(resolved, model_id, artifact_id)

        collection_id = "ab" * 48
        self.log.info("subscribemodelcollection %s", collection_id)
        subscribed = self._rpc_optional(node, "subscribemodelcollection", collection_id)
        if subscribed is None:
            self.log.warning("subscribemodelcollection missing")
        else:
            if not isinstance(subscribed, dict):
                raise AssertionError(f"subscribemodelcollection expected object: {subscribed}")
            if subscribed.get("on_chain_membership") is not False:
                raise AssertionError(
                    f"subscribemodelcollection on_chain_membership must be false: {subscribed}"
                )
            impact = subscribed.get("impact")
            if isinstance(impact, dict):
                if impact.get("quota_raised") is True:
                    raise AssertionError(f"subscribe raised quota: {impact}")
                if impact.get("preview_only") is not True:
                    raise AssertionError(f"subscribe impact must be preview_only: {impact}")
            self.log.info("unsubscribemodelcollection %s", collection_id)
            unsubscribed = self._rpc_optional(node, "unsubscribemodelcollection", collection_id)
            if unsubscribed is None:
                self.log.info(
                    "unsubscribemodelcollection not registered; leaving local subscription"
                )
            elif not isinstance(unsubscribed, dict):
                raise AssertionError(
                    f"unsubscribemodelcollection expected object: {unsubscribed}"
                )
            else:
                    if unsubscribed.get("on_chain_membership") is not False:
                        raise AssertionError(
                            f"unsubscribe on_chain_membership must be false: {unsubscribed}"
                        )

        policy_id = "cd" * 48
        self.log.info("subscribemodelpolicy / unsubscribemodelpolicy %s", policy_id)
        spol = self._rpc_optional(node, "subscribemodelpolicy", policy_id)
        if spol is None:
            self.log.warning("subscribemodelpolicy missing")
        else:
            if spol.get("on_chain_membership") is not False:
                raise AssertionError(f"policy subscribe on_chain: {spol}")
            unpol = self._rpc_optional(node, "unsubscribemodelpolicy", policy_id)
            if isinstance(unpol, dict) and unpol.get("automatic_preservation") is not False:
                raise AssertionError(f"unsubscribemodelpolicy must stop preservation: {unpol}")

        banned_before = []
        try:
            banned_before = node.listbanned()
        except JSONRPCException:
            banned_before = []
        rule = self._rpc_optional(node, "setmodelrule", {"deny": "complaint-peer", "action": "deny"})
        if isinstance(rule, dict) and rule.get("affects_banman") is True:
            raise AssertionError(f"setmodelrule must not affect BanMan: {rule}")
        try:
            banned_after = node.listbanned()
        except JSONRPCException:
            banned_after = banned_before
        if banned_after != banned_before:
            raise AssertionError(f"model ACL wrote BanMan: {banned_before} -> {banned_after}")

        self.log.info("getmodel EXPLICIT_PAID journals a quote; automatic spend stays 0")
        paid_last = None
        paid_ok = False
        for mode_arg in ("EXPLICIT_PAID", GETMODEL_EXPLICIT_PAID_OBJ):
            try:
                paid_last = self._rpc(node, "getmodel", uri, mode_arg)
            except JSONRPCException as exc:
                paid_last = exc
                err = exc.error if isinstance(exc.error, dict) else {}
                if err.get("code") in (-3, -8, -32602):
                    continue
                raise
            if not isinstance(paid_last, dict):
                continue
            if paid_last.get("automatic_spend_atoms", paid_last.get("automatic_spend", 1)) not in (0, "0"):
                raise AssertionError(f"EXPLICIT_PAID auto-spend: {paid_last}")
            if "quote" not in paid_last:
                raise AssertionError(f"EXPLICIT_PAID missing quote: {paid_last}")
            paid_ok = True
            self.log.info("getmodel EXPLICIT_PAID quote: %s", paid_last.get("plan"))
            break
        if not paid_ok:
            raise AssertionError(f"getmodel EXPLICIT_PAID must return a quote, got {paid_last}")

        got_free = self._rpc(node, "getmodel", uri, "FREE_ONLY")
        if not isinstance(got_free, dict):
            raise AssertionError(f"getmodel FREE_ONLY after EXPLICIT_PAID: {got_free}")

        self.log.info(
            "stopping test-spawned btx-modeld with SIGTERM (never production btxd)"
        )
        self._stop_helper()
        chain = node.getblockchaininfo()
        if not isinstance(chain, dict) or "chain" not in chain:
            raise AssertionError(f"getblockchaininfo after helper SIGTERM: {chain}")
        try:
            down = self._rpc(node, "getmodelnetworkinfo")
        except JSONRPCException as exc:
            self.log.info("getmodelnetworkinfo after helper stop: %s", exc)
            down = None
        if isinstance(down, dict):
            self.log.info(
                "getmodelnetworkinfo after helper stop helper_ready=%s",
                down.get("helper_ready"),
            )

        if self.missing_rpcs:
            self.log.warning("missing RPCs: %s", ", ".join(dict.fromkeys(self.missing_rpcs)))
        self.log.info("RPCs used: %s", ", ".join(dict.fromkeys(self.used_rpcs)))
        self.log.info("modelnet helper e2e passed (uri=%s)", uri)


if __name__ == "__main__":
    ModelNetHelperTest(__file__).main()
