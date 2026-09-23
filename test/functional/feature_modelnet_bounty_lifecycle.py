#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest create → find → on-chain timelock complete.

Owned helper (btxd spawns btx-modeld). Unix-only PQ1 (`-modelbind=off`).
Does not SIGKILL production btxd. --timeout-factor=1.

Proves:

  create   createbountydraft + publishbounty (signed terms)
  find     searchbounties LOCAL hits the published title/description
  complete two-leaf P2MR escrow on chain:
             mr(cltv_multi_pq(award_height, m, council…), refund(refund_height, key))
           early award/refund fail closed; after award_height the council
           CLTV leaf pays the winner; an unawarded lot refunds after
           refund_height without council or helper.

Helper proposebountyaward / approvebountyaward is policy only and is not
completion. automatic_spend_atoms stays 0.

Run:

  python3 test/functional/feature_modelnet_bounty_lifecycle.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_greater_than, get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

NETWORK_ID = "0" * 64
TITLE = "regtest-bounty-lifecycle-x7"
DESCRIPTION = "Japanese repository maintenance tooling for coding agents."
PRINCIPAL = 50_000_000
FEE = 1_000_000
FEE_RESERVE = 10_000_000


def sample_terms(council_hex, threshold=2) -> dict:
    return {
        "terms_version": 1,
        "network_id": NETWORK_ID,
        "requester_identity": "",
        "title": TITLE,
        "description": DESCRIPTION,
        "tags": ["coding", "repository"],
        "deliverable_classes": ["BASE_MODEL"],
        "evaluation_spec_id": "e2e-exact-checks",
        "submission_mode": "PUBLIC",
        "payout_authority": "COUNCIL_MULTISIG",
        "council": [{"public_key_hex": k} for k in council_hex],
        "threshold": threshold,
        "nomination_min_bps": 0,
        "target_atoms": "100000000",
        "max_lots_per_round": 4,
        "funding_close_height": 200,
        "submission_close_height": 300,
        "evaluation_close_height": 400,
        "earliest_award_height": 450,
        "last_safe_award_height": 480,
        "refund_height": 600,
        "minimum_confirmations": 6,
        "claim_margin_blocks": 20,
        "challenge_policy": "BOUNDED_TYPED",
        "selection_rule": "EXACT_CANDIDATE",
        "license_statement": "MIT",
        "max_model_bytes": 1048576,
        "fee_policy": "USER_CEILING",
        "sealed_confidentiality_disclosure": "",
    }


class ModelnetBountyLifecycleTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [[
            "-modelnet=1",
            "-modelbind=off",
            "-modelstorage=8MiB",
            "-autoshieldcoinbase=0",
            *MATMUL_OFF_ARGS,
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
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
            candidates.append(Path(builddir) / "src" / name)
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _debug_log_tail(self, n=80):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        log = datadir / "regtest" / "debug.log"
        if not log.is_file():
            return ""
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n:])

    def _wait_helper(self, node):
        def helper_ready():
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        try:
            self.wait_until(helper_ready, timeout=30)
        except AssertionError as e:
            raise AssertionError(
                f"helper not ready:\n{self._debug_log_tail()}\n{e}"
            ) from e

    def _pq_pubkey(self, wallet):
        addr = wallet.getnewaddress()
        exported = wallet.exportpqkey(addr)
        pk = exported.get("pubkey")
        if not isinstance(pk, str) or len(pk) != 2624:
            raise AssertionError(f"exportpqkey: {exported}")
        return pk, addr

    def _rpc_message(self, exc):
        if isinstance(exc.error, dict):
            return str(exc.error.get("message", exc.error))
        return str(exc)

    def _assert_timelock_closed(self, wallet, method, opts):
        try:
            getattr(wallet, method)(opts)
        except JSONRPCException as exc:
            msg = self._rpc_message(exc).lower()
            if "timelock" in msg or "mature" in msg or "locktime" in msg:
                return
            raise AssertionError(f"{method} failed for a reason other than timelock: {exc.error}") from exc
        raise AssertionError(f"{method} must fail closed before locktime")

    def _fund_lot(self, funder, plan, funding_addr):
        prep = funder.preparebountyfunding(plan)
        if not prep.get("unsigned_hex"):
            raise AssertionError(f"preparebountyfunding: {prep}")
        assert_equal(prep.get("automatic_spend"), 0)
        insp = funder.inspectbountytransaction({**plan, "hex": prep["unsigned_hex"]})
        if not insp.get("escrow_output_present"):
            raise AssertionError(f"inspectbountytransaction: {insp}")
        signed = funder.signbountyfunding({**plan, "hex": prep["unsigned_hex"], "plan_id": prep.get("plan_id")})
        if not signed.get("hex"):
            raise AssertionError(f"signbountyfunding: {signed}")
        decoded = funder.decoderawtransaction(signed["hex"])
        script = prep.get("output_script")
        vout_n = 0
        for i, vout in enumerate(decoded.get("vout") or []):
            hx = ((vout.get("scriptPubKey") or {}).get("hex") or "")
            if script and hx == script:
                vout_n = int(vout.get("n", i))
                break
        sub = funder.submitbountyfunding({"hex": signed["hex"]})
        if not sub.get("submitted") and not sub.get("duplicate"):
            raise AssertionError(f"submitbountyfunding: {sub}")
        txid = sub.get("txid") or decoded.get("txid")
        if not txid:
            raise AssertionError(f"submitbountyfunding missing txid: {sub}")
        mempool = funder.getrawmempool()
        if txid not in mempool and not sub.get("duplicate"):
            raise AssertionError(f"funding tx not in mempool: {txid} {sub}")
        self.generatetoaddress(self.nodes[0], 1, funding_addr)
        return {
            "txid": txid,
            "vout": vout_n,
            "descriptor": prep.get("descriptor"),
            "output_script": script,
            "plan": {**plan, "descriptor": prep.get("descriptor"), "output_script": script},
        }

    def _submit_spend(self, wallet, submit_name, hex_tx, funding_addr):
        sub = getattr(wallet, submit_name)({"hex": hex_tx})
        if not sub.get("submitted") and not sub.get("duplicate"):
            raise AssertionError(f"{submit_name}: {sub}")
        txid = sub.get("txid")
        if not txid:
            raise AssertionError(f"{submit_name} missing txid: {sub}")
        mempool = wallet.getrawmempool()
        if txid not in mempool and not sub.get("duplicate"):
            raise AssertionError(f"spend not in mempool: {txid} {sub}")
        self.generatetoaddress(self.nodes[0], 1, funding_addr)
        return txid

    def run_test(self):
        node = self.nodes[0]
        helptext = node.help()
        for name in (
            "createbountydraft",
            "publishbounty",
            "searchbounties",
            "preparebountyfunding",
            "submitbountyfunding",
            "preparebountyaward",
            "submitbountyaward",
            "preparebountyrefund",
            "submitbountyrefund",
        ):
            if name not in helptext:
                raise SkipTest(f"{name} not compiled")

        self._wait_helper(node)
        caps = node.getbountycapabilities()
        assert_equal(caps.get("automatic_spend_atoms", 1), 0)

        funder = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name="council")
        node.createwallet(wallet_name="winner")
        council = node.get_wallet_rpc("council")
        winner = node.get_wallet_rpc("winner")

        funding_addr = funder.getnewaddress()
        self.generatetoaddress(node, 101, funding_addr)

        pk0, _ = self._pq_pubkey(council)
        pk1, _ = self._pq_pubkey(council)
        council_hex = [pk0, pk1]
        refund_key, _ = self._pq_pubkey(funder)
        winner_addr = winner.getnewaddress()
        refund_dest = funder.getnewaddress()

        terms = sample_terms(council_hex, threshold=2)
        v = node.validatebountyterms({"terms": terms})
        if not v.get("ok"):
            raise AssertionError(f"validatebountyterms: {v}")
        draft = node.createbountydraft({"terms": terms})
        draft_id = draft.get("draft_id")
        if not draft_id:
            raise AssertionError(f"createbountydraft: {draft}")
        assert_equal(draft.get("local_only"), True)
        assert_equal(draft.get("published"), False)

        pub = node.publishbounty({"draft_id": draft_id})
        bounty_id = pub.get("bounty_id")
        if not bounty_id:
            raise AssertionError(f"publishbounty: {pub}")
        got = node.getbounty({"bounty_id": bounty_id})
        assert_equal(got.get("state"), "PUBLISHED")
        assert_equal(got.get("title"), TITLE)

        hits = node.searchbounties({"text": "repository maintenance Japanese", "scope": "LOCAL", "limit": 20})
        results = hits.get("results") or []
        if not any(h.get("bounty_id") == bounty_id for h in results if isinstance(h, dict)):
            raise AssertionError(f"searchbounties missed {bounty_id} in {hits}")
        assert_equal(hits.get("complete"), True)
        assert_equal(hits.get("global_complete"), False)

        height = node.getblockcount()
        award_height = height + 6
        refund_height = height + 20
        award_plan = {
            "principal_atoms": str(PRINCIPAL),
            "refund_key": refund_key,
            "fee_reserve_atoms": str(FEE_RESERVE),
            "fee_atoms": str(FEE),
            "council_keys": council_hex,
            "threshold": 2,
            "award_height": award_height,
            "refund_height": refund_height,
        }
        funded = self._fund_lot(funder, award_plan, funding_addr)
        spend_opts = {
            **funded["plan"],
            "outpoint": f"{funded['txid']}:{funded['vout']}",
            "destination": winner_addr,
            "fee_atoms": str(FEE),
        }
        self._assert_timelock_closed(council, "preparebountyaward", spend_opts)

        while node.getblockcount() < award_height:
            self.generatetoaddress(node, 1, funding_addr)

        prep_award = council.preparebountyaward(spend_opts)
        hex_award = prep_award.get("hex") or prep_award.get("signed_hex")
        if not hex_award or not prep_award.get("complete"):
            raise AssertionError(f"preparebountyaward: {prep_award}")
        assert_equal(prep_award.get("selected_path"), "award")
        assert_equal(prep_award.get("automatic_spend"), 0)
        insp_award = council.inspectbountyaward({**spend_opts, "hex": hex_award})
        assert_equal(insp_award.get("selected_path"), "award")
        assert_equal(insp_award.get("timelock_enforced"), True)
        decoded_award = council.decoderawtransaction(hex_award)
        assert_equal(decoded_award["locktime"], award_height)
        if decoded_award["vin"][0]["sequence"] == 0xffffffff:
            raise AssertionError("award sequence must be non-final for CLTV")

        before = winner.getreceivedbyaddress(winner_addr)
        self._submit_spend(council, "submitbountyaward", hex_award, funding_addr)
        after = winner.getreceivedbyaddress(winner_addr)
        expect = (PRINCIPAL - FEE) / 100_000_000
        if abs(float(after) - float(before) - expect) > 1e-8:
            raise AssertionError(f"winner did not receive principal-fee: before={before} after={after} expect_delta={expect}")

        height = node.getblockcount()
        refund_award_h = height + 40
        refund_h = height + 5
        refund_plan = {
            "principal_atoms": str(PRINCIPAL),
            "refund_key": refund_key,
            "fee_reserve_atoms": str(FEE_RESERVE),
            "fee_atoms": str(FEE),
            "council_keys": council_hex,
            "threshold": 2,
            "award_height": refund_award_h,
            "refund_height": refund_h,
        }
        refund_funded = self._fund_lot(funder, refund_plan, funding_addr)
        refund_opts = {
            **refund_funded["plan"],
            "outpoint": f"{refund_funded['txid']}:{refund_funded['vout']}",
            "destination": refund_dest,
            "fee_atoms": str(FEE),
        }
        self._assert_timelock_closed(funder, "preparebountyrefund", refund_opts)
        self._assert_timelock_closed(council, "preparebountyaward", {
            **refund_opts,
            "destination": winner_addr,
        })

        while node.getblockcount() < refund_h:
            self.generatetoaddress(node, 1, funding_addr)

        prep_refund = funder.preparebountyrefund(refund_opts)
        hex_refund = prep_refund.get("hex") or prep_refund.get("signed_hex")
        if not hex_refund or not prep_refund.get("complete"):
            raise AssertionError(f"preparebountyrefund: {prep_refund}")
        assert_equal(prep_refund.get("selected_path"), "refund")
        decoded_refund = funder.decoderawtransaction(hex_refund)
        assert_equal(decoded_refund["locktime"], refund_h)
        if decoded_refund["vin"][0]["sequence"] == 0xffffffff:
            raise AssertionError("refund sequence must be non-final for CLTV")

        before_refund = funder.getreceivedbyaddress(refund_dest)
        self._submit_spend(funder, "submitbountyrefund", hex_refund, funding_addr)
        after_refund = funder.getreceivedbyaddress(refund_dest)
        if abs(float(after_refund) - float(before_refund) - expect) > 1e-8:
            raise AssertionError(
                f"contributor refund missing: before={before_refund} after={after_refund} expect_delta={expect}"
            )
        assert_greater_than(float(after_refund), float(before_refund))

        self.log.info("create/find/on-chain award+refund ok")


if __name__ == "__main__":
    ModelnetBountyLifecycleTest(__file__).main()
