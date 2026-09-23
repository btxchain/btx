#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest create → find → complete a bounty request.

Owned helper (btxd spawns btx-modeld). Unix-only PQ1 (`-modelbind=off`).
Does not SIGKILL production btxd. --timeout-factor=1.

Proves:

  create   createbountydraft + publishbounty (signed terms)
  find     searchbounties LOCAL hits the published title/description
  complete wallet prepare/sign/submit of a real funding tx, mine it,
           observebountychain on that outpoint, commit/reveal,
           EXACT_CHECKS eval, proposebountyaward / approvebountyaward

On-chain award broadcast (`submitbountyaward`) is a later operator-built
tx. Completing the helper path does not auto-spend.
`automatic_spend_atoms` stays 0.

Run:

  python3 test/functional/feature_modelnet_bounty_lifecycle.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

MLDSA44_PUBKEY_SIZE = 1312
NETWORK_ID = "0" * 64
TITLE = "regtest-bounty-lifecycle-x7"
DESCRIPTION = "Japanese repository maintenance tooling for coding agents."
PRINCIPAL = 500000


def dummy_ml_dsa44(seed: int) -> str:
    return bytes((seed + i) & 0xFF for i in range(MLDSA44_PUBKEY_SIZE)).hex()


def council_keys(n: int = 3) -> list:
    return [{"public_key_hex": dummy_ml_dsa44(0x20 + i)} for i in range(n)]


def sample_terms() -> dict:
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
        "council": council_keys(3),
        "threshold": 2,
        "nomination_min_bps": 0,
        "target_atoms": "1000000",
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

    def _pq_or_dummy(self, node, seed: int) -> str:
        addr = node.getnewaddress()
        info = node.getaddressinfo(addr)
        pk = info.get("pubkey")
        if isinstance(pk, str) and len(pk) == 2624:
            return pk
        return dummy_ml_dsa44(seed)

    def run_test(self):
        node = self.nodes[0]
        helptext = node.help()
        for name in (
            "createbountydraft",
            "publishbounty",
            "searchbounties",
            "preparebountyfunding",
            "submitbountyfunding",
            "observebountychain",
            "proposebountyaward",
            "approvebountyaward",
        ):
            if name not in helptext:
                raise SkipTest(f"{name} not compiled")

        self._wait_helper(node)
        caps = node.getbountycapabilities()
        assert_equal(caps.get("automatic_spend_atoms", 1), 0)

        funding_addr = node.getnewaddress()
        self.generatetoaddress(node, 101, funding_addr)

        terms = sample_terms()
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
        refund_key = self._pq_or_dummy(node, 0x31)
        plan = {
            "principal_atoms": str(PRINCIPAL),
            "refund_key": refund_key,
            "fee_reserve_atoms": "10000000",
            "council_keys": [k["public_key_hex"] for k in council_keys(3)],
            "threshold": 2,
            "award_height": height + 200,
            "refund_height": height + 400,
        }
        prep = node.preparebountyfunding(plan)
        if not prep.get("unsigned_hex"):
            raise AssertionError(f"preparebountyfunding: {prep}")
        assert_equal(prep.get("automatic_spend"), 0)
        insp = node.inspectbountytransaction({**plan, "hex": prep["unsigned_hex"]})
        if not insp.get("escrow_output_present"):
            raise AssertionError(f"inspectbountytransaction: {insp}")
        signed = node.signbountyfunding({**plan, "hex": prep["unsigned_hex"], "plan_id": prep.get("plan_id")})
        if not signed.get("hex"):
            raise AssertionError(f"signbountyfunding: {signed}")
        decoded = node.decoderawtransaction(signed["hex"])
        script = prep.get("output_script")
        vout_n = 0
        for i, vout in enumerate(decoded.get("vout") or []):
            hx = ((vout.get("scriptPubKey") or {}).get("hex") or "")
            if script and hx == script:
                vout_n = int(vout.get("n", i))
                break
        sub = node.submitbountyfunding({"hex": signed["hex"]})
        if not sub.get("submitted") and not sub.get("duplicate"):
            raise AssertionError(f"submitbountyfunding: {sub}")
        txid = sub.get("txid") or decoded.get("txid")
        if not txid:
            raise AssertionError(f"submitbountyfunding missing txid: {sub}")
        mempool = node.getrawmempool()
        if txid not in mempool and not sub.get("duplicate"):
            raise AssertionError(f"funding tx not in mempool: {txid} {sub}")

        self.generatetoaddress(node, 6, funding_addr)
        outpoint = f"{txid}:{vout_n}"
        snap = node.observebountychain({
            "bounty_id": bounty_id,
            "outpoint": outpoint,
            "amount_atoms": str(PRINCIPAL),
            "confirmations": 6,
            "height": node.getblockcount(),
        })
        economy = node.getbountyeconomy({"bounty_id": bounty_id})
        nested = economy.get("economy") if isinstance(economy.get("economy"), dict) else {}
        chain = economy.get("chain") if isinstance(economy.get("chain"), dict) else {}
        confirmed = nested.get("confirmed_atoms")
        if confirmed is None:
            confirmed = chain.get("confirmed_atoms")
        if confirmed is None:
            confirmed = snap.get("confirmed_atoms") if isinstance(snap, dict) else None
        if str(confirmed) != str(PRINCIPAL):
            raise AssertionError(f"confirmed funding missing: economy={economy} snap={snap}")

        art = Path(self.options.tmpdir) / "artifact"
        art.mkdir(parents=True, exist_ok=True)
        (art / "weights.bin").write_bytes(b"\x00" * 32)
        commit = node.commitbountysubmission({
            "bounty_id": bounty_id,
            "commitment": {"artifact_digest": "ab" * 48},
        })
        cid = commit.get("commitment_id") or commit.get("record_id")
        if not cid:
            raise AssertionError(f"commitbountysubmission: {commit}")
        reveal = node.revealbountysubmission({
            "commitment_id": cid,
            "submission": {
                "artifact_dir": str(art),
                "evaluation_spec_id": "e2e-exact-checks",
            },
        })
        sid = reveal.get("submission_id")
        if not sid:
            raise AssertionError(f"revealbountysubmission: {reveal}")

        eval_plan = node.preparebountyevaluation({
            "submission_id": sid,
            "profile_id": "EXACT_CHECKS",
            "required_files": ["weights.bin"],
        })
        plan_id = eval_plan.get("plan_id")
        if not plan_id:
            raise AssertionError(f"preparebountyevaluation: {eval_plan}")
        job = node.runbountyevaluation({
            "plan_id": plan_id,
            "execution_approval_ref": "regtest-user",
        })
        if job.get("state") != "COMPLETE" and not job.get("report"):
            raise AssertionError(f"runbountyevaluation: {job}")
        if job.get("pass") is False:
            raise AssertionError(f"EXACT_CHECKS failed: {job}")
        pub_eval = node.publishbountyevaluation({"job_id": job.get("job_id")})
        assert_equal(pub_eval.get("is_award"), False)

        award = node.proposebountyaward({
            "bounty_id": bounty_id,
            "submission_id": sid,
            "mode": "PUBLIC_PAYOUT",
        })
        aid = award.get("award_id")
        if not aid:
            raise AssertionError(f"proposebountyaward: {award}")
        assert_equal(award.get("paid"), False)
        approved = node.approvebountyaward({"award_id": aid, "decision": "APPROVE"})
        assert_equal(approved.get("transaction_signature"), False)

        feed = node.getmodelfeed({"scope": "LOCAL", "mode": "NEWEST", "limit": 20})
        assert_equal(feed.get("automatic_spend_atoms", 1), 0)
        self.log.info("create/find/complete ok bounty_id=%s outpoint=%s award_id=%s", bounty_id, outpoint, aid)


if __name__ == "__main__":
    ModelnetBountyLifecycleTest(__file__).main()
