#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Pay With Compute review regressions over the btxd -> btx-modeld RPC path.

REGTEST TEST ONLY. Toy profile. Nothing here touches consensus.

R1  the qualification anchor must be on the active chain at redeem time
    (a reorg that removes the anchor block refuses the redeem).
R2  an agreement is frozen only from an offer this node issued; an imported
    offer's own scheduler and receipt issuer cannot earn this node's grant.
R3  a record too large for the 256 KiB helper reply is refused, so it cannot
    leave listcomputeoffers unanswerable.
R4  a quarantined registry is replaced by an empty one on the next restart;
    a challenge redeemed before that reads "unknown" and cannot redeem again.
"""

import hashlib
import json
import os
from pathlib import Path

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE, ADDRESS_BCRT1_UNSPENDABLE
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_datadir_path

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
MODEL_ARGS = [
    "-modelnet=1",
    "-modelbind=off",
    "-modelstorage=8MiB",
    "-autoshieldcoinbase=0",
    "-enablecomputetestprofiles=1",
    *MATMUL_OFF,
]
PLAIN_ARGS = ["-modelnet=0", "-autoshieldcoinbase=0", "-enablecomputetestprofiles=1", *MATMUL_OFF]
RESOURCE = "urn:btx:pwc:demo-model"
HELPER_REPLY_CAP = 256 * 1024


def expect_error(fn, code):
    try:
        fn()
    except JSONRPCException as exc:
        if code not in exc.error["message"]:
            raise AssertionError(f"expected {code}, got {exc.error['message']}") from exc
        return exc.error["message"]
    raise AssertionError(f"expected {code}, call succeeded")


def offer_for(issuer, schedulers, issuers, required, nonce, resource=RESOURCE, profile_id=None):
    return {
        "record_type": "compute_offer_v1",
        "schema_version": 1,
        "issuer_pubkey": issuer,
        "created_at_ms": 1,
        "expires_at_ms": 10_000_000,
        "nonce": nonce,
        "resource_ref": resource,
        "access": {"access_kind": "MODEL_ACCESS", "period_ms": 1_800_000, "rights": ["USE"]},
        "settlement": {
            "profile_id": profile_id,
            "required_p1e_microunits": required,
            "schedule": "PREPAID",
            "allowed_settlement_modes": ["USEFUL_JOB_RECEIPTS", "DIRECT_COMPUTE"],
            "qualification_required": False,
            "allowed_job_classes": ["REGTEST_DETERMINISTIC"],
            "authorized_job_scheduler_pubkeys": schedulers,
            "authorized_receipt_issuer_pubkeys": issuers,
        },
        "policy": {"transferable": False, "cash_redeemable": False, "cross_agreement_credit": False, "carryover": False},
    }


class PayWithComputeReviewTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.supports_cli = False
        # node3 runs with the attacker's key but without the attacker's offer,
        # as an attacker controlling two machines would.
        self.extra_args = [MODEL_ARGS, MODEL_ARGS, PLAIN_ARGS, MODEL_ARGS]

    def setup_network(self):
        # Private nodes; they never connect to each other.
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        if not builddir or not Path(builddir, "bin", f"btx-modeld{exeext}").is_file():
            if not os.environ.get("BTXMODELD"):
                raise SkipTest("btx-modeld not found")

    def run_test(self):
        provider, attacker, plain, _ = self.nodes
        self.stop_node(3)
        ident = Path("regtest", "modelnet", "research_identity.json")
        src = Path(get_datadir_path(self.options.tmpdir, 1)) / ident
        dst = Path(get_datadir_path(self.options.tmpdir, 3)) / ident
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        self.start_node(3)
        for node in (provider, attacker, self.nodes[3]):
            self.wait_until(lambda n=node: n.getmodelnetworkinfo().get("helper_ready"), timeout=60)
        assert_equal(self.nodes[3].getcomputesigningidentity()["public_key_hex"],
                     attacker.getcomputesigningidentity()["public_key_hex"])
        self.pid = provider.getcomputeworkprofile("btx-rc-p1e-toy-v1")["profile_id"]
        failures = []
        for name, fn in (("R1", lambda: self.r1_anchor_reorg(plain)),
                         ("R2", lambda: self.r2_agreement_needs_own_offer(provider, attacker, self.nodes[3])),
                         ("R3", lambda: self.r3_record_size(provider)),
                         ("R4", self.r4_quarantine_then_reset)):
            try:
                fn()
                self.log.info("%s PASS", name)
            except (AssertionError, JSONRPCException) as exc:
                self.log.error("%s FAIL: %s", name, exc)
                failures.append(name)
        assert not failures, f"failed: {failures}"

    def r1_anchor_reorg(self, node):
        self.log.info("R1 a reorg that removes the anchor block refuses the redeem")
        self.generatetoaddress(node, 3, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        subject = hashlib.sha256(b"r1-subject").hexdigest()
        challenge = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 600)
        assert_equal(challenge["anchor_hash"], node.getbestblockhash())
        response = node.solvecomputequalification(challenge, "cpu")
        node.invalidateblock(challenge["anchor_hash"])
        self.generatetoaddress(node, 2, ADDRESS_BCRT1_P2WSH_OP_TRUE, sync_fun=self.no_op)
        assert challenge["anchor_hash"] != node.getblockhash(challenge["anchor_height"])
        expect_error(lambda: node.verifycomputequalification(challenge, response), "COMPUTE_CHALLENGE_INVALID")
        expect_error(lambda: node.redeemcomputequalification(challenge, response), "COMPUTE_CHALLENGE_INVALID")
        assert_equal(node.getcomputequalificationstatus(challenge["challenge_id"])["status"], "issued")
        # Positive control: a challenge anchored on the new tip redeems.
        fresh = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 600)
        assert_equal(node.redeemcomputequalification(fresh, node.solvecomputequalification(fresh, "cpu"))["redeemed"], True)

    def r2_agreement_needs_own_offer(self, provider, attacker, attacker2):
        self.log.info("R2 the provider does not freeze an imported offer into an agreement it signs")
        P = provider.getcomputesigningidentity()["public_key_hex"]
        A = attacker.getcomputesigningidentity()["public_key_hex"]
        # The attacker's offer names the provider's resource and lists only the
        # attacker as scheduler and receipt issuer.
        offer = attacker.createcomputeoffer({"offer": offer_for(A, [A], [A], 1_000_000, "r2", profile_id=self.pid), "now_ms": 1000})
        provider.importcomputeoffer({"envelope": offer})
        req = {"offer_id": offer["offer_id"], "subject_pubkey": A, "period_start_ms": 1000,
               "period_end_ms": 9_000_000, "nonce": "r2", "now_ms": 1000}
        try:
            agreement = provider.issuecomputeagreement(req)
        except JSONRPCException as exc:
            assert "COMPUTE_RECORD_INVALID" in exc.error["message"], exc.error["message"]
            self.log.info("  refused: %s", exc.error["message"])
            return
        # Unpatched: walk the whole path to show what the signature buys.
        aid = agreement["agreement_id"]
        attacker2.importcomputeagreement({"envelope": agreement})
        job = attacker2.createcomputejob({"agreement_id": aid, "subject_pubkey": A, "job_class": "REGTEST_DETERMINISTIC",
                                         "credit_p1e_microunits": 1_000_000, "input_commitment": "r2", "executor_spec_commitment": "x",
                                         "expires_at_ms": 8_000_000, "nonce": "r2", "now_ms": 1100})
        result = attacker2.submitcomputejobresult({"job_id": job["job_id"], "output_commitment": "anything", "now_ms": 1200})
        receipt = attacker2.acceptcomputejobresult({"result_id": result["result_id"], "now_ms": 1300})
        provider.importcomputejob({"envelope": job, "now_ms": 1350})
        provider.importcomputereceipt({"envelope": receipt})
        grant = provider.issuecomputeaccessgrant({"agreement_id": aid, "now_ms": 1500})
        verdict = provider.verifycomputeaccessgrant({"envelope": grant, "trusted_issuer_pubkey": P, "subject_pubkey": A,
                                                     "resource_ref": RESOURCE, "now_ms": 2000})
        self.log.info("  UNPATCHED: provider-signed grant for %s verifies: %s", RESOURCE, verdict.get("valid"))
        raise AssertionError("provider signed an agreement under an offer it did not issue; attacker holds a valid grant")

    def r3_record_size(self, provider):
        self.log.info("R3 a record larger than the helper reply cap is refused, listing stays answerable")
        P = provider.getcomputesigningidentity()["public_key_hex"]
        offer = offer_for(P, [P], [P], 1_000_000, "r3", profile_id=self.pid)
        req = {"offer": offer, "now_ms": 1000}
        # Size the request so it reaches btx-modeld whole and its signed preimage
        # stays under the codec's 256 KiB envelope limit (strings <= 8 KiB each),
        # while the stored JSON, which adds the 2420-byte signature as hex, is
        # larger than the 256 KiB helper reply.
        wire = '{"jsonrpc":"1.0","id":"model","method":"createcomputeoffer","params":[%s]}\n'
        offer["note"] = []
        target = HELPER_REPLY_CAP - 5600
        while True:
            size = len(wire % json.dumps(req, separators=(",", ":")))
            if size >= target:
                break
            offer["note"].append("x" * min(8000, max(1, target - size - 3)))
        self.log.info("  request %d bytes", len(wire % json.dumps(req, separators=(",", ":"))))
        try:
            provider.createcomputeoffer(req)
            self.log.info("  createcomputeoffer accepted the large offer")
        except JSONRPCException as exc:
            self.log.info("  createcomputeoffer: %s", exc.error["message"][:120])
        try:
            listed = provider.listcomputeoffers({})
        except JSONRPCException as exc:
            raise AssertionError(f"listcomputeoffers is unanswerable: {exc.error['message'][:160]}") from exc
        assert all(len(json.dumps(r)) < HELPER_REPLY_CAP for r in listed["records"])

    def r4_quarantine_then_reset(self):
        self.log.info("R4 quarantine, then an empty registry on the next start; old challenges stay dead")
        node = self.nodes[2]
        subject = hashlib.sha256(b"r4-subject").hexdigest()
        challenge = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 600)
        response = node.solvecomputequalification(challenge, "cpu")
        node.redeemcomputequalification(challenge, response)
        pending = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 600)
        pending_response = node.solvecomputequalification(pending, "cpu")
        self.stop_node(2)
        reg = Path(get_datadir_path(self.options.tmpdir, 2)) / "regtest" / "compute_qualifications.dat"
        reg.write_text("not-a-registry\n", encoding="utf-8")
        self.start_node(2)
        node = self.nodes[2]
        assert_equal(node.getcomputestatus()["healthy"], False)
        expect_error(lambda: node.redeemcomputequalification(challenge, response), "COMPUTE_CHALLENGE")
        self.restart_node(2)
        node = self.nodes[2]
        status = node.getcomputestatus()
        self.log.info("  after second start: healthy=%s entries=%s", status["healthy"], status["entries"])
        assert_equal(status["entries"], 0)
        assert_equal(node.getcomputequalificationstatus(challenge["challenge_id"])["status"], "unknown")
        expect_error(lambda: node.redeemcomputequalification(challenge, response), "COMPUTE_CHALLENGE_UNKNOWN")
        expect_error(lambda: node.redeemcomputequalification(pending, pending_response), "COMPUTE_CHALLENGE_UNKNOWN")


if __name__ == "__main__":
    PayWithComputeReviewTest(__file__).main()
