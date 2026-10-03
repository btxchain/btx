#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Model-plane Pay With Compute records. Regtest toy profile. No wallet spend."""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


def assert_code(fn, code):
    try:
        fn()
    except JSONRPCException as exc:
        if code not in exc.error["message"]:
            raise AssertionError(exc.error["message"]) from exc
        return
    raise AssertionError(f"expected {code}")


class ModelnetComputeEconomyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [
            [
                "-modelnet=1",
                "-modelbind=off",
                "-modelstorage=8MiB",
                "-autoshieldcoinbase=0",
                "-enablecomputetestprofiles=1",
                *MATMUL_OFF,
            ],
            [
                "-modelnet=0",
                "-autoshieldcoinbase=0",
                *MATMUL_OFF,
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        import os
        from pathlib import Path
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        if not builddir or not Path(builddir, "bin", f"btx-modeld{exeext}").is_file():
            if not os.environ.get("BTXMODELD"):
                raise SkipTest("btx-modeld not found")

    def run_test(self):
        node = self.nodes[0]
        bare = self.nodes[1]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=30)
        assert_equal(bare.getblockchaininfo()["chain"], "regtest")
        assert_code(lambda: bare.createcomputeoffer({}), "model helper unavailable")
        ident = node.getcomputesigningidentity()
        pk = ident["public_key_hex"]
        profile = node.getcomputeworkprofile("btx-rc-p1e-toy-v1")
        offer = {
            "record_type": "compute_offer_v1",
            "schema_version": 1,
            "issuer_pubkey": pk,
            "created_at_ms": 1,
            "expires_at_ms": 10_000_000,
            "nonce": "aa",
            "resource_ref": "urn:btx:pwc:demo-model",
            "access": {"access_kind": "MODEL_ACCESS", "period_ms": 1_800_000, "rights": ["USE"]},
            "settlement": {
                "profile_id": profile["profile_id"],
                "required_p1e_microunits": 1_000_000,
                "schedule": "PREPAID",
                "allowed_settlement_modes": ["USEFUL_JOB_RECEIPTS", "DIRECT_COMPUTE"],
                "qualification_required": False,
                "allowed_job_classes": ["REGTEST_DETERMINISTIC"],
                "authorized_job_scheduler_pubkeys": [pk],
                "authorized_receipt_issuer_pubkeys": [pk],
            },
            "policy": {
                "transferable": False,
                "cash_redeemable": False,
                "cross_agreement_credit": False,
                "carryover": False,
            },
        }
        created = node.createcomputeoffer({"offer": offer, "now_ms": 1000})
        assert_equal(created["automatic_spend_atoms"], 0)
        imported = node.importcomputeoffer({"envelope": created})
        assert_equal(imported["offer_id"], created["offer_id"])
        passport = node.buildcomputepassport({
            "profile_name": "btx-rc-p1e-toy-v1",
            "wall_us": [1_000_000],
            "backend_requested": "cpu",
            "backend_resolved": "cpu",
        })
        quote = node.quotecomputeaccess({
            "offer_id": created["offer_id"],
            "passport": passport,
            "duty_cycle_bps": 10000,
            "now_ms": 1000,
        })
        assert_equal(quote["profile_match"], True)
        assert_equal(quote["estimate_only"], True)
        assert_equal(quote["settlement_requires_receipts"], True)
        assert_equal(quote["automatic_spend_atoms"], 0)
        agreement = node.issuecomputeagreement({
            "offer_id": created["offer_id"],
            "subject_pubkey": pk,
            "period_start_ms": 1000,
            "period_end_ms": 5000,
            "now_ms": 1000,
        })
        job = node.createcomputejob({
            "agreement_id": agreement["agreement_id"],
            "subject_pubkey": pk,
            "job_class": "REGTEST_DETERMINISTIC",
            "credit_p1e_microunits": 1_000_000,
            "input_commitment": "11",
            "executor_spec_commitment": "22",
            "expires_at_ms": 4000,
            "now_ms": 1500,
        })
        result = node.submitcomputejobresult({
            "job_id": job["job_id"],
            "output_commitment": "33",
            "now_ms": 1600,
        })
        node.acceptcomputejobresult({
            "result_id": result["result_id"],
            "expected_output_commitment": "33",
            "now_ms": 1700,
        })
        bal = node.getcomputebalance({"agreement_id": agreement["agreement_id"], "now_ms": 1800})
        assert_equal(bal["status"], "SATISFIED")
        assert_equal(bal["credited_p1e_microunits"], 1_000_000)
        assert_equal(bal["automatic_spend_atoms"], 0)
        grant = node.issuecomputeaccessgrant({"agreement_id": agreement["agreement_id"], "now_ms": 1800})
        verdict = node.verifycomputeaccessgrant({
            "envelope": grant,
            "trusted_issuer_pubkey": pk,
            "subject_pubkey": pk,
            "resource_ref": "urn:btx:pwc:demo-model",
            "now_ms": 1800,
        })
        assert_equal(verdict["valid"], True)
        # ~14 KB per signed receipt: 25 receipts exceed the 256 KiB helper reply, so page.
        page_offer = node.createcomputeoffer({
            "offer": {**offer, "nonce": "page", "settlement": {**offer["settlement"], "required_p1e_microunits": 100}},
            "now_ms": 1900,
        })
        page_agreement = node.issuecomputeagreement({
            "offer_id": page_offer["offer_id"],
            "subject_pubkey": pk,
            "period_start_ms": 1900,
            "period_end_ms": 9_000_000,
            "now_ms": 1900,
        })
        for i in range(24):
            page_job = node.createcomputejob({
                "agreement_id": page_agreement["agreement_id"],
                "subject_pubkey": pk,
                "job_class": "REGTEST_DETERMINISTIC",
                "credit_p1e_microunits": 1,
                "input_commitment": f"page-{i}",
                "executor_spec_commitment": "22",
                "expires_at_ms": 8_000_000,
                "nonce": f"page-{i}",
                "now_ms": 1900,
            })
            page_result = node.submitcomputejobresult({"job_id": page_job["job_id"], "output_commitment": "33", "now_ms": 1900})
            node.acceptcomputejobresult({"result_id": page_result["result_id"], "nonce": f"page-{i}", "now_ms": 1900})
        seen, start = [], 0
        while True:
            page = node.listcomputereceipts({"start": start})
            seen += [r["id"] for r in page["records"]]
            if "next_start" not in page:
                break
            start = page["next_start"]
        assert_equal(len(set(seen)), 25)
        assert_equal(node.listtransactions("*", 10), [])
        assert_equal(node.getcomputebalance({"agreement_id": agreement["agreement_id"], "now_ms": 1800})["automatic_spend_atoms"], 0)


if __name__ == "__main__":
    ModelnetComputeEconomyTest(__file__).main()
