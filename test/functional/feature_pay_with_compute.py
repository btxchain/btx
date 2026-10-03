#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two- and three-party regtest Pay With Compute. Toy units are REGTEST ONLY."""

import hashlib
import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
NODE_ARGS = [
    "-modelnet=1",
    "-modelbind=off",
    "-modelstorage=8MiB",
    "-autoshieldcoinbase=0",
    "-enablecomputetestprofiles=1",
    *MATMUL_OFF,
]


def assert_code(fn, code):
    try:
        fn()
    except JSONRPCException as exc:
        if code not in exc.error["message"]:
            raise AssertionError(exc.error["message"]) from exc
        return
    raise AssertionError(f"expected {code}")


def offer_for(profile_id, issuer, schedulers, issuers, required, schedule, job_class="REGTEST_DETERMINISTIC", qualification_required=False):
    return {
        "record_type": "compute_offer_v1",
        "schema_version": 1,
        "issuer_pubkey": issuer,
        "created_at_ms": 1,
        "expires_at_ms": 10_000_000,
        "nonce": hashlib.sha256(f"{schedule}:{required}:{job_class}".encode()).hexdigest()[:16],
        "resource_ref": "urn:btx:pwc:demo-model",
        "access": {"access_kind": "MODEL_ACCESS", "period_ms": 1_800_000, "rights": ["USE"]},
        "settlement": {
            "profile_id": profile_id,
            "required_p1e_microunits": required,
            "schedule": schedule,
            "allowed_settlement_modes": ["USEFUL_JOB_RECEIPTS", "DIRECT_COMPUTE"],
            "qualification_required": qualification_required,
            "allowed_job_classes": [job_class],
            "authorized_job_scheduler_pubkeys": schedulers,
            "authorized_receipt_issuer_pubkeys": issuers,
        },
        "policy": {
            "transferable": False,
            "cash_redeemable": False,
            "cross_agreement_credit": False,
            "carryover": False,
        },
    }


def det_commit(input_commitment):
    return hashlib.sha256(b"BTX/PWC/regtest-job/v1" + input_commitment.encode()).hexdigest()


class PayWithComputeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [NODE_ARGS, NODE_ARGS, NODE_ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        if not builddir or not Path(builddir, "bin", f"btx-modeld{exeext}").is_file():
            if not os.environ.get("BTXMODELD"):
                raise SkipTest("btx-modeld not found")

    def run_test(self):
        provider, worker, scheduler = self.nodes
        for node in self.nodes:
            self.wait_until(lambda n=node: n.getmodelnetworkinfo().get("helper_ready"), timeout=30)
        ppk = provider.getcomputesigningidentity()["public_key_hex"]
        wpk = worker.getcomputesigningidentity()["public_key_hex"]
        spk = scheduler.getcomputesigningidentity()["public_key_hex"]
        profile = provider.getcomputeworkprofile("btx-rc-p1e-toy-v1")
        pid = profile["profile_id"]
        assert_equal(profile["test_only"], True)

        passport = worker.buildcomputepassport({
            "profile_name": "btx-rc-p1e-toy-v1",
            "wall_us": [1_000_000, 1_100_000, 900_000, 1_050_000, 980_000],
            "backend_requested": "cpu",
            "backend_resolved": "cpu",
        })
        assert_equal(passport["self_attested"], True)
        assert_equal(passport["test_only"], True)
        assert_equal(passport["p99_claimable"], False)

        created = provider.createcomputeoffer({
            "offer": offer_for(pid, ppk, [ppk, spk], [ppk, spk], 3_000_000, "PREPAID", qualification_required=True),
            "now_ms": 1000,
        })
        quote = worker.quotecomputeaccess({
            "offer": created["body"]["payload"],
            "passport": passport,
            "duty_cycle_bps": 10000,
        })
        assert_equal(quote["profile_match"], True)
        assert_equal(quote["required_p1e_microunits"], 3_000_000)
        assert_equal(quote["settlement_requires_receipts"], True)
        assert_equal(quote["estimate_only"], True)

        subject = hashlib.sha256(bytes.fromhex(wpk)).hexdigest()
        provider.setmocktime(1_700_000_000)
        worker.setmocktime(1_700_000_000)
        challenge = provider.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 600)
        response = worker.solvecomputequalification(challenge, "cpu")
        redeemed = provider.redeemcomputequalification(challenge, response)
        assert_equal(redeemed["valid"], True)
        assert_equal(redeemed["demonstrated_p1e_microunits"], 1_000_000)
        assert_code(lambda: provider.redeemcomputequalification(challenge, response), "COMPUTE_CHALLENGE_REDEEMED")

        forged = {
            "offer_id": created["offer_id"],
            "subject_pubkey": wpk,
            "period_start_ms": 1000,
            "period_end_ms": 9_000_000,
            "now_ms": 2000,
            "qualification": {
                "method": "btx_compute_qualification_v1",
                "challenge_id": "00" * 48,
                "profile_id": pid,
                "verified_at_ms": 2000,
                "demonstrated_p1e_microunits": 1_000_000,
                "conservative_rate_p1e_microunits_per_hour": 1,
            },
        }
        assert_code(lambda: provider.issuecomputeagreement(forged), "COMPUTE_QUALIFICATION_REQUIRED")

        agreement = provider.issuecomputeagreement({
            "offer_id": created["offer_id"],
            "subject_pubkey": wpk,
            "period_start_ms": 1000,
            "period_end_ms": 9_000_000,
            "now_ms": 2000,
            "qualification": {
                "method": "btx_compute_qualification_v1",
                "challenge_id": challenge["challenge_id"],
                "profile_id": pid,
                "verified_at_ms": 2000,
                "demonstrated_p1e_microunits": redeemed["demonstrated_p1e_microunits"],
                "conservative_rate_p1e_microunits_per_hour": redeemed["conservative_rate_p1e_microunits_per_hour"],
            },
        })
        worker.importcomputeagreement({"envelope": agreement})
        aid = agreement["agreement_id"]
        assert_code(
            lambda: worker.createcomputejob({
                "agreement_id": aid,
                "subject_pubkey": wpk,
                "job_class": "REGTEST_DETERMINISTIC",
                "credit_p1e_microunits": 1_000_000,
                "input_commitment": "not-a-scheduler",
                "executor_spec_commitment": "regtest-runner",
                "expires_at_ms": 8_000_000,
                "nonce": "not-a-scheduler",
                "now_ms": 2500,
            }),
            "COMPUTE_UNAUTHORIZED_SCHEDULER",
        )

        def settle(credit, nonce, beneficiary=""):
            job = provider.createcomputejob({
                "agreement_id": aid,
                "subject_pubkey": wpk,
                "job_class": "REGTEST_DETERMINISTIC",
                "credit_p1e_microunits": credit,
                "input_commitment": nonce,
                "executor_spec_commitment": "regtest-runner",
                "expires_at_ms": 8_000_000,
                "beneficiary_ref": beneficiary,
                "nonce": nonce,
                "now_ms": 3000,
            })
            worker.importcomputejob({"envelope": job, "now_ms": 3000})
            output = det_commit(nonce)
            result = worker.submitcomputejobresult({
                "job_id": job["job_id"],
                "output_commitment": output,
                "now_ms": 3100,
            })
            provider.importcomputejobresult({"envelope": result, "now_ms": 3100})
            receipt = provider.acceptcomputejobresult({
                "result_id": result["result_id"],
                "expected_output_commitment": output,
                "now_ms": 3200,
            })
            return job, result, receipt

        settle(2_000_000, "job-1", "urn:btx:pwc:another-model")
        bal = provider.getcomputebalance({"agreement_id": aid, "now_ms": 3300})
        assert_equal(bal["credited_p1e_microunits"], 2_000_000)
        assert_equal(bal["status"], "OPEN")
        assert_code(lambda: provider.issuecomputeaccessgrant({"agreement_id": aid, "now_ms": 3300}), "COMPUTE_NOT_SATISFIED")
        _, _, receipt = settle(1_000_000, "job-2")
        assert_code(
            lambda: provider.acceptcomputejobresult({"result_id": receipt["body"]["payload"]["result_id"], "now_ms": 3400}),
            "COMPUTE_JOB_ALREADY_SETTLED",
        )
        bal = provider.getcomputebalance({"agreement_id": aid, "now_ms": 3500})
        assert_equal(bal["status"], "SATISFIED")
        assert_equal(bal["credited_p1e_microunits"], 3_000_000)
        grant = provider.issuecomputeaccessgrant({"agreement_id": aid, "now_ms": 3500})
        assert_code(
            lambda: worker.verifycomputeaccessgrant({
                "envelope": grant,
                "subject_pubkey": wpk,
                "resource_ref": "urn:btx:pwc:demo-model",
                "now_ms": 3500,
            }),
            "COMPUTE_GRANT_INVALID",
        )
        assert_code(
            lambda: worker.verifycomputeaccessgrant({
                "envelope": grant,
                "trusted_issuer_pubkey": wpk,
                "subject_pubkey": wpk,
                "resource_ref": "urn:btx:pwc:demo-model",
                "now_ms": 3500,
            }),
            "COMPUTE_GRANT_INVALID",
        )
        assert_code(
            lambda: worker.verifycomputeaccessgrant({
                "envelope": grant,
                "trusted_issuer_pubkey": ppk,
                "subject_pubkey": ppk,
                "resource_ref": "urn:btx:pwc:demo-model",
                "now_ms": 3500,
            }),
            "COMPUTE_GRANT_INVALID",
        )
        worker.importcomputeaccessgrant({"envelope": grant})
        allowed = worker.verifycomputeaccessgrant({
            "envelope": grant,
            "trusted_issuer_pubkey": ppk,
            "subject_pubkey": wpk,
            "resource_ref": "urn:btx:pwc:demo-model",
            "now_ms": 3500,
        })
        assert_equal(allowed["valid"], True)

        self.restart_node(0)
        provider = self.nodes[0]
        bal = provider.getcomputebalance({"agreement_id": aid, "now_ms": 3600})
        assert_equal(bal["credited_p1e_microunits"], 3_000_000)
        assert_equal(bal["status"], "SATISFIED")
        assert_equal(provider.listtransactions("*", 20), [])
        assert_equal(bal["automatic_spend_atoms"], 0)

        direct_offer = provider.createcomputeoffer({
            "offer": offer_for(pid, ppk, [ppk], [ppk], 2_000_000, "PREPAID"),
            "now_ms": 4000,
        })
        direct_agreement = provider.issuecomputeagreement({
            "offer_id": direct_offer["offer_id"],
            "subject_pubkey": wpk,
            "period_start_ms": 4000,
            "period_end_ms": 9_000_000,
            "now_ms": 4000,
        })
        provider.setmocktime(1_700_000_500)
        worker.setmocktime(1_700_000_500)
        direct_challenge = provider.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 2, 600)
        direct_response = worker.solvecomputequalification(direct_challenge, "cpu")
        direct_redeemed = provider.redeemcomputequalification(direct_challenge, direct_response)
        assert_equal(direct_redeemed["demonstrated_p1e_microunits"], 2_000_000)
        assert_code(
            lambda: provider.issuecomputereceipt({
                "agreement_id": direct_agreement["agreement_id"],
                "subject_pubkey": wpk,
                "profile_id": pid,
                "credited_p1e_microunits": 2_000_000,
                "verification_method": "DIRECT_COMPUTE",
                "evidence_commitment": "00" * 48,
                "now_ms": 4100,
            }),
            "COMPUTE_QUALIFICATION_REQUIRED",
        )
        assert_code(
            lambda: provider.issuecomputereceipt({
                "agreement_id": direct_agreement["agreement_id"],
                "subject_pubkey": wpk,
                "profile_id": pid,
                "credited_p1e_microunits": 1_000_000,
                "verification_method": "DIRECT_COMPUTE",
                "evidence_commitment": direct_challenge["challenge_id"],
                "now_ms": 4100,
            }),
            "COMPUTE_RECEIPT_CREDIT_MISMATCH",
        )
        provider.issuecomputereceipt({
            "agreement_id": direct_agreement["agreement_id"],
            "subject_pubkey": wpk,
            "profile_id": pid,
            "credited_p1e_microunits": 2_000_000,
            "verification_method": "DIRECT_COMPUTE",
            "evidence_commitment": direct_challenge["challenge_id"],
            "now_ms": 4100,
        })
        dbal = provider.getcomputebalance({"agreement_id": direct_agreement["agreement_id"], "now_ms": 4200})
        assert_equal(dbal["status"], "SATISFIED")
        provider.issuecomputeaccessgrant({"agreement_id": direct_agreement["agreement_id"], "now_ms": 4200})

        clear_offer = provider.createcomputeoffer({
            "offer": offer_for(pid, ppk, [spk], [spk], 1_000_000, "PREPAID"),
            "now_ms": 5000,
        })
        clear_agreement = provider.issuecomputeagreement({
            "offer_id": clear_offer["offer_id"],
            "subject_pubkey": wpk,
            "period_start_ms": 5000,
            "period_end_ms": 9_000_000,
            "now_ms": 5000,
        })
        scheduler.importcomputeagreement({"envelope": clear_agreement})
        worker.importcomputeagreement({"envelope": clear_agreement})
        job = scheduler.createcomputejob({
            "agreement_id": clear_agreement["agreement_id"],
            "subject_pubkey": wpk,
            "job_class": "REGTEST_DETERMINISTIC",
            "credit_p1e_microunits": 1_000_000,
            "input_commitment": "cleared",
            "executor_spec_commitment": "regtest-runner",
            "beneficiary_ref": "urn:btx:pwc:another-model",
            "expires_at_ms": 8_000_000,
            "nonce": "clear-1",
            "now_ms": 5100,
        })
        provider.importcomputejob({"envelope": job, "now_ms": 5100})
        worker.importcomputejob({"envelope": job, "now_ms": 5100})
        output = det_commit("cleared")
        result = worker.submitcomputejobresult({"job_id": job["job_id"], "output_commitment": output, "now_ms": 5200})
        scheduler.importcomputejobresult({"envelope": result, "now_ms": 5200})
        receipt = scheduler.acceptcomputejobresult({
            "result_id": result["result_id"],
            "expected_output_commitment": output,
            "now_ms": 5300,
        })
        provider.importcomputereceipt({"envelope": receipt})
        cbal = provider.getcomputebalance({"agreement_id": clear_agreement["agreement_id"], "now_ms": 5400})
        assert_equal(cbal["credited_p1e_microunits"], 1_000_000)
        assert_equal(cbal["status"], "SATISFIED")
        assert_code(
            lambda: worker.issuecomputereceipt({
                "agreement_id": clear_agreement["agreement_id"],
                "subject_pubkey": wpk,
                "profile_id": pid,
                "credited_p1e_microunits": 1_000_000,
                "now_ms": 5500,
            }),
            "COMPUTE_UNAUTHORIZED_RECEIPT_ISSUER",
        )

        pro_offer = provider.createcomputeoffer({
            "offer": offer_for(pid, ppk, [ppk], [ppk], 8_000_000, "PRO_RATA"),
            "now_ms": 0,
        })
        pro = provider.issuecomputeagreement({
            "offer_id": pro_offer["offer_id"],
            "subject_pubkey": wpk,
            "period_start_ms": 0,
            "period_end_ms": 8000,
            "now_ms": 0,
        })
        worker.importcomputeagreement({"envelope": pro})
        due = provider.getcomputebalance({"agreement_id": pro["agreement_id"], "now_ms": 2000})
        assert_equal(due["due_now_p1e_microunits"], 2_000_000)
        assert_equal(due["status"], "OPEN")
        job = provider.createcomputejob({
            "agreement_id": pro["agreement_id"],
            "subject_pubkey": wpk,
            "job_class": "REGTEST_DETERMINISTIC",
            "credit_p1e_microunits": 2_000_000,
            "input_commitment": "pace-1",
            "executor_spec_commitment": "regtest-runner",
            "expires_at_ms": 9000,
            "nonce": "pace-1",
            "now_ms": 2000,
        })
        worker.importcomputejob({"envelope": job, "now_ms": 2000})
        output = det_commit("pace-1")
        result = worker.submitcomputejobresult({"job_id": job["job_id"], "output_commitment": output, "now_ms": 2100})
        provider.importcomputejobresult({"envelope": result, "now_ms": 2100})
        provider.acceptcomputejobresult({"result_id": result["result_id"], "expected_output_commitment": output, "now_ms": 2200})
        standing = provider.getcomputebalance({"agreement_id": pro["agreement_id"], "now_ms": 2000})
        assert_equal(standing["status"], "IN_GOOD_STANDING")
        grant = provider.issuecomputeaccessgrant({"agreement_id": pro["agreement_id"], "now_ms": 2000})
        assert_equal(grant["body"]["payload"]["valid_until_ms"], 8000)
        later = provider.getcomputebalance({"agreement_id": pro["agreement_id"], "now_ms": 6000})
        assert_equal(later["due_now_p1e_microunits"], 6_000_000)
        assert_equal(later["status"], "OPEN")
        assert_code(lambda: provider.issuecomputeaccessgrant({"agreement_id": pro["agreement_id"], "now_ms": 6000}), "COMPUTE_NOT_SATISFIED")
        job = provider.createcomputejob({
            "agreement_id": pro["agreement_id"],
            "subject_pubkey": wpk,
            "job_class": "REGTEST_DETERMINISTIC",
            "credit_p1e_microunits": 4_000_000,
            "input_commitment": "pace-2",
            "executor_spec_commitment": "regtest-runner",
            "expires_at_ms": 9000,
            "nonce": "pace-2",
            "now_ms": 6100,
        })
        worker.importcomputejob({"envelope": job, "now_ms": 6100})
        output = det_commit("pace-2")
        result = worker.submitcomputejobresult({"job_id": job["job_id"], "output_commitment": output, "now_ms": 6200})
        provider.importcomputejobresult({"envelope": result, "now_ms": 6200})
        provider.acceptcomputejobresult({"result_id": result["result_id"], "expected_output_commitment": output, "now_ms": 6300})
        back = provider.getcomputebalance({"agreement_id": pro["agreement_id"], "now_ms": 6000})
        assert_equal(back["due_now_p1e_microunits"], 6_000_000)
        assert_equal(back["status"], "IN_GOOD_STANDING")
        provider.issuecomputeaccessgrant({"agreement_id": pro["agreement_id"], "now_ms": 6000})
        assert_equal(provider.getblockchaininfo()["chain"], "regtest")


if __name__ == "__main__":
    PayWithComputeTest(__file__).main()
