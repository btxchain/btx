#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest Pay With Compute qualification. Toy profile only. Not consensus."""

import hashlib
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_datadir_path

MATMUL_OFF = [
    "-modelnet=0",
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


class ComputeQualificationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [
            MATMUL_OFF,
            [*MATMUL_OFF, "-enablecomputetestprofiles=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()

    def run_test(self):
        plain = self.nodes[0]
        node = self.nodes[1]
        hidden = {p["profile_name"] for p in plain.getcomputeworkprofiles()["profiles"]}
        assert_equal("btx-rc-p1e-v1" in hidden, True)
        assert_equal("btx-rc-p1e-toy-v1" in hidden, False)
        assert_code(lambda: plain.getcomputeworkprofile("btx-rc-p1e-toy-v1"), "COMPUTE_TEST_PROFILE_DISABLED")

        listed = node.getcomputeworkprofiles()
        names = {p["profile_name"]: p for p in listed["profiles"]}
        assert_equal(listed["test_profiles_enabled"], True)
        assert_equal(names["btx-rc-p1e-v1"]["test_only"], False)
        assert_equal(names["btx-rc-p1e-toy-v1"]["test_only"], True)
        assert_equal(listed["microunits_per_episode"], 1000000)
        toy = node.getcomputeworkprofile("btx-rc-p1e-toy-v1")
        assert_equal(toy["profile_id"], names["btx-rc-p1e-toy-v1"]["profile_id"])
        assert_equal(toy["profile_name"], "btx-rc-p1e-toy-v1")

        subject = hashlib.sha256(b"worker-subject").hexdigest()
        node.setmocktime(1_700_000_000)
        challenge = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 300)
        assert_equal(challenge["kind"], "btx_compute_qualification_v1")
        assert_equal(challenge["episode_count"], 1)
        response = node.solvecomputequalification(challenge, "cpu")
        assert_equal(len(response["episodes"]), 1)
        verified = node.verifycomputequalification(challenge, response)
        assert_equal(verified["valid"], True)
        assert_equal(verified["redeemed"], False)
        redeemed = node.redeemcomputequalification(challenge, response)
        assert_equal(redeemed["valid"], True)
        assert_equal(redeemed["redeemed"], True)
        assert_equal(redeemed["demonstrated_p1e_microunits"], 1000000)
        assert_code(lambda: node.redeemcomputequalification(challenge, response), "COMPUTE_CHALLENGE_REDEEMED")

        status = node.getcomputequalificationstatus(challenge["challenge_id"])
        assert_equal(status["status"], "redeemed")
        info = node.getblockchaininfo()
        assert_equal(info["chain"], "regtest")
        health = node.getcomputestatus()
        assert_equal(health["healthy"], True)
        assert_equal(health["test_profiles_enabled"], True)
        assert_equal("balance" in health, False)

        node.setmocktime(1_700_000_000)
        short = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 30)
        solved = node.solvecomputequalification(short, "cpu")
        node.setmocktime(1_700_000_120)
        assert_code(lambda: node.redeemcomputequalification(short, solved), "COMPUTE_CHALLENGE_EXPIRED")

        other = hashlib.sha256(b"other-subject").hexdigest()
        node.setmocktime(1_700_000_200)
        fresh = node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 1, 300)
        fresh_response = node.solvecomputequalification(fresh, "cpu")
        mismatch = dict(fresh_response)
        mismatch["subject_digest"] = other
        assert_code(lambda: node.verifycomputequalification(fresh, mismatch), "COMPUTE_SUBJECT_MISMATCH")
        bad_profile = dict(fresh_response)
        bad_profile["profile_id"] = "00" * 48
        assert_code(lambda: node.verifycomputequalification(fresh, bad_profile), "COMPUTE_PROFILE_MISMATCH")
        assert_code(lambda: node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 0, 30), "COMPUTE_CHALLENGE_INVALID")
        assert_code(lambda: node.issuecomputequalification(subject, "btx-rc-p1e-toy-v1", 99, 30), "COMPUTE_CHALLENGE_INVALID")

        self.restart_node(1)
        self.nodes[1].setmocktime(1_700_000_200)
        again = self.nodes[1].getcomputequalificationstatus(challenge["challenge_id"])
        assert_equal(again["status"], "redeemed")
        assert_code(lambda: self.nodes[1].redeemcomputequalification(challenge, response), "COMPUTE_CHALLENGE_REDEEMED")

        self.stop_node(1)
        reg = Path(get_datadir_path(self.options.tmpdir, 1)) / "regtest" / "compute_qualifications.dat"
        reg.write_text("not-a-registry\n", encoding="utf-8")
        self.start_node(1)
        broken = self.nodes[1].getcomputestatus()
        assert_equal(broken["healthy"], False)
        assert_equal("quarantine" in broken.get("error", "") or "quarantine_path" in broken, True)
        chain = self.nodes[1].getblockchaininfo()
        assert_equal(chain["chain"], "regtest")


if __name__ == "__main__":
    ComputeQualificationTest(__file__).main()
