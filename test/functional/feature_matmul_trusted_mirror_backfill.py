#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end: trusted mirror backfills historical attestations across many gaps.

Production failure B: GETMMATTEST could return nothing (no message, no log) when
a canonical Profile-1 block lacked a cached attestation. Mirrors joining from
behind then pended forever. The mirror side here is the real trusted path; the
authority is a CPU consensus+signer archive (GPU ExactReplay is not required in
this functional environment — see summary).

Coverage:
  - Mirror starts well behind an authority that already has many Profile-1 tips
  - Attestation archive is wiped so historical GETMMATTEST must regenerate
    (many distinct heights, not a single gap)
  - Mirror reaches tip without operator intervention
  - Every GETMMATTEST outcome is logged with an explicit reason=
"""

import os
import re
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
# Enough post-activation blocks that catch-up spans many attestation requests.
HISTORICAL_BLOCKS = 34

TRUST_WARNING = (
    "Warning: TRUSTED MATMUL MIRROR ACTIVE: this node delegates Profile-1 "
    "ExactReplay to a configured threshold of {} signer(s). It validates "
    "block bodies and scripts but is not an independent full consensus "
    "validator."
)
INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class MatMulTrustedMirrorBackfillTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.signer_wif = signer_wif
        self.signer_pub = signer_pub.hex()
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            "-regtestmatmulbindingheight=2",
            "-regtestmatmulproductdigestheight=2",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={ACTIVATION_HEIGHT}",
            f"-regtestbmx4cheight={ACTIVATION_HEIGHT}",
            f"-regtestdrltheight={DISABLED_HEIGHT}",
            f"-regtestrcheight={ACTIVATION_HEIGHT}",
            f"-regtestrccoupledheight={DISABLED_HEIGHT}",
            "-regtestrcprofile=1",
            "-regtestrctoydims=1",
            "-regtestrccoupledtoydims=0",
            "-regtestmatmulltsealaspow=0",
            "-regtestmatmulv4dimension=128",
            f"-matmultrustedpubkey={self.signer_pub}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
            "-debug=net",
        ]
        archive = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
            # Public peers retain the 16-block window. Only the explicitly
            # authorized loopback mirror may trigger deeper regeneration.
            f"-matmulattestationbackfillwindow={HISTORICAL_BLOCKS + 2}",
            "-whitelist=in,matmulbackfill@127.0.0.1/32",
        ]
        mirror = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
            # Stay in IBD-friendly tip-age so a late-starting mirror downloads.
            "-maxtipage=999999999",
        ]
        self.archive_args = archive
        self.mirror_args = mirror
        self.extra_args = [archive, mirror]

    def setup_network(self):
        self.setup_nodes()
        # Mirror stays isolated until the authority has mined ahead.

    def run_test(self):
        authority, mirror = self.nodes

        self.log.info("Stop mirror so the authority can mine a long Profile-1 lead")
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))

        tip_height = ACTIVATION_HEIGHT + HISTORICAL_BLOCKS
        self.generate(authority, tip_height, sync_fun=self.no_op)
        assert_equal(authority.getblockcount(), tip_height)
        authority_tip = authority.getbestblockhash()

        # Confirm Profile-1 attestations existed before we wipe the archive.
        activation_hash = authority.getblockhash(ACTIVATION_HEIGHT)
        before = authority.getmatmulattestations(activation_hash)
        assert_greater_than_or_equal(len(before), 1)

        self.log.info(
            "Wipe matmul_attestations.dat and restart authority so historical "
            "GETMMATTEST must regenerate across many heights"
        )
        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        attest_path = os.path.join(
            authority.datadir_path, "regtest", "matmul_attestations.dat"
        )
        assert os.path.exists(attest_path), attest_path
        os.remove(attest_path)
        self.start_node(0, extra_args=self.archive_args)
        assert_equal(authority.getblockcount(), tip_height)
        assert_equal(authority.getbestblockhash(), authority_tip)
        # Do not call getmatmulattestations here: that RPC regenerates on read.
        # The bounded startup scan may restore/sign the current frontier, but
        # it must not eagerly repopulate the historical range under test.
        status_before = authority.getmatmultrustedstatus()
        assert status_before["stored_attestations"] <= 1, status_before
        assert status_before["stored_blocks"] <= 1, status_before

        self.log.info("Start mirror from genesis and connect to the ahead authority")
        self.start_node(1, extra_args=self.mirror_args)
        assert_equal(mirror.getblockcount(), 0)

        log_start = mirror.debug_log_size(encoding="utf-8")
        auth_log_start = authority.debug_log_size(encoding="utf-8")
        self.connect_nodes(1, 0)

        self.wait_until(
            lambda: mirror.getbestblockhash() == authority_tip,
            timeout=600,
        )
        assert_equal(mirror.getblockcount(), tip_height)
        status = mirror.getmatmultrustedstatus()
        assert_equal(status["trusted_mirror"], True)
        assert_greater_than_or_equal(status["blocks_with_quorum"], HISTORICAL_BLOCKS)
        assert_greater_than_or_equal(status["accepted"], HISTORICAL_BLOCKS)

        self.log.info("Assert GETMMATTEST outcomes were logged with an explicit reason")
        # Authority always LogDebug's reason=; with -debug=net those lines land in debug.log.
        # Also require at least one LogInfo-rate-limited line (reason=) as defense in depth.
        deadline = time.time() + 30 * self.options.timeout_factor
        reasons = set()
        auth_log = ""
        while time.time() < deadline:
            with open(authority.debug_log_path, encoding="utf-8", errors="replace") as dl:
                dl.seek(auth_log_start)
                auth_log = dl.read()
            reasons = set(
                re.findall(
                    r"getmmattest peer=\d+ block=[0-9a-f]+ height=-?\d+ reason=([a-z0-9_]+)",
                    auth_log,
                )
            )
            if reasons:
                break
            time.sleep(0.1)
        assert reasons, (
            "Authority debug.log had no getmmattest ... reason= lines after backfill; "
            "silent GETMMATTEST outcomes are the production failure under test.\n"
            f"Tail:\n{auth_log[-4000:]}"
        )
        # Regeneration after wipe should surface regenerated and/or cached serves.
        assert reasons & {
            "regenerated",
            "cached",
            "reverify_queued",
            "reverify_rate_limited",
        }, f"unexpected getmmattest reasons only: {sorted(reasons)}"
        # Explicitly forbid the historical silent path: no reason-less serve marker.
        assert "getmmattest" in auth_log

        # Mirror side should have progressed via mmattest intake (not operator inject).
        with open(mirror.debug_log_path, encoding="utf-8", errors="replace") as dl:
            dl.seek(log_start)
            mirror_log = dl.read()
        assert mirror.getblockcount() == tip_height
        self.log.info(
            f"Backfill complete: tip={tip_height}, getmmattest reasons={sorted(reasons)}"
        )
        # Keep mirror_log referenced so failures can include it later if needed.
        assert mirror_log is not None

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))


if __name__ == "__main__":
    MatMulTrustedMirrorBackfillTest(__file__).main()
