#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""P2P attested UTXO snapshot: non-blocking export hold, quorum-before-body, re-serve."""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647


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


class AttestedUtxoSnapshotP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        _, other_pub = generate_keypair(wif=True)
        self.signer_wif = signer_wif
        self.signer_pub = signer_pub.hex()
        self.other_pub = other_pub.hex()
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
        ]
        archive = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        mirror = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
        ]
        strict_mirror = [
            arg for arg in mirror
            if not arg.startswith("-matmultrustedthreshold=")
            and not arg.startswith("-matmultrustedpubkey=")
        ] + [
            f"-matmultrustedpubkey={self.signer_pub}",
            f"-matmultrustedpubkey={self.other_pub}",
            "-matmultrustedthreshold=2",
            "-matmultrustedwaitms=1000",
        ]
        self.mirror_args = mirror
        self.extra_args = [archive, mirror, strict_mirror]

    def setup_network(self):
        self.setup_nodes()
        # Keep the threshold-2 mirror isolated during mining; it would stall
        # waiting for a second ExactReplay attestation.
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[:2])

    def run_test(self):
        archive, mirror_a, mirror_strict = self.nodes
        self.generate(archive, ACTIVATION_HEIGHT + 5, sync_fun=lambda: self.sync_all(self.nodes[:2]))

        self.log.info("Non-blocking attested export reports cs_main hold")
        dump = archive.dumptxoutsetattested("utxo.dat", "utxo.manifest")
        assert_greater_than(dump["coins_written"], 0)
        assert "max_cs_main_hold_us" in dump
        assert "flush_cs_main_hold_us" in dump
        assert "shielded_cs_main_hold_us" in dump
        assert dump["max_cs_main_hold_us"] < 60_000_000
        assert_equal(dump["signatures"], 1)

        self.log.info("Offer from signer; CPU mirror fetches (quorum-before-body)")
        # Transfer geometry is signed into the v2 manifest so a server cannot
        # amplify requests or disk allocation after quorum verification.
        offer = archive.offerattestedutxosnapshot("utxo.dat", "utxo.manifest", 1 << 20)
        assert_greater_than(offer["chunk_count"], 0)
        assert "ATTESTED_UTXO_SNAPSHOT" in archive.getnetworkinfo()["localservicesnames"]

        # Service bits are fixed at VERSION time; reconnect so the mirror sees
        # NODE_ATTESTED_UTXO_SNAPSHOT.
        self.disconnect_nodes(0, 1)
        self.connect_nodes(0, 1)
        self.wait_until(lambda: any(
            "ATTESTED_UTXO_SNAPSHOT" in (p.get("servicesnames") or [])
            for p in mirror_a.getpeerinfo()
        ))

        fetched = mirror_a.fetchattestedutxosnapshot(
            "fetched.dat", "fetched.manifest", dump["base_hash"], -1, 60000
        )
        assert_equal(fetched["block_hash"], dump["base_hash"])
        assert_equal(fetched["chunks_received"], offer["chunk_count"])
        assert_equal(fetched["signatures"], 1)

        src = os.path.join(archive.datadir_path, "regtest", "utxo.dat")
        dst = os.path.join(mirror_a.datadir_path, "regtest", "fetched.dat")
        assert_equal(os.path.getsize(src), os.path.getsize(dst))

        self.log.info("Insufficient quorum rejects before body download")
        self.connect_nodes(2, 0)
        # Fresh connection after the offer is already active.
        self.wait_until(lambda: any(
            "ATTESTED_UTXO_SNAPSHOT" in (p.get("servicesnames") or [])
            for p in mirror_strict.getpeerinfo()
        ))
        assert_raises_rpc_error(
            -8,
            "Remote manifest rejected before body download",
            mirror_strict.fetchattestedutxosnapshot,
            "nope.dat",
            "nope.manifest",
            dump["base_hash"],
            -1,
            60000,
        )
        nope = os.path.join(mirror_strict.datadir_path, "regtest", "nope.dat")
        assert not os.path.exists(nope)

        self.log.info("Non-signer CPU mirror re-serves the snapshot")
        archive.withdrawattestedutxosnapshot()
        reoffer = mirror_a.offerattestedutxosnapshot(
            "fetched.dat", "fetched.manifest", 1 << 20
        )
        assert_equal(reoffer["block_hash"], dump["base_hash"])

        # Restart node 2 as a normal threshold-1 mirror to accept re-serve.
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(2))
        self.start_node(2, extra_args=self.mirror_args)
        self.connect_nodes(2, 1)
        self.wait_until(lambda: any(
            "ATTESTED_UTXO_SNAPSHOT" in (p.get("servicesnames") or [])
            for p in self.nodes[2].getpeerinfo()
        ))
        fetched_b = self.nodes[2].fetchattestedutxosnapshot(
            "from_mirror.dat", "from_mirror.manifest", "", -1, 60000
        )
        assert_equal(fetched_b["block_hash"], dump["base_hash"])

        mirror_a.withdrawattestedutxosnapshot()

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))


if __name__ == "__main__":
    AttestedUtxoSnapshotP2PTest(__file__).main()
