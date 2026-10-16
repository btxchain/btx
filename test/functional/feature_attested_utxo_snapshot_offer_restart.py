#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Attested UTXO snapshot offer across restarts.

An offerattestedutxosnapshot RPC offer is held in memory, so it is gone after
a restart. -offerattestedutxosnapshot / -offerattestedutxosnapshotmanifest
re-offer the files at startup with the same checks as the RPC, and a bad
configuration only costs the offer, not the node.
"""

import hashlib
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
OFFER_WARNING = (
    "Warning: Not offering the attested UTXO snapshot from "
    "-offerattestedutxosnapshot: {}"
)
SERVICE = "ATTESTED_UTXO_SNAPSHOT"


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class AttestedUtxoSnapshotOfferRestartTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
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
            f"-matmultrustedpubkey={signer_pub.hex()}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
            "-modelnet=0",
        ]
        self.archive_args = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        self.mirror_args = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
        ]
        self.extra_args = [self.archive_args, self.mirror_args]

    def setup_network(self):
        self.setup_nodes()
        # The mirror dials the archive, as a real mirror would.
        self.connect_nodes(1, 0)
        self.sync_all()

    def offering(self, node):
        return SERVICE in node.getnetworkinfo()["localservicesnames"]

    def restart_archive(self, extra, warning=None):
        """Restart node 0 with extra args; warning = the offer warning it should print."""
        self.stop_node(0, expected_stderr=self.archive_stderr)
        self.start_node(0, extra_args=self.archive_args + extra)
        self.archive_stderr = INLINE_SIGNER_WARNING
        if warning is not None:
            self.archive_stderr += "\n" + OFFER_WARNING.format(warning)

    def reconnect_mirror(self):
        mirror = self.nodes[1]
        for peer in mirror.getpeerinfo():
            mirror.disconnectnode(nodeid=peer["id"])
        self.wait_until(lambda: len(mirror.getpeerinfo()) == 0)
        self.connect_nodes(1, 0)
        self.wait_until(lambda: len(mirror.getpeerinfo()) == 1)

    def fetch(self, name, base_hash):
        mirror = self.nodes[1]
        self.wait_until(lambda: any(
            SERVICE in (p.get("servicesnames") or []) for p in mirror.getpeerinfo()
        ))
        got = mirror.fetchattestedutxosnapshot(
            f"{name}.dat", f"{name}.manifest", base_hash, -1, 60000
        )
        assert_equal(got["block_hash"], base_hash)
        return got, os.path.join(mirror.datadir_path, "regtest", f"{name}.dat")

    def run_test(self):
        archive, mirror = self.nodes
        self.archive_stderr = INLINE_SIGNER_WARNING
        self.generate(archive, ACTIVATION_HEIGHT + 5)

        dump = archive.dumptxoutsetattested("utxo.dat", "utxo.manifest")
        assert_equal(dump["signatures"], 1)
        src_sha = sha256_file(dump["path"])
        option = [
            "-offerattestedutxosnapshot=utxo.dat",
            "-offerattestedutxosnapshotmanifest=utxo.manifest",
        ]

        self.log.info("An RPC offer does not survive a restart")
        offer = archive.offerattestedutxosnapshot("utxo.dat", "utxo.manifest")
        assert_greater_than(offer["chunk_count"], 0)
        assert self.offering(archive)
        self.restart_archive([])
        assert not self.offering(archive)
        self.reconnect_mirror()
        assert_raises_rpc_error(
            -29, "No connected peer advertises NODE_ATTESTED_UTXO_SNAPSHOT",
            mirror.fetchattestedutxosnapshot,
            "lost.dat", "lost.manifest", dump["base_hash"], -1, 5000,
        )

        self.log.info("The startup option offers the files before the first connection")
        with archive.assert_debug_log([
            "Offering attested UTXO snapshot from -offerattestedutxosnapshot: "
            f"height={dump['base_height']} block={dump['base_hash']}"
        ]):
            self.restart_archive(option)
        archive = self.nodes[0]
        assert self.offering(archive)
        self.reconnect_mirror()
        got, path = self.fetch("after_restart1", dump["base_hash"])
        assert_equal(got["chunks_received"], offer["chunk_count"])
        assert_equal(got["signatures"], 1)
        assert_equal(sha256_file(path), src_sha)

        self.log.info("... and again after a second restart")
        self.restart_archive(option)
        assert self.offering(self.nodes[0])
        self.reconnect_mirror()
        _, path = self.fetch("after_restart2", dump["base_hash"])
        assert_equal(sha256_file(path), src_sha)

        self.log.info("withdraw still works at runtime; the option re-offers on the next start")
        self.nodes[0].withdrawattestedutxosnapshot()
        assert not self.offering(self.nodes[0])
        self.restart_archive(option)
        assert self.offering(self.nodes[0])

        self.log.info("A bad configuration skips the offer, warns, and the node still runs")
        self.restart_archive(
            ["-offerattestedutxosnapshot=utxo.dat"],
            warning="set both -offerattestedutxosnapshot and "
                    "-offerattestedutxosnapshotmanifest",
        )
        assert not self.offering(self.nodes[0])
        assert_equal(self.nodes[0].getblockcount(), dump["base_height"])
        self.restart_archive(
            ["-offerattestedutxosnapshot=utxo.dat",
             "-offerattestedutxosnapshotmanifest=missing.manifest"],
            warning="Couldn't open manifest file",
        )
        assert not self.offering(self.nodes[0])
        assert_equal(self.nodes[0].getblockcount(), dump["base_height"])

        self.log.info("A body that does not match the signed manifest is refused at startup too")
        datadir = os.path.join(self.nodes[0].datadir_path, "regtest")
        with open(os.path.join(datadir, "utxo.dat"), "rb") as f:
            body = bytearray(f.read())
        body[-1] ^= 0x01
        with open(os.path.join(datadir, "tampered.dat"), "wb") as f:
            f.write(body)
        self.restart_archive(
            ["-offerattestedutxosnapshot=tampered.dat",
             "-offerattestedutxosnapshotmanifest=utxo.manifest"],
            warning="Snapshot body or requested chunk geometry does not match "
                    "signed manifest",
        )
        assert not self.offering(self.nodes[0])
        assert_equal(self.nodes[0].getblockcount(), dump["base_height"])

        self.stop_node(0, expected_stderr=self.archive_stderr)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))


if __name__ == "__main__":
    AttestedUtxoSnapshotOfferRestartTest(__file__).main()
