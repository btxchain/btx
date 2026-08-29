#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""Unrequested followed-chain bodies persist; competing forks stay anti-DoS.

Residual after 1eb8caf3: AcceptBlock's unrequested less-work / height /
min-chainwork / nTx gates dropped a delivered followed-chain body after the
header (HEADER_ONLY). FindNextBlocks then getdata'd the same hash; compact/
inbound delivery was still unrequested relative to that path, so the body
never reached BLOCK_HAVE_DATA.

Invariant: persist HAVE_DATA, or put the hash in the followed skip-fetch
set until the active tip moves. True anti-DoS (less-work competing junk)
must remain getdata-eligible (p2p_unrequested_blocks.py).

This test:
  - loads an attested snapshot so pre-snapshot hashes are followed holes
    (ancestors of the snapshot tip) with no HAVE_DATA
  - pushes those bodies unrequested from an outbound archive and requires
    HAVE_DATA (unsolicited inbound bodies remain authority-only)
  - pushes an unrequested low-work competing fork and requires it is NOT
    persisted
  - reconnects to the archive and requires <20 Requesting-block log lines
    per pre-snapshot hash (live bug was 150–301)

CheckBlockIndex stays on. p2p_unrequested_blocks.py covers generic Bitcoin
Core unrequested anti-DoS; this file is the followed-chain exception.
"""

import collections
import re
import shutil
import time
from shutil import rmtree

from test_framework.blocktools import create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.authproxy import JSONRPCException
from test_framework.wallet_util import generate_keypair
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    NODE_MATMUL_CONSENSUS,
    NODE_NETWORK,
    NODE_WITNESS,
    from_hex,
    msg_block,
    msg_generic,
    msg_headers,
    ser_compact_size,
)
from test_framework.p2p import P2PInterface


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
SNAPSHOT_HEIGHT = ACTIVATION_HEIGHT + 4
assert SNAPSHOT_HEIGHT > ACTIVATION_HEIGHT
assert SNAPSHOT_HEIGHT == 10

NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
ARCHIVE_SERVICES = (
    NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE
)

MAX_REQUESTS_PER_HASH = 20

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

REQUESTING_BLOCK_RE = re.compile(
    r"Requesting block ([0-9a-f]{64})(?: \(\d+\))? from\s+peer=\d+"
)


def body_available(node, blockhash):
    try:
        node.getblock(blockhash, False)
        return True
    except JSONRPCException:
        return False


class MatMulUnrequestedFollowedPersistTest(BitcoinTestFramework):
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
            "-checkblockindex=1",
            "-debug=net",
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
        self.archive_args = archive
        self.mirror_args = mirror
        self.extra_args = [archive, mirror]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def _push_headers(self, dest, hashes, src, *, services, with_attestations):
        assert_greater_than(len(hashes), 0)
        headers = [
            from_hex(CBlockHeader(), src.getblockheader(h, False)) for h in hashes
        ]
        peer = dest.add_p2p_connection(P2PInterface(), services=services)
        if not with_attestations:
            peer.send_and_ping(msg_headers(headers=headers))
            peer.peer_disconnect()
            dest.disconnect_p2ps()
            return

        proof_pos = next(
            i
            for i, blockhash in enumerate(hashes)
            if src.getblockheader(blockhash)["height"] >= ACTIVATION_HEIGHT
        )
        peer.send_and_ping(msg_headers(headers=headers[: proof_pos + 1]))
        proof_atts = src.getmatmulattestations(hashes[proof_pos])
        assert_greater_than_or_equal(len(proof_atts), 1)
        peer.send_and_ping(
            msg_generic(
                b"mmattest",
                ser_compact_size(len(proof_atts))
                + b"".join(bytes.fromhex(att) for att in proof_atts),
            )
        )
        if proof_pos + 1 < len(headers):
            peer.send_and_ping(msg_headers(headers=headers[proof_pos + 1 :]))
        remaining = []
        for i, blockhash in enumerate(hashes):
            if i == proof_pos:
                continue
            if src.getblockheader(blockhash)["height"] < ACTIVATION_HEIGHT:
                continue
            atts = src.getmatmulattestations(blockhash)
            assert_greater_than_or_equal(len(atts), 1)
            remaining.extend(bytes.fromhex(att) for att in atts)
        for i in range(0, len(remaining), 16):
            batch = remaining[i : i + 16]
            peer.send_and_ping(
                msg_generic(
                    b"mmattest",
                    ser_compact_size(len(batch)) + b"".join(batch),
                )
            )
        peer.peer_disconnect()
        dest.disconnect_p2ps()

    def _assert_snapshot_chainstate(self, mirror, base_hash, *, blocks, tip_hash):
        states = mirror.getchainstates()["chainstates"]
        snapshots = [s for s in states if s.get("snapshot_blockhash") == base_hash]
        assert_equal(len(snapshots), 1)
        snap = snapshots[0]
        assert_equal(snap["blocks"], blocks)
        assert_equal(snap["bestblockhash"], tip_hash)
        info = mirror.getblockchaininfo()
        assert_equal(info["blocks"], blocks)
        assert_equal(info["bestblockhash"], tip_hash)

    def _pre_snapshot_hashes(self, archive):
        return [archive.getblockhash(h) for h in range(2, SNAPSHOT_HEIGHT)]

    def _count_requesting_block(self, log_text, hashes):
        counts = collections.Counter()
        wanted = set(hashes)
        for match in REQUESTING_BLOCK_RE.finditer(log_text):
            blockhash = match.group(1)
            if blockhash in wanted:
                counts[blockhash] += 1
        return counts

    def run_test(self):
        archive, mirror = self.nodes

        self.log.info("Mine shared prefix through snapshot height H")
        self.generate(archive, SNAPSHOT_HEIGHT, sync_fun=self.no_op)
        self.wait_until(
            lambda: mirror.getbestblockhash() == archive.getbestblockhash(),
            timeout=300,
        )
        snapshot_hash = archive.getbestblockhash()
        pre_snapshot_hashes = self._pre_snapshot_hashes(archive)
        header_hashes = [
            archive.getblockhash(h) for h in range(1, SNAPSHOT_HEIGHT + 1)
        ]

        self.log.info("Dump attested UTXO snapshot at H")
        dump = archive.dumptxoutsetattested("utxo.dat", "utxo.manifest")
        assert_equal(dump["base_height"], SNAPSHOT_HEIGHT)
        assert_equal(dump["base_hash"], snapshot_hash)

        self.log.info("Stop mirror and wipe datadir to a clean chain")
        try:
            self.disconnect_nodes(0, 1)
        except Exception:
            pass
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        rmtree(mirror.chain_path)
        self.start_node(1, extra_args=self.mirror_args)
        mirror = self.nodes[1]
        assert_equal(mirror.getblockcount(), 0)

        self.log.info("Feed headers through H (no bodies)")
        self._push_headers(
            mirror,
            header_hashes,
            archive,
            services=ARCHIVE_SERVICES,
            with_attestations=True,
        )
        self.wait_until(
            lambda: mirror.getblockchaininfo()["headers"] >= SNAPSHOT_HEIGHT
            and any(t["hash"] == snapshot_hash for t in mirror.getchaintips()),
            timeout=180,
        )
        for blockhash in pre_snapshot_hashes:
            mirror.getblockheader(blockhash)
            assert not body_available(mirror, blockhash), blockhash

        self.log.info("loadtxoutsetattested at H with no pre-snapshot bodies")
        dst_dat = mirror.chain_path / "snapshot.dat"
        dst_man = mirror.chain_path / "snapshot.manifest"
        shutil.copyfile(dump["path"], dst_dat)
        shutil.copyfile(dump["manifest_path"], dst_man)
        loaded = mirror.loadtxoutsetattested("snapshot.dat", "snapshot.manifest")
        assert_equal(loaded["base_height"], SNAPSHOT_HEIGHT)
        self._assert_snapshot_chainstate(
            mirror, snapshot_hash, blocks=SNAPSHOT_HEIGHT, tip_hash=snapshot_hash
        )
        for blockhash in pre_snapshot_hashes:
            assert not body_available(mirror, blockhash), blockhash

        self.log.info(
            "Deliver unrequested followed-chain bodies; they must persist HAVE_DATA"
        )
        log_start = mirror.debug_log_size(encoding="utf-8")
        # Recovery downloads come from an archive/mirror connection selected
        # outbound by this node. An inbound P2P fixture is intentionally
        # rejected by the authority-only unsolicited-body gate even when it
        # merely advertises the archive service bit.
        peer = mirror.add_outbound_p2p_connection(
            P2PInterface(),
            p2p_idx=0,
            connection_type="outbound-full-relay",
            services=ARCHIVE_SERVICES,
        )
        for blockhash in pre_snapshot_hashes:
            raw = archive.getblock(blockhash, False)
            block = from_hex(CBlock(), raw)
            peer.send_and_ping(msg_block(block))
            assert body_available(mirror, blockhash), (
                f"unrequested followed-chain body {blockhash} was not persisted"
            )

        self.log.info("Unrequested low-work competing fork must not persist")
        genesis = int("0x" + archive.getblockhash(0), 0)
        competing = create_block(genesis, create_coinbase(1), int(time.time()) + 50)
        competing.solve()
        # The anti-DoS rejection disconnects this outbound source before it can
        # answer a synchronization ping. The disconnect is the expected wire
        # result; verify the body stayed unavailable afterward.
        with mirror.assert_debug_log(
            expected_msgs=["invalid claimed block-header work"]
        ):
            peer.send_message(msg_block(competing))
            peer.wait_for_disconnect()
        assert not body_available(mirror, competing.hash)

        mirror.disconnect_p2ps()

        self.log.info("Reconnect; followed hashes must not unbounded re-getdata")
        self.connect_nodes(1, 0)
        self.generate(archive, 2, sync_fun=self.no_op)
        archive_tip = archive.getbestblockhash()

        def tip_caught_up():
            return mirror.getbestblockhash() == archive_tip

        self.wait_until(tip_caught_up, timeout=300)

        with open(mirror.debug_log_path, encoding="utf-8", errors="replace") as dl:
            dl.seek(log_start)
            mirror_log = dl.read()
        counts = self._count_requesting_block(mirror_log, pre_snapshot_hashes)
        for blockhash in pre_snapshot_hashes:
            n = counts.get(blockhash, 0)
            assert n < MAX_REQUESTS_PER_HASH, (
                f"followed hash {blockhash} requested {n} times "
                f"(limit {MAX_REQUESTS_PER_HASH}); unbounded HEADER_ONLY re-getdata"
            )
            assert body_available(mirror, blockhash), blockhash
        self.log.info(
            "Request counts: "
            + ", ".join(
                f"{h[:12]}…={counts.get(h, 0)}" for h in pre_snapshot_hashes
            )
        )

        assert_equal(mirror.listbanned(), [])
        assert_equal(archive.listbanned(), [])

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))


if __name__ == "__main__":
    MatMulUnrequestedFollowedPersistTest(__file__).main()
