#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Trusted mirror snapshot background backfill without unbounded re-getdata.

Production residual after 8e8b857d (jarekpiot): loadtxoutsetattested at H left
pre-snapshot bodies missing. Background genesis→H backfill delivered those
bodies, but HEADER_ONLY admission discarded them, so FindNextBlocks /
TryDownloadingHistoricalBlocks re-requested the same hashes 150–301 times
(heights 2–5 in the live report) while the tip still needed to follow
signer-attested forward blocks.

This test:
  - dumps an attested snapshot at height H on the signer archive
  - wipes the trusted mirror to a clean datadir and loads the snapshot so the
    tip is H with no pre-snapshot bodies
  - reconnects over P2P and requires bounded getdata for each pre-snapshot hash
  - requires the attested frontier to advance while backfill is still running
  - does not require a competing unattested fork (follow_forward covers that)

CheckBlockIndex stays on (-checkblockindex=1). Do not disable it.
"""

import collections
import re
import shutil
from shutil import rmtree

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.authproxy import JSONRPCException
from test_framework.wallet_util import generate_keypair
from test_framework.messages import (
    CBlockHeader,
    NODE_MATMUL_CONSENSUS,
    NODE_NETWORK,
    NODE_WITNESS,
    from_hex,
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

# NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31 (src/protocol.h).
NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
ARCHIVE_SERVICES = (
    NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE
)

# Live bug: 150–301 requests per hash. Bound must stay well below that.
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

# net_processing.cpp variants (historical backfill uses the third form):
#   "Requesting block %s from peer=%d"
#   "Requesting block %s from  peer=%d"
#   "Requesting block %s (%d) peer=%d"
REQUESTING_BLOCK_RE = re.compile(r"Requesting block ([0-9a-f]{64})")


def body_available(node, blockhash):
    try:
        node.getblock(blockhash, False)
        return True
    except JSONRPCException:
        return False


class MatMulTrustedMirrorSnapshotBackfillTest(BitcoinTestFramework):
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
            # Required: header-known / body-missing after snapshot must not
            # abort CheckBlockIndex. Never disable this to make the suite green.
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
        """Deliver headers (and optional ExactReplay attestations) without bodies."""
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
        assert_equal(states[-1].get("snapshot_blockhash"), base_hash)
        info = mirror.getblockchaininfo()
        assert_equal(info["blocks"], blocks)
        assert_equal(info["bestblockhash"], tip_hash)

    def _pre_snapshot_hashes(self, archive):
        """Hashes at heights 2..SNAPSHOT_HEIGHT-1 (the live re-getdata window)."""
        return [
            archive.getblockhash(h) for h in range(2, SNAPSHOT_HEIGHT)
        ]

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
        assert_equal(archive.getblockcount(), SNAPSHOT_HEIGHT)
        assert_equal(mirror.getblockcount(), SNAPSHOT_HEIGHT)
        snapshot_hash = archive.getbestblockhash()
        pre_snapshot_hashes = self._pre_snapshot_hashes(archive)
        assert_equal(len(pre_snapshot_hashes), SNAPSHOT_HEIGHT - 2)
        header_hashes = [
            archive.getblockhash(h) for h in range(1, SNAPSHOT_HEIGHT + 1)
        ]

        self.log.info("Dump attested UTXO snapshot at H")
        dump = archive.dumptxoutsetattested("utxo.dat", "utxo.manifest")
        assert_equal(dump["base_height"], SNAPSHOT_HEIGHT)
        assert_equal(dump["base_hash"], snapshot_hash)
        assert_greater_than(dump["coins_written"], 0)
        assert_equal(dump["signatures"], 1)

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

        self.log.info("Feed headers through H (no bodies) so loadtxoutsetattested can see the base")
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
        assert_equal(mirror.getblockcount(), 0)
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
        assert_equal(loaded["tip_hash"], snapshot_hash)
        self._assert_snapshot_chainstate(
            mirror, snapshot_hash, blocks=SNAPSHOT_HEIGHT, tip_hash=snapshot_hash
        )
        for blockhash in pre_snapshot_hashes:
            assert not body_available(mirror, blockhash), blockhash

        self.log.info(
            "Reconnect mirror→archive; backfill bodies while tip follows forward"
        )
        log_start = mirror.debug_log_size(encoding="utf-8")
        before_frontier = mirror.getmatmulattestedtip().get("signed_frontier", {})
        before_height = before_frontier.get("height", SNAPSHOT_HEIGHT)

        self.connect_nodes(1, 0)

        # Generate promptly so tip follow-forward overlaps background backfill.
        self.generate(archive, 2, sync_fun=self.no_op)
        archive_tip = archive.getbestblockhash()
        archive_height = archive.getblockcount()
        assert_equal(archive_height, SNAPSHOT_HEIGHT + 2)

        def read_request_counts():
            with open(mirror.debug_log_path, encoding="utf-8", errors="replace") as dl:
                dl.seek(log_start)
                return self._count_requesting_block(dl.read(), pre_snapshot_hashes)

        def assert_requests_bounded(counts, *, require_seen=False):
            for blockhash in pre_snapshot_hashes:
                n = counts.get(blockhash, 0)
                if require_seen:
                    assert_greater_than_or_equal(n, 1)
                assert n < MAX_REQUESTS_PER_HASH, (
                    f"pre-snapshot {blockhash} requested {n} times "
                    f"(limit {MAX_REQUESTS_PER_HASH}); unbounded HEADER_ONLY re-getdata"
                )

        def tip_and_frontier_caught_up():
            # Fail fast if the HEADER_ONLY re-getdata loop is already unbounded;
            # otherwise msghand floods debug.log and RPC stops answering.
            assert_requests_bounded(read_request_counts())
            if mirror.getblockcount() < SNAPSHOT_HEIGHT:
                return False
            attested = mirror.getmatmulattestedtip()
            frontier = attested.get("signed_frontier")
            if not frontier:
                return False
            return (
                frontier["height"] >= before_height + 2
                and frontier["on_active_chain"] is True
                and frontier["blocks_behind"] == 0
                and mirror.getbestblockhash() == archive_tip
            )

        self.wait_until(tip_and_frontier_caught_up, timeout=300)
        assert_greater_than_or_equal(mirror.getblockcount(), SNAPSHOT_HEIGHT)
        final_frontier = mirror.getmatmulattestedtip()["signed_frontier"]
        assert_equal(final_frontier["on_active_chain"], True)
        assert_equal(final_frontier["blocks_behind"], 0)
        assert_greater_than_or_equal(final_frontier["height"], before_height + 2)
        assert_equal(mirror.getblockcount(), archive_height)
        assert_equal(mirror.getbestblockhash(), archive_tip)

        def backfill_done():
            assert_requests_bounded(read_request_counts())
            if all(body_available(mirror, h) for h in pre_snapshot_hashes):
                return True
            states = mirror.getchainstates()["chainstates"]
            if len(states) == 1:
                return True
            info = mirror.getblockchaininfo()
            snap = info.get("snapshot_sync") or {}
            if snap.get("active") and not snap.get("background_validation_in_progress"):
                return True
            return False

        self.wait_until(backfill_done, timeout=300)
        for blockhash in pre_snapshot_hashes:
            assert body_available(mirror, blockhash), blockhash
        assert_greater_than_or_equal(mirror.getblockcount(), SNAPSHOT_HEIGHT)

        self.log.info(
            "Each pre-snapshot hash must be Requesting-block'd fewer than "
            f"{MAX_REQUESTS_PER_HASH} times (bug was 150–301)"
        )
        counts = read_request_counts()
        assert_requests_bounded(counts, require_seen=True)
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
    MatMulTrustedMirrorSnapshotBackfillTest(__file__).main()
