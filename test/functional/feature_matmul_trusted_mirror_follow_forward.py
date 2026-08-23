#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Trusted mirror follow-forward after attested UTXO snapshot.

Production stall (jarekpiot): loadtxoutsetattested at H, signer-attested
headers already known through H+N, bodies missing, lowest_missing logged
with select=root_async_pending and in_flight=0. The mirror stayed at the
snapshot tip instead of requesting the followed-chain bodies, and a
competing most-work headers-only tree must not be fetched or activated.

This test:
  - dumps an attested snapshot at height H on the signer archive
  - gives the trusted mirror headers H+1..H+N (no bodies) plus a heavier
    unattested competing headers-only fork from H
  - loads the snapshot with loadtxoutsetattested
  - restarts the mirror and checks the snapshot chainstate survives
  - reconnects over P2P only (no getblockfrompeer / invalidateblock /
    reconsiderblock / preciousblock)
  - requires automatic connect through H+N
  - requires the competing suffix to stay headers-only

CheckBlockIndex stays on (-checkblockindex=1). Do not disable it.
"""

import shutil

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
FORWARD_COUNT = 8
COMPETING_COUNT = 16
assert COMPETING_COUNT > FORWARD_COUNT
assert SNAPSHOT_HEIGHT > ACTIVATION_HEIGHT

# NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31 (src/protocol.h).
NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
ARCHIVE_SERVICES = (
    NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE
)

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


def collect_hashes(node, tip_hash, stop_hash):
    """Hashes from stop_hash (exclusive) to tip_hash (inclusive), low to high."""
    hashes = []
    blockhash = tip_hash
    while blockhash != stop_hash:
        hashes.append(blockhash)
        header = node.getblockheader(blockhash, True)
        if "previousblockhash" not in header:
            break
        blockhash = header["previousblockhash"]
    hashes.reverse()
    return hashes


def body_available(node, blockhash):
    try:
        node.getblock(blockhash, False)
        return True
    except JSONRPCException:
        return False


class MatMulTrustedMirrorFollowForwardTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
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
        # Consensus miner without a signer: competing bodies have no quorum.
        competitor = common + [
            "-matmulvalidation=consensus",
            "-matmulattestationserve=0",
        ]
        self.archive_args = archive
        self.mirror_args = mirror
        # node0=authority, node1=mirror, node2=competing miner
        self.extra_args = [archive, mirror, competitor]

    def setup_network(self):
        self.setup_nodes()
        # Connect later so the mirror stays headers-only until follow-forward.

    def _disconnect_all(self):
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                try:
                    self.disconnect_nodes(i, j)
                except Exception:
                    pass

    def _push_headers(self, dest, hashes, src, *, services, with_attestations):
        """Deliver headers (and optional ExactReplay attestations) without bodies.

        When attesting, prove authority with a signer-valid mmattest before
        announcing the complete branch on the same connection. Replay the
        attestations once their headers are indexed — the same pattern as
        feature_matmul_trusted_mirror_convergence.
        """
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

        # Match the exact stop hash in the MMATTEST-triggered GETHEADERS
        # request. A mid-branch proof must not authorize a longer batch.
        proof_pos = len(hashes) - 1
        proof_atts = src.getmatmulattestations(hashes[proof_pos])
        assert_greater_than_or_equal(len(proof_atts), 1)
        peer.send_and_ping(
            msg_generic(
                b"mmattest",
                ser_compact_size(len(proof_atts))
                + b"".join(bytes.fromhex(att) for att in proof_atts),
            )
        )
        peer.send_and_ping(msg_headers(headers=headers))
        remaining = []
        for blockhash in hashes:
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
        # Active chainstate is last (most work) and must remain the snapshot.
        assert_equal(states[-1].get("snapshot_blockhash"), base_hash)
        info = mirror.getblockchaininfo()
        assert_equal(info["blocks"], blocks)
        assert_equal(info["bestblockhash"], tip_hash)

    def run_test(self):
        authority, mirror, competitor = self.nodes

        self.log.info("Mine shared prefix through snapshot height H")
        self.connect_nodes(0, 2)
        self.generate(authority, SNAPSHOT_HEIGHT, sync_fun=self.no_op)
        self.wait_until(
            lambda: competitor.getbestblockhash() == authority.getbestblockhash(),
            timeout=300,
        )
        assert_equal(authority.getblockcount(), SNAPSHOT_HEIGHT)
        snapshot_hash = authority.getbestblockhash()
        genesis_hash = authority.getblockhash(0)

        self.log.info("Dump attested UTXO snapshot at H")
        dump = authority.dumptxoutsetattested("utxo.dat", "utxo.manifest")
        assert_equal(dump["base_height"], SNAPSHOT_HEIGHT)
        assert_equal(dump["base_hash"], snapshot_hash)
        assert_greater_than(dump["coins_written"], 0)
        assert_equal(dump["signatures"], 1)

        self.log.info(
            f"Partition: authority mines H+1..H+{FORWARD_COUNT}; "
            f"competitor mines a heavier unattested fork from H"
        )
        self._disconnect_all()
        self.generate(authority, FORWARD_COUNT, sync_fun=self.no_op)
        self.generate(competitor, COMPETING_COUNT, sync_fun=self.no_op)
        authority_tip = authority.getbestblockhash()
        authority_height = authority.getblockcount()
        competing_tip = competitor.getbestblockhash()
        competing_height = competitor.getblockcount()
        assert_equal(authority_height, SNAPSHOT_HEIGHT + FORWARD_COUNT)
        assert_equal(competing_height, SNAPSHOT_HEIGHT + COMPETING_COUNT)
        assert_greater_than(competing_height, authority_height)
        assert authority_tip != competing_tip
        assert_equal(
            authority.getblockheader(authority.getblockhash(SNAPSHOT_HEIGHT + 1))[
                "previousblockhash"
            ],
            snapshot_hash,
        )
        assert_equal(
            competitor.getblockheader(competitor.getblockhash(SNAPSHOT_HEIGHT + 1))[
                "previousblockhash"
            ],
            snapshot_hash,
        )

        followed_hashes = collect_hashes(authority, authority_tip, genesis_hash)
        competing_suffix = collect_hashes(competitor, competing_tip, snapshot_hash)
        assert_equal(len(competing_suffix), COMPETING_COUNT)
        missing_followed = followed_hashes[SNAPSHOT_HEIGHT:]
        assert_equal(len(missing_followed), FORWARD_COUNT)

        self.log.info("Mirror (genesis): accept attested headers through H+N")
        assert_equal(mirror.getblockcount(), 0)
        self._push_headers(
            mirror,
            followed_hashes,
            authority,
            services=ARCHIVE_SERVICES,
            with_attestations=True,
        )
        self.wait_until(
            lambda: mirror.getblockchaininfo()["headers"] >= authority_height
            and any(t["hash"] == authority_tip for t in mirror.getchaintips()),
            timeout=180,
        )
        tips = {t["hash"]: t for t in mirror.getchaintips()}
        assert authority_tip in tips
        assert competing_tip not in tips
        info = mirror.getblockchaininfo()
        # The followed H+N headers remain known and no body has arrived. The
        # heavier unattested fork stays isolated until the explicit outbound
        # connection after snapshot activation.
        assert_greater_than_or_equal(info["headers"], authority_height)
        assert_equal(info["blocks"], 0)
        for blockhash in missing_followed:
            mirror.getblockheader(blockhash)
            assert not body_available(mirror, blockhash), blockhash
        for blockhash in competing_suffix:
            try:
                mirror.getblockheader(blockhash)
            except JSONRPCException:
                pass
            else:
                raise AssertionError(f"indexed unattested inbound header {blockhash}")
            assert not body_available(mirror, blockhash), blockhash

        self.log.info("loadtxoutsetattested at H while H+1..H+N are header-known")
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
        post = mirror.getblockchaininfo()
        assert_greater_than_or_equal(post["headers"], authority_height)
        assert_greater_than(post["headers"], post["blocks"])
        for blockhash in missing_followed:
            assert not body_available(mirror, blockhash), blockhash

        self.log.info("Restart mirror: snapshot chainstate and headers must survive")
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.start_node(1, extra_args=self.mirror_args)
        mirror = self.nodes[1]
        self._assert_snapshot_chainstate(
            mirror, snapshot_hash, blocks=SNAPSHOT_HEIGHT, tip_hash=snapshot_hash
        )
        restarted = mirror.getblockchaininfo()
        # Snapshot chainstate is the tip. Headers above H may rewind to the
        # authenticated snapshot frontier across restart; reconnect re-syncs.
        assert_greater_than_or_equal(restarted["headers"], SNAPSHOT_HEIGHT)
        assert_equal(restarted["blocks"], SNAPSHOT_HEIGHT)
        for blockhash in missing_followed:
            try:
                mirror.getblockheader(blockhash)
            except JSONRPCException:
                continue
            assert not body_available(mirror, blockhash), blockhash
        for blockhash in competing_suffix:
            try:
                mirror.getblockheader(blockhash)
            except JSONRPCException:
                continue
            assert not body_available(mirror, blockhash), blockhash

        self.log.info(
            "Reconnect mirror→authority and mirror→competitor; follow-forward "
            "must request H+1..H+N with no operator RPC"
        )
        # From here the test only uses read-only RPCs plus P2P connect.
        self.connect_nodes(1, 0)
        self.connect_nodes(1, 2)
        self.wait_until(
            lambda: mirror.getbestblockhash() == authority_tip,
            timeout=300,
        )
        final = mirror.getblockchaininfo()
        assert_equal(final["bestblockhash"], authority_tip)
        assert_equal(final["blocks"], authority_height)
        assert_equal(mirror.getblockcount(), authority_height)
        for blockhash in missing_followed:
            assert body_available(mirror, blockhash), blockhash

        self.log.info("Competing most-work suffix must stay headers-only")
        for blockhash in competing_suffix:
            assert not body_available(mirror, blockhash), (
                f"downloaded competing body {blockhash}"
            )
        tips = {t["hash"]: t for t in mirror.getchaintips()}
        if competing_tip in tips:
            assert_equal(tips[competing_tip]["status"], "headers-only")
        assert_equal(tips[authority_tip]["status"], "active")
        assert mirror.getbestblockhash() != competing_tip

        status = mirror.getmatmultrustedstatus()
        assert_equal(status["trusted_mirror"], True)
        assert_greater_than_or_equal(status["accepted"], 1)
        # Restart already proved the snapshot chainstate survived. After
        # follow-forward the active tip is H+N; background validation of
        # genesis→H may have completed and dropped the snapshot tag.
        states = mirror.getchainstates()["chainstates"]
        assert_equal(states[-1]["bestblockhash"], authority_tip)
        assert_equal(states[-1]["blocks"], authority_height)
        if len(states) > 1:
            assert_equal(states[-1].get("snapshot_blockhash"), snapshot_hash)

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(2)


if __name__ == "__main__":
    MatMulTrustedMirrorFollowForwardTest(__file__).main()
