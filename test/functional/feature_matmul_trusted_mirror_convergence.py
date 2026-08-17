#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end: trusted mirror recovers from a same-height race without invalidateblock.

Production failure A (seen on multiple CPU mirrors): after connecting the losing
sibling at height H, getblockchaininfo stayed at headers==blocks==tip while the
attestation authority advanced hundreds of blocks on the winning branch;
outstanding download slots stayed empty until an operator ran invalidateblock.

This functional test drives that topology with real nodes:
  - consensus+signer archive (authority)
  - trusted mirror (real admission / header / download path)
  - second consensus+signer used only to produce the losing sibling
  - non-archive consensus relay that holds winning-branch bodies

Then it asserts the mirror converges to the authority tip with no operator
intervention, within a bounded timeout.

It also guards the download-gate defect: once best-header follows the authority
branch, bodies must be fetchable from the non-archive relay (not only from
IsTrustedMirrorAuthorityPeer). Depending on a single authority connection left
production mirrors stranded with trusted_mirror_not_tip_chain while ordinary
peers held the identical recovery chain.

It also guards the claimed-vs-trust-adjusted download deadlock: a competing
headers-only branch MORE THAN TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS (6) past the
fork has trust-adjusted work capped at fork+6, which can lose to the
authenticated tip — but DOWNLOAD must still use claimed nChainWork so bodies
can arrive and authenticate. A test that only diverges by 1-2 blocks cannot
catch that interaction (production stall was ~193 headers-only ahead).

It also guards the combined production recovery case, rather than testing its
pieces only in isolation: the mirror is exactly PARK_DEPTH blocks down a losing
fork, the authenticated branch is more than 10 headers ahead and more than the
unauthenticated-work allowance past the fork, and the mirror already holds its
higher canonical bodies. Six lower roots remain missing. LastCommon must not
skip past those holes, and receipt of the roots over P2P must automatically
activate the authority branch without invalidateblock, reconsiderblock, a
restart, or any other operator recovery action.

It also guards deep-reorg finality (failure C): a competing rewrite deeper than
EMERGENCY park_depth must still be refused by both authority and mirror.

CheckBlockIndex stays on (-checkblockindex=1; regtest fDefaultConsistencyChecks).
Gate-evicted unattested HAVE_DATA candidates must not abort the mirror. If the
C++ exemption is missing this test fails; do not "fix" that by disabling
consistency checks.
"""

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
# Arm local reorg protection early so the park-depth guard is reachable on regtest.
REORG_PROTECTION_START = 5
PARK_DEPTH = 6
# Must match src/chain.h TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS.
TRUST_ADJUSTED_WORK_ALLOWANCE = 6
# Missing lower roots planted in the LastCommon drag scenario.
MISSING_ROOT_COUNT = 6
# Higher bodies planted above the hole (must be > 0 so LastCommon is tempted).
# Twelve makes the authenticated tip more than ten headers ahead of a mirror
# whose losing branch is exactly PARK_DEPTH blocks long.
HIGHER_BODY_COUNT = 12
# EMERGENCY hysteresis_work_margin is 2; extend the winning branch past that.
AUTHORITY_EXTENSIONS = 4
# NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31 (src/protocol.h). Not exported by
# the python messages module; keep the literal in lockstep with protocol.h.
NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
ARCHIVE_SERVICES = (
    NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE
)
# Small race: mirror tip is the losing sibling (1 block divergent) while the
# winning branch must still clear EMERGENCY hysteresis_work_margin=2
# (required_work = tip_work + 2*proof). Sibling + 2 extensions ⇒ work margin 2.
# Large gap MUST exceed the unauth allowance so trust-adjusted work of the
# headers-only winning branch is capped below what a naive trust-adjusted
# download gate would require — claimed work must still open the fetch.
RELAY_GAP_SMALL = 2
RELAY_GAP_LARGE = 12
assert RELAY_GAP_LARGE > TRUST_ADJUSTED_WORK_ALLOWANCE
assert RELAY_GAP_LARGE > PARK_DEPTH


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


def submit_chain_via_rpc(src, dest, stop_hash=None):
    """Push blocks from src tip back to stop_hash (exclusive) onto dest."""
    blockhash = src.getbestblockhash()
    to_copy = []
    while True:
        if stop_hash is not None and blockhash == stop_hash:
            break
        try:
            dest.getblock(blockhash, False)
            break
        except Exception:
            to_copy.append(blockhash)
            header = src.getblockheader(blockhash, True)
            if "previousblockhash" not in header:
                break
            blockhash = header["previousblockhash"]
    for blockhash in reversed(to_copy):
        raw = src.getblock(blockhash, False)
        result = dest.submitblock(raw)
        assert result in (None, "duplicate", "inconclusive"), (
            f"submitblock({blockhash}) -> {result}"
        )


def submit_attested_chain_via_rpc(src, dest_mirror, stop_hash=None):
    """Push Profile-1 blocks + their ExactReplay attestations onto a trusted mirror.

    submitblock fails closed without an existing quorum; after the first attempt
    the block is known so attestations can be imported, then submitblock retries.
    """
    blockhash = src.getbestblockhash()
    to_copy = []
    while True:
        if stop_hash is not None and blockhash == stop_hash:
            break
        try:
            dest_mirror.getblock(blockhash, False)
            break
        except Exception:
            to_copy.append(blockhash)
            header = src.getblockheader(blockhash, True)
            if "previousblockhash" not in header:
                break
            blockhash = header["previousblockhash"]
    for blockhash in reversed(to_copy):
        raw = src.getblock(blockhash, False)
        atts = src.getmatmulattestations(blockhash)
        assert_greater_than_or_equal(len(atts), 1)
        try:
            dest_mirror.submitblock(raw)
        except JSONRPCException as exc:
            if "quorum" not in str(exc):
                raise
        imported = dest_mirror.submitmatmulattestations(atts)
        assert imported[0]["quorum"] is True
        result = dest_mirror.submitblock(raw)
        assert result in (None, "duplicate", "inconclusive"), (
            f"attested submitblock({blockhash}) -> {result}"
        )


class MatMulTrustedMirrorConvergenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
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
            f"-regtestreorgprotectionstartheight={REORG_PROTECTION_START}",
            "-reorgprotectionprofile=emergency",
            # Keep the profile's PARK action explicit for the finality guard.
            "-parkdeepreorg=1",
            f"-maxreorgdepthpark={PARK_DEPTH}",
            # Required: gate-eviction vs CheckBlockIndex is the defect. Never
            # disable this to make the suite green.
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
        relay = common + [
            "-matmulvalidation=consensus",
            "-matmulattestationserve=0",
        ]
        self.archive_args = archive
        self.mirror_args = mirror
        # node0=authority, node1=mirror, node2=losing-sibling miner (same
        # trusted signer so the mirror can UpdateTip onto that fork),
        # node3=non-archive relay
        self.extra_args = [archive, mirror, archive, relay]

    def setup_network(self):
        self.setup_nodes()
        # Connect later inside the test so partitions are deliberate.

    def _disconnect_all(self):
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                try:
                    self.disconnect_nodes(i, j)
                except Exception:
                    pass

    def _drive_mirror_onto(self, mirror, source, blockhash, *, timeout=180):
        """Make blockhash the mirror tip via P2P, then RPC bodies if needed.

        Losing-race blocks are unattested (loser is not a trusted signer).
        Tip-extending remains eligible for the most-work gate.
        """
        try:
            self.wait_until(
                lambda: mirror.getbestblockhash() == blockhash,
                timeout=min(timeout, 10),
            )
            return
        except AssertionError:
            pass
        submit_chain_via_rpc(source, mirror)
        self.wait_until(
            lambda: mirror.getbestblockhash() == blockhash,
            timeout=timeout,
        )

    def run_test(self):
        authority, mirror, loser, relay = self.nodes

        self.log.info("Bring up shared tip through Profile-1 activation")
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)
        fork_height = ACTIVATION_HEIGHT + 2
        self.generate(authority, fork_height, sync_fun=self.no_op)
        self.wait_until(
            lambda: mirror.getbestblockhash() == authority.getbestblockhash()
            and loser.getbestblockhash() == authority.getbestblockhash()
            and relay.getbestblockhash() == authority.getbestblockhash(),
            timeout=300,
        )
        fork_hash = authority.getbestblockhash()
        assert_equal(mirror.getbestblockhash(), fork_hash)
        assert_equal(loser.getbestblockhash(), fork_hash)
        assert_equal(relay.getbestblockhash(), fork_hash)
        assert_greater_than_or_equal(fork_height, REORG_PROTECTION_START)

        rp = authority.getdifficultyhealth(5)["reorg_protection"]
        assert_equal(rp["profile"], "emergency")
        assert_equal(rp["parking_enabled"], True)
        assert_equal(rp["park_depth"], PARK_DEPTH)
        assert_equal(rp["active"], True)

        self.log.info(
            "Partition: authority mines winning sibling; loser mines losing sibling"
        )
        self._disconnect_all()

        winning = self.generate(authority, 1, sync_fun=self.no_op)[0]
        losing = self.generate(loser, 1, sync_fun=self.no_op)[0]
        assert winning != losing
        assert_equal(authority.getblockcount(), fork_height + 1)
        assert_equal(loser.getblockcount(), fork_height + 1)
        assert_equal(authority.getblockheader(winning)["previousblockhash"], fork_hash)
        assert_equal(loser.getblockheader(losing)["previousblockhash"], fork_hash)

        self.log.info(
            "Authority extends the winning branch past hysteresis; mirror stays at the fork"
        )
        # A 1-block attested losing tip is retained by the most-work gate
        # (active_tip_has_quorum). Production recovery is from an unattested
        # race; this opening scenario follows the attested authority from the
        # shared fork. Later cases still drive an attested losing fork.
        self.generate(authority, AUTHORITY_EXTENSIONS, sync_fun=self.no_op)
        authority_tip = authority.getbestblockhash()
        authority_height = authority.getblockcount()
        assert_greater_than(authority_height, fork_height)
        assert_equal(mirror.getbestblockhash(), fork_hash)
        assert_equal(mirror.getblockcount(), fork_height)

        self.log.info(
            "Reconnect mirror→authority only; must follow-forward without invalidateblock/restart"
        )
        pre = mirror.getblockchaininfo()
        assert_equal(pre["bestblockhash"], fork_hash)

        self.connect_nodes(1, 0)

        saw_headers_advance = {"value": False}
        saw_body_request = {"value": False}

        def converging():
            info = mirror.getblockchaininfo()
            if info["headers"] > fork_height:
                saw_headers_advance["value"] = True
            for peer in mirror.getpeerinfo():
                if peer.get("inflight"):
                    saw_body_request["value"] = True
                # bytes toward block download also prove the path is alive
                recv = peer.get("bytesrecv_per_msg") or {}
                if recv.get("block", 0) > 0 or recv.get("cmpctblock", 0) > 0:
                    saw_body_request["value"] = True
            return mirror.getbestblockhash() == authority_tip

        # Bounded wait: a regression must fail, not hang for hours like production.
        self.wait_until(converging, timeout=300)

        final = mirror.getblockchaininfo()
        assert_equal(final["bestblockhash"], authority_tip)
        assert_equal(final["blocks"], authority_height)
        assert_equal(final["headers"], authority_height)
        assert_equal(mirror.getbestblockhash(), authority.getbestblockhash())
        # headers must have moved off the stranded tip at some point (or the tip
        # itself advanced past it — either proves best-header was not permanently pinned).
        assert saw_headers_advance["value"] or final["blocks"] > fork_height
        assert saw_body_request["value"] or final["blocks"] > fork_height

        status = mirror.getmatmultrustedstatus()
        assert_equal(status["trusted_mirror"], True)
        assert_greater_than_or_equal(status["accepted"], 1)

        # Run the combined acceptance scenario before narrower download-gate
        # cases so a failure there cannot mask PARK-depth/already-held-data
        # coverage in the functional test log.
        self.log.info(
            "PARK-depth losing fork, >10-header authenticated divergence, and "
            "higher bodies already present: root-first must request the holes "
            "and recover without operator action"
        )
        self._test_six_missing_roots_with_higher_bodies(
            authority, mirror, loser, relay
        )

        self.log.info(
            "Non-authority relay must serve followed-branch bodies "
            "(1-block divergent tip, hysteresis-clearing gap)"
        )
        self._test_bodies_from_non_authority_relay(
            authority, mirror, loser, relay, extensions=RELAY_GAP_SMALL
        )
        self.log.info(
            "Non-authority relay must serve followed-branch bodies "
            f"(gap>{TRUST_ADJUSTED_WORK_ALLOWANCE} past fork — claimed-work download)"
        )
        self._test_bodies_from_non_authority_relay(
            authority, mirror, loser, relay, extensions=RELAY_GAP_LARGE
        )

        self.log.info(
            "Deep-reorg guard: rewrite deeper than park_depth must stay refused"
        )
        self._test_deep_reorg_refusal(authority, mirror, loser)

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(2, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(3)

    def _push_authenticated_authority_headers_only(
        self, authority, mirror, fork_hash, tip_hash
    ):
        """Select an authority branch without letting that peer serve bodies.

        VERSION services are discovery hints only. Establish peer authority by
        delivering a signer-verified attestation at or above the mirror's active
        height, then announce its still-new descendants on the same connection.
        The peer is disconnected after all branch attestations are delivered,
        clearing its direct-fetch requests; later bodies therefore have to come
        from the separately asserted non-archive relay.
        """
        hashes = []
        blockhash = tip_hash
        while blockhash != fork_hash:
            hashes.append(blockhash)
            blockhash = authority.getblockheader(blockhash, True)[
                "previousblockhash"
            ]
        hashes.reverse()
        assert_greater_than(len(hashes), 0)

        headers = [
            from_hex(CBlockHeader(), authority.getblockheader(h, False))
            for h in hashes
        ]
        mirror_height = mirror.getblockcount()
        proof_pos = next(
            i
            for i, blockhash in enumerate(hashes)
            if authority.getblockheader(blockhash)["height"] >= mirror_height
        )

        peer = mirror.add_p2p_connection(P2PInterface(), services=ARCHIVE_SERVICES)
        peer.send_and_ping(msg_headers(headers=headers[: proof_pos + 1]))

        proof_atts = authority.getmatmulattestations(hashes[proof_pos])
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

        remaining_atts = []
        for i, blockhash in enumerate(hashes):
            if i == proof_pos:
                continue
            atts = authority.getmatmulattestations(blockhash)
            assert_greater_than_or_equal(len(atts), 1)
            remaining_atts.extend(bytes.fromhex(att) for att in atts)
        for i in range(0, len(remaining_atts), 16):
            batch = remaining_atts[i : i + 16]
            peer.send_and_ping(
                msg_generic(
                    b"mmattest",
                    ser_compact_size(len(batch)) + b"".join(batch),
                )
            )

        peer.peer_disconnect()
        mirror.disconnect_p2ps()

    def _test_bodies_from_non_authority_relay(
        self, authority, mirror, loser, relay, *, extensions
    ):
        """Production download-gate defect: after best-header follows the authority
        branch, bodies must be fetchable from ANY peer that has that chain — not
        only from IsTrustedMirrorAuthorityPeer(). Old gate logged
        trusted_mirror_not_tip_chain for every non-archive peer and stranded the
        mirror whenever the authority's inflight slots were stuck.

        Headers are injected via a headers-only P2P peer so the tip remains
        stranded. The peer's self-advertised archive bit is never treated as
        authority; verified attestations are imported and the known headers are
        re-announced before best-header is expected to follow. Bodies can then
        ONLY arrive from the non-archive relay.
        Old gate: fail (tip never moves). New gate: pass.

        When extensions > TRUST_ADJUSTED_WORK_ALLOWANCE, the headers-only winning
        branch is deeper than the unauth allowance: trust-adjusted work caps at
        fork+allowance while claimed nChainWork keeps climbing. Download must
        still open on claimed work (production: trusted_mirror_competing_less_work
        must not fire for a claimed-heavier recovery branch).
        """
        self._disconnect_all()

        # Align everyone on the post-convergence tip, then create a fresh race.
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)
        tip_hash = authority.getbestblockhash()
        self.wait_until(
            lambda: mirror.getbestblockhash() == tip_hash
            and loser.getbestblockhash() == tip_hash
            and relay.getbestblockhash() == tip_hash,
            timeout=300,
        )
        self._disconnect_all()

        fork_hash = tip_hash
        fork_height = authority.getblockcount()
        winning = self.generate(authority, 1, sync_fun=self.no_op)[0]
        losing = self.generate(loser, 1, sync_fun=self.no_op)[0]
        assert winning != losing
        if extensions > 0:
            self.generate(authority, extensions, sync_fun=self.no_op)
        authority_tip = authority.getbestblockhash()
        authority_height = authority.getblockcount()
        assert_equal(authority_height, fork_height + 1 + extensions)
        # Winning branch length past the fork (sibling + extensions).
        gap_past_fork = authority_height - fork_height
        if extensions > TRUST_ADJUSTED_WORK_ALLOWANCE:
            assert_greater_than(gap_past_fork, TRUST_ADJUSTED_WORK_ALLOWANCE)

        # Relay holds the full winning bodies but does NOT advertise archive.
        submit_chain_via_rpc(authority, relay)
        assert_equal(relay.getbestblockhash(), authority_tip)
        relay_services = int(relay.getnetworkinfo()["localservices"], 16)
        assert_equal(relay_services & NODE_MATMUL_ATTESTATION_ARCHIVE, 0)

        self.connect_nodes(1, 2)
        self._drive_mirror_onto(mirror, loser, losing, timeout=180)
        stranded_height = mirror.getblockcount()
        stranded_tip = mirror.getbestblockhash()
        self.disconnect_nodes(1, 2)
        assert_equal(stranded_height, fork_height + 1)
        assert_equal(stranded_tip, losing)

        # The headers-only source proves authority by delivering a valid signer
        # statement on this connection; its self-advertised service bit alone
        # grants no frontier-follow authority.
        self._push_authenticated_authority_headers_only(
            authority, mirror, fork_hash, authority_tip
        )
        self.wait_until(
            lambda: mirror.getblockchaininfo()["headers"] >= authority_height,
            timeout=180,
        )
        info = mirror.getblockchaininfo()
        assert_equal(info["blocks"], stranded_height)
        assert_equal(info["bestblockhash"], stranded_tip)
        assert_greater_than_or_equal(info["headers"], authority_height)
        headers_ahead = info["headers"] - info["blocks"]
        if extensions > TRUST_ADJUSTED_WORK_ALLOWANCE:
            assert_greater_than(headers_ahead, TRUST_ADJUSTED_WORK_ALLOWANCE)

        # Bodies can ONLY come from the non-archive relay.
        self.connect_nodes(1, 3)
        # Old gate: trusted_mirror_not_tip_chain forever. New gate: relay is on
        # the followed best-header chain → bodies download → tip moves.
        # Claimed-work download: even when headers_ahead > allowance, tip must
        # advance without invalidateblock / restart.
        self.wait_until(
            lambda: mirror.getbestblockhash() == authority_tip,
            timeout=300,
        )
        assert_equal(mirror.getblockcount(), authority_height)

        relay_peers = [
            p
            for p in mirror.getpeerinfo()
            if "MATMUL_ATTESTATION_ARCHIVE" not in (p.get("servicesnames") or [])
        ]
        assert_greater_than(len(relay_peers), 0)
        saw_relay_body = False
        for peer in relay_peers:
            recv = peer.get("bytesrecv_per_msg") or {}
            if recv.get("block", 0) > 0 or recv.get("cmpctblock", 0) > 0:
                saw_relay_body = True
            if peer.get("inflight"):
                saw_relay_body = True
        assert saw_relay_body, (
            "expected block bytes from the non-archive relay after followed-chain "
            "download gate opened"
        )

        assert_equal(mirror.getbestblockhash(), authority.getbestblockhash())
        self._disconnect_all()

    def _test_six_missing_roots_with_higher_bodies(
        self, authority, mirror, loser, relay
    ):
        """Reproduce automatic PARK-depth recovery with higher bodies held.

        Topology:
          - Mirror tip stranded exactly PARK_DEPTH blocks down a losing fork
          - Authority winning branch: sibling + MISSING_ROOT_COUNT + HIGHER_BODY_COUNT
          - Headers + attestations delivered; tip stays stranded
          - Higher canonical bodies planted onto the mirror via RPC (HAVE_DATA
            without a contiguous connectable prefix) so pindexLastCommonBlock is
            tempted to skip the hole
          - Bodies for the six lower roots remain absent
          - Non-archive relay holds the full winning chain

        Old behavior: walk starts past the holes → roots never requested → tip
        frozen, or activation remains trapped behind reorg policy despite data
        already being present. New behavior: root-first clamp re-derives
        LastCommon and the coordinated recovery state automatically activates
        the uniquely attested branch. Recovery uses no invalidateblock,
        reconsiderblock, or process restart and must finish within 300 seconds.
        """
        self._disconnect_all()

        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)
        tip_hash = authority.getbestblockhash()
        self.wait_until(
            lambda: mirror.getbestblockhash() == tip_hash
            and loser.getbestblockhash() == tip_hash
            and relay.getbestblockhash() == tip_hash,
            timeout=300,
        )
        self._disconnect_all()

        fork_hash = tip_hash
        fork_height = authority.getblockcount()
        winning = self.generate(authority, 1, sync_fun=self.no_op)[0]
        losing_hashes = self.generate(loser, PARK_DEPTH, sync_fun=self.no_op)
        losing_root = losing_hashes[0]
        losing_tip = losing_hashes[-1]
        assert winning != losing_root
        assert_equal(
            loser.getblockheader(losing_root)["previousblockhash"], fork_hash
        )
        assert_equal(loser.getblockcount(), fork_height + PARK_DEPTH)

        # Six lower roots after the winning sibling, then twelve higher bodies.
        # This makes both the winning branch length and the observable
        # headers-minus-blocks gap exceed ten once the mirror is on the
        # PARK_DEPTH losing branch.
        self.generate(
            authority,
            MISSING_ROOT_COUNT + HIGHER_BODY_COUNT,
            sync_fun=self.no_op,
        )
        authority_tip = authority.getbestblockhash()
        authority_height = authority.getblockcount()
        assert_equal(
            authority_height,
            fork_height + 1 + MISSING_ROOT_COUNT + HIGHER_BODY_COUNT,
        )
        assert_greater_than(authority_height - fork_height, 10)
        assert_greater_than(
            authority_height - (fork_height + PARK_DEPTH), 10
        )
        assert_greater_than(
            authority_height - fork_height, TRUST_ADJUSTED_WORK_ALLOWANCE
        )

        # Winning-branch hashes from low to high (exclusive of fork).
        winning_hashes = []
        blockhash = authority_tip
        while blockhash != fork_hash:
            winning_hashes.append(blockhash)
            header = authority.getblockheader(blockhash, True)
            blockhash = header["previousblockhash"]
        winning_hashes.reverse()
        assert_equal(len(winning_hashes), 1 + MISSING_ROOT_COUNT + HIGHER_BODY_COUNT)
        missing_roots = winning_hashes[: 1 + MISSING_ROOT_COUNT]
        higher_bodies = winning_hashes[1 + MISSING_ROOT_COUNT :]
        assert_equal(len(missing_roots), 1 + MISSING_ROOT_COUNT)
        assert_equal(len(higher_bodies), HIGHER_BODY_COUNT)

        submit_chain_via_rpc(authority, relay)
        assert_equal(relay.getbestblockhash(), authority_tip)

        self.connect_nodes(1, 2)
        self._drive_mirror_onto(mirror, loser, losing_tip, timeout=300)
        stranded_height = mirror.getblockcount()
        stranded_tip = mirror.getbestblockhash()
        self.disconnect_nodes(1, 2)
        assert_equal(stranded_tip, losing_tip)
        assert_equal(stranded_height, fork_height + PARK_DEPTH)
        assert_equal(stranded_height - fork_height, PARK_DEPTH)

        # Deliver the complete header and authority-attestation view first.
        # The headers-only source proves authority by delivering a signer-valid
        # statement on this connection; its self-advertised service bit alone
        # grants no frontier-follow authority.
        self._push_authenticated_authority_headers_only(
            authority, mirror, fork_hash, authority_tip
        )
        self.wait_until(
            lambda: mirror.getblockchaininfo()["headers"] >= authority_height,
            timeout=180,
        )
        info = mirror.getblockchaininfo()
        assert_equal(info["blocks"], stranded_height)
        assert_equal(info["bestblockhash"], stranded_tip)
        assert_greater_than(info["headers"] - info["blocks"], 10)

        # Plant ONLY the higher bodies so LastCommon is tempted past the hole.
        # Headers are already known; submitblock stores HAVE_DATA even when the
        # parent body is absent (unlinked). That is the production drag bait.
        for blockhash in higher_bodies:
            raw = authority.getblock(blockhash, False)
            try:
                result = mirror.submitblock(raw)
            except JSONRPCException as exc:
                # Quorum race: attestations were seeded, but retry once.
                if "quorum" not in str(exc).lower():
                    raise
                atts = authority.getmatmulattestations(blockhash)
                mirror.submitmatmulattestations(atts)
                result = mirror.submitblock(raw)
            assert result in (None, "duplicate", "inconclusive"), (
                f"plant higher body {blockhash} -> {result}"
            )
            # Prove the body is on disk (HAVE_DATA), not merely the header.
            mirror.getblock(blockhash, False)
        assert_equal(len(higher_bodies), HIGHER_BODY_COUNT)

        # Confirm the lower roots (winning sibling + six) are still absent.
        for blockhash in missing_roots:
            try:
                mirror.getblock(blockhash, False)
                raise AssertionError(
                    f"missing root {blockhash} unexpectedly present before reconnect"
                )
            except JSONRPCException:
                pass

        pre = mirror.getblockchaininfo()
        assert_equal(pre["blocks"], stranded_height)
        assert_equal(pre["bestblockhash"], stranded_tip)
        assert_greater_than_or_equal(pre["headers"], authority_height)
        assert_greater_than(pre["headers"] - pre["blocks"], 10)
        # Re-read every planted block immediately before the network recovery
        # trigger. This is the acceptance proof that the mirror already holds
        # the upper branch data while its active tip remains on the losing fork.
        for blockhash in higher_bodies:
            mirror.getblock(blockhash, False)

        # Bodies for the roots can ONLY come from the non-archive relay. From
        # this point onward the test performs no RPC that mutates chain state:
        # P2P delivery and activation must complete recovery automatically.
        self.connect_nodes(1, 3)
        self.wait_until(
            lambda: mirror.getbestblockhash() == authority_tip,
            timeout=300,
        )
        assert_equal(mirror.getblockcount(), authority_height)
        assert_equal(mirror.getbestblockhash(), authority.getbestblockhash())
        self._disconnect_all()

    def _test_deep_reorg_refusal(self, authority, mirror, loser):
        # Ensure mirror follows authority on the canonical tip first.
        self._disconnect_all()

        # Grow a settled tip well above park_depth so a deep rewrite is possible.
        self.connect_nodes(0, 1)
        self.generate(authority, PARK_DEPTH + 3, sync_fun=self.no_op)
        self.wait_until(
            lambda: mirror.getbestblockhash() == authority.getbestblockhash(),
            timeout=300,
        )
        tip_hash = authority.getbestblockhash()
        tip_height = authority.getblockcount()
        fork_height = tip_height - (PARK_DEPTH + 2)
        assert_greater_than(fork_height, REORG_PROTECTION_START)
        fork_hash = authority.getblockhash(fork_height)

        rejected_before = authority.getdifficultyhealth(5)["reorg_protection"]["rejected_reorgs"]
        mirror_rejected_before = mirror.getdifficultyhealth(5)["reorg_protection"]["rejected_reorgs"]

        self.log.info(
            f"Build competing branch from height {fork_height} deeper than park_depth={PARK_DEPTH}"
        )
        self.disconnect_nodes(0, 1)
        # Bring the competing miner onto the authority tip first (consensus path,
        # no attestations required), then rewind to the fork and mine a deep rewrite.
        submit_chain_via_rpc(authority, loser)
        self.wait_until(lambda: loser.getbestblockhash() == tip_hash, timeout=120)
        while loser.getblockcount() > fork_height:
            loser.invalidateblock(loser.getbestblockhash())
        assert_equal(loser.getbestblockhash(), fork_hash)
        competing_len = (tip_height - fork_height) + 3
        self.generate(loser, competing_len, sync_fun=self.no_op)
        assert_greater_than(loser.getblockcount(), tip_height)
        competing_tip = loser.getbestblockhash()

        # Authority is consensus: RPC submit is enough to exercise PARK.
        submit_chain_via_rpc(loser, authority, stop_hash=fork_hash)
        assert_equal(authority.getbestblockhash(), tip_hash)
        assert_equal(authority.getblockcount(), tip_height)

        # Mirror: deliver competing bodies with attestations so ActivateBestChain
        # actually considers the rewrite and must PARK it.
        submit_attested_chain_via_rpc(loser, mirror, stop_hash=fork_hash)
        assert_equal(mirror.getbestblockhash(), tip_hash)
        assert_equal(mirror.getblockcount(), tip_height)

        # Competing headers may be known, but must not become the active tip.
        auth_tips = {t["hash"]: t for t in authority.getchaintips()}
        assert competing_tip in auth_tips or any(
            t.get("height", 0) >= loser.getblockcount() for t in authority.getchaintips()
        )

        auth_rp = authority.getdifficultyhealth(5)["reorg_protection"]
        mirror_rp = mirror.getdifficultyhealth(5)["reorg_protection"]
        assert_greater_than_or_equal(auth_rp["rejected_reorgs"], rejected_before + 1)
        assert_greater_than_or_equal(
            mirror_rp["rejected_reorgs"], mirror_rejected_before + 1
        )
        assert_equal(auth_rp["parking_enabled"], True)
        assert_equal(mirror_rp["parking_enabled"], True)

        # Mirror still must not chase the parked rewrite once reconnected to authority.
        self.connect_nodes(1, 0)
        self.generate(authority, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: mirror.getbestblockhash() == authority.getbestblockhash(),
            timeout=180,
        )
        assert mirror.getbestblockhash() != competing_tip


if __name__ == "__main__":
    MatMulTrustedMirrorConvergenceTest(__file__).main()
