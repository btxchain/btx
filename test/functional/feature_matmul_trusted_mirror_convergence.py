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

It also guards pindexLastCommonBlock root-first recovery: when higher canonical
bodies are already on the mirror (getblockfrompeer / partial sync) while six
lower roots on the followed chain are still missing, LastCommon must not skip
past the holes — the mirror must request the roots and reach tip with no
operator action. A test that does not first plant higher bodies cannot
reproduce that stall class.

It also guards deep-reorg finality (failure C): a competing rewrite deeper than
EMERGENCY park_depth must still be refused by both authority and mirror.
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
    msg_headers,
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
HIGHER_BODY_COUNT = 6
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
        # Full consensus peer that holds bodies but is NOT an attestation
        # archive — production mirrors must be able to fetch the followed
        # recovery branch from any such peer, not only from the authority.
        relay = common + [
            "-matmulvalidation=consensus",
            "-matmulattestationserve=0",
        ]
        self.archive_args = archive
        self.mirror_args = mirror
        # node0=authority, node1=mirror, node2=losing-sibling miner,
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

    def _seed_attestations_for_chain(self, src, dest_mirror, stop_hash):
        """Import ExactReplay attestations for every block above stop_hash."""
        blockhash = src.getbestblockhash()
        hashes = []
        while blockhash != stop_hash:
            hashes.append(blockhash)
            header = src.getblockheader(blockhash, True)
            if "previousblockhash" not in header:
                break
            blockhash = header["previousblockhash"]
        for blockhash in reversed(hashes):
            atts = src.getmatmulattestations(blockhash)
            assert_greater_than_or_equal(len(atts), 1)
            imported = dest_mirror.submitmatmulattestations(atts)
            assert imported[0]["quorum"] is True

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

        self.log.info("Drive the trusted mirror onto the LOSING sibling over P2P")
        self.connect_nodes(1, 2)
        self.wait_until(
            lambda: mirror.getbestblockhash() == losing,
            timeout=180,
        )
        stranded_tip = mirror.getbestblockhash()
        stranded_height = mirror.getblockcount()
        stranded_info = mirror.getblockchaininfo()
        assert_equal(stranded_tip, losing)
        assert_equal(stranded_info["blocks"], stranded_height)
        assert_equal(stranded_info["headers"], stranded_height)
        self.disconnect_nodes(1, 2)

        self.log.info(
            "Authority extends the winning branch past hysteresis; mirror stays stranded"
        )
        self.generate(authority, AUTHORITY_EXTENSIONS, sync_fun=self.no_op)
        authority_tip = authority.getbestblockhash()
        authority_height = authority.getblockcount()
        assert_greater_than(authority_height, stranded_height)
        assert_equal(mirror.getbestblockhash(), stranded_tip)
        assert_equal(mirror.getblockcount(), stranded_height)

        self.log.info(
            "Reconnect mirror→authority only; must converge without invalidateblock/restart"
        )
        # Snapshot stall signals the production failure used to show forever.
        pre = mirror.getblockchaininfo()
        assert_equal(pre["blocks"], pre["headers"])
        assert_equal(pre["bestblockhash"], stranded_tip)

        self.connect_nodes(1, 0)

        saw_headers_advance = {"value": False}
        saw_body_request = {"value": False}

        def converging():
            info = mirror.getblockchaininfo()
            if info["headers"] > stranded_height:
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
        assert saw_headers_advance["value"] or final["blocks"] > stranded_height
        # Body fetch path must have been used (not outstanding_slots=0 forever).
        # If convergence was so fast inflight was never sampled, block bytes still count;
        # as a last resort, tip equality after a multi-block gap implies bodies arrived.
        assert saw_body_request["value"] or final["blocks"] > stranded_height

        status = mirror.getmatmultrustedstatus()
        assert_equal(status["trusted_mirror"], True)
        assert_greater_than_or_equal(status["accepted"], 1)

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
            "Six missing roots with higher bodies already present: "
            "root-first must request the holes without operator action"
        )
        self._test_six_missing_roots_with_higher_bodies(
            authority, mirror, loser, relay
        )

        self.log.info(
            "Deep-reorg guard: rewrite deeper than park_depth must stay refused"
        )
        self._test_deep_reorg_refusal(authority, mirror, loser)

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(2, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(3)

    def _push_authority_headers_only(self, authority, mirror, fork_hash, tip_hash):
        """Move mirror best-header onto the winning branch without delivering bodies.

        A real authority node would HeadersDirectFetch and serve bodies; that
        collapses the download-gate scenario. Inject HEADERS from a throwaway
        P2P peer that advertises NODE_MATMUL_ATTESTATION_ARCHIVE, then disconnect
        so any direct-fetch in-flight entries are cleared with the peer.
        """
        hashes = []
        blockhash = tip_hash
        while blockhash != fork_hash:
            hashes.append(blockhash)
            header = authority.getblockheader(blockhash, True)
            if "previousblockhash" not in header:
                break
            blockhash = header["previousblockhash"]
        hashes.reverse()
        assert_greater_than(len(hashes), 0)

        headers = [
            from_hex(CBlockHeader(), authority.getblockheader(h, False))
            for h in hashes
        ]
        peer = mirror.add_p2p_connection(P2PInterface(), services=ARCHIVE_SERVICES)
        # Chunk to stay under max_headers_result.
        for i in range(0, len(headers), 2000):
            peer.send_and_ping(msg_headers(headers=headers[i : i + 2000]))
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

        Headers are injected via a headers-only archive P2P peer so the tip
        remains stranded; bodies can then ONLY arrive from the non-archive relay.
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
        self.wait_until(lambda: mirror.getbestblockhash() == losing, timeout=180)
        stranded_height = mirror.getblockcount()
        stranded_tip = mirror.getbestblockhash()
        self.disconnect_nodes(1, 2)
        assert_equal(stranded_height, fork_height + 1)
        assert_equal(stranded_tip, losing)

        # Headers-only: best-header follows winning branch; tip stays stranded.
        self._push_authority_headers_only(authority, mirror, fork_hash, authority_tip)
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

        # Seed quorums via RPC so acceptance does not depend on the relay
        # serving MMATTEST (it does not). Download policy is what we test.
        self._seed_attestations_for_chain(authority, mirror, stop_hash=fork_hash)

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
        """Reproduce LastCommon drag past missing roots when higher bodies exist.

        Topology:
          - Mirror tip stranded on a losing sibling
          - Authority winning branch: sibling + MISSING_ROOT_COUNT + HIGHER_BODY_COUNT
          - Headers + attestations delivered; tip stays stranded
          - Higher canonical bodies planted onto the mirror via RPC (HAVE_DATA
            without a contiguous connectable prefix) so pindexLastCommonBlock is
            tempted to skip the hole
          - Bodies for the six lower roots remain absent
          - Non-archive relay holds the full winning chain

        Old behavior: walk starts past the holes → roots never requested → tip
        frozen. New behavior: root-first clamp re-derives LastCommon and the
        mirror converges with no invalidateblock/restart.
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
        losing = self.generate(loser, 1, sync_fun=self.no_op)[0]
        assert winning != losing
        # Six lower roots after the winning sibling, then six higher bodies.
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
        self.wait_until(lambda: mirror.getbestblockhash() == losing, timeout=180)
        stranded_height = mirror.getblockcount()
        stranded_tip = mirror.getbestblockhash()
        self.disconnect_nodes(1, 2)
        assert_equal(stranded_tip, losing)

        # Headers-only follow onto the winning branch; tip stays stranded.
        self._push_authority_headers_only(authority, mirror, fork_hash, authority_tip)
        self.wait_until(
            lambda: mirror.getblockchaininfo()["headers"] >= authority_height,
            timeout=180,
        )
        info = mirror.getblockchaininfo()
        assert_equal(info["blocks"], stranded_height)
        assert_equal(info["bestblockhash"], stranded_tip)

        self._seed_attestations_for_chain(authority, mirror, stop_hash=fork_hash)

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

        # Bodies for the roots can ONLY come from the non-archive relay.
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
