// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Audit P0.1/C1 -- provisional vs. authenticated chainwork.
//
// These tests exercise the consensus-accounting CORE used by the production
// maintenance sites (BlockManager::AddToBlockIndex, ReceivedBlockTransactions,
// BlockManager::LoadBlockIndex). All three call the exact same primitives tested
// here: IsBlockAuthenticated / GetBlockAuthenticatedProof /
// UpdateAuthenticatedChainWork (src/chain.cpp). Building synthetic CBlockIndex
// trees lets us flood thousands of forged (matmul_digest-only) header indices on
// CPU deterministically, which real MatMul mining could not do in a unit test.
//
// See doc/btx-matmul-v4.2-chainwork-authentication.md for the design and for the
// networking-layer behavior that requires a live multi-node network to verify.

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <kernel/chainstatemanager_opts.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <deque>
#include <limits>
#include <vector>

namespace {

// A per-block nBits giving a fixed, non-trivial work unit W = GetBlockProof(nBits).
constexpr uint32_t TEST_NBITS{0x1d00ffffU};

Consensus::Params ParamsWithFork(int32_t fork_height)
{
    Consensus::Params p = CreateChainParams(ArgsManager{}, ChainType::REGTEST)->GetConsensus();
    p.fMatMulPOW = true;
    p.nMatMulV4Height = fork_height; // finite => IsMatMulV4Active(height) becomes testable
    return p;
}

// Stable-address container of block indices (deque never invalidates references on
// push_back, so pprev pointers stay valid as the chain grows).
struct Chain {
    std::deque<CBlockIndex> blocks;

    CBlockIndex* Add(uint32_t status) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CBlockIndex* prev = blocks.empty() ? nullptr : &blocks.back();
        blocks.emplace_back();
        CBlockIndex& idx = blocks.back();
        idx.pprev = prev;
        idx.nHeight = prev ? prev->nHeight + 1 : 0;
        idx.nBits = TEST_NBITS;
        idx.nStatus = status;
        return &idx;
    }

    // Recompute nChainWork + nAuthenticatedChainWork in height order -- exactly what
    // BlockManager::LoadBlockIndex does on startup (the restart/reindex path).
    void Recompute(const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        for (CBlockIndex& idx : blocks) {
            idx.nChainWork = (idx.pprev ? idx.pprev->nChainWork : arith_uint256{}) + GetBlockProof(idx);
            UpdateAuthenticatedChainWork(idx, params);
        }
    }
};

// Body-verified block: at MatMul heights this is what ContextualCheckBlock ->
// ReceivedBlockTransactions produces once the MatMul proof passes.
constexpr uint32_t ST_AUTHENTICATED{BLOCK_VALID_TRANSACTIONS};
// Header-only block: what AddToBlockIndex produces for a header with no body.
constexpr uint32_t ST_HEADER_ONLY{BLOCK_VALID_TREE};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_chainwork_auth_tests, BasicTestingSetup)

// A flood of matmul_digest-only headers must NOT increase authenticated work,
// even though provisional nChainWork keeps climbing with every header.
BOOST_AUTO_TEST_CASE(forged_header_flood_adds_zero_authenticated_work)
{
    LOCK(::cs_main);
    const int32_t kFork = 5;
    const Consensus::Params params = ParamsWithFork(kFork);
    Chain c;

    // Heights 0..4: pre-fork blocks with bodies.
    for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED);
    // Height 5: first MatMul-height block, body verified (authenticated).
    CBlockIndex* last_real = c.Add(ST_AUTHENTICATED);
    // Heights 6..3005: 3000 forged header-only MatMul blocks (no bodies).
    const int kForged = 3000;
    for (int i = 0; i < kForged; ++i) c.Add(ST_HEADER_ONLY);

    c.Recompute(params);

    const arith_uint256 authed_at_last_real = last_real->nAuthenticatedChainWork;
    BOOST_CHECK(authed_at_last_real > arith_uint256{}); // real work accrued

    arith_uint256 prev_chainwork = last_real->nChainWork;
    for (size_t h = kFork + 1; h < c.blocks.size(); ++h) {
        const CBlockIndex& idx = c.blocks[h];
        // Provisional work keeps growing with every forged header...
        BOOST_CHECK(idx.nChainWork > prev_chainwork);
        prev_chainwork = idx.nChainWork;
        // ...but authenticated work is flat at the last genuinely-verified block.
        BOOST_CHECK_EQUAL(idx.nAuthenticatedChainWork.GetHex(), authed_at_last_real.GetHex());
        // And the two notions have visibly diverged.
        BOOST_CHECK(idx.nChainWork > idx.nAuthenticatedChainWork);
    }

    // The forged tip claims full provisional work but zero *additional* authenticated work.
    const CBlockIndex& forged_tip = c.blocks.back();
    BOOST_CHECK(forged_tip.nChainWork > forged_tip.nAuthenticatedChainWork);
    BOOST_CHECK_EQUAL(forged_tip.nAuthenticatedChainWork.GetHex(), authed_at_last_real.GetHex());
}

// Supplying a valid body later promotes work deterministically, and the promotion
// propagates to all descendants on recompute.
BOOST_AUTO_TEST_CASE(valid_body_promotes_deterministically)
{
    LOCK(::cs_main);
    const int32_t kFork = 3;
    const Consensus::Params params = ParamsWithFork(kFork);
    Chain c;
    for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED); // 0..2 pre-fork
    c.Add(ST_AUTHENTICATED);                                 // height 3 authenticated
    CBlockIndex* h4 = c.Add(ST_HEADER_ONLY);                 // height 4 header-only
    CBlockIndex* h5 = c.Add(ST_HEADER_ONLY);                 // height 5 header-only
    c.Recompute(params);

    const arith_uint256 authed_before = h5->nAuthenticatedChainWork;
    const arith_uint256 W = GetBlockProof(*h4);
    BOOST_CHECK_EQUAL(h4->nAuthenticatedChainWork.GetHex(), h4->pprev->nAuthenticatedChainWork.GetHex());

    // Body for height 4 arrives and its MatMul proof verifies -> BLOCK_VALID_TRANSACTIONS.
    h4->nStatus = ST_AUTHENTICATED;
    c.Recompute(params);

    // h4 gains exactly one work unit; h5 (still header-only) inherits the promotion.
    BOOST_CHECK_EQUAL(h4->nAuthenticatedChainWork.GetHex(), (h4->pprev->nAuthenticatedChainWork + W).GetHex());
    BOOST_CHECK_EQUAL(h5->nAuthenticatedChainWork.GetHex(), (authed_before + W).GetHex());
    BOOST_CHECK(h5->nAuthenticatedChainWork > authed_before);
}

// A verified body above a header-only gap must not earn authenticated work
// until the gap is filled. Authenticated chainwork is a contiguous prefix;
// otherwise an attacker could interleave forged headers with isolated valid
// bodies and receive trust credit for a branch whose ancestry is not valid.
BOOST_AUTO_TEST_CASE(out_of_order_body_does_not_authenticate_across_gap)
{
    LOCK(::cs_main);
    const int32_t kFork = 2;
    const Consensus::Params params = ParamsWithFork(kFork);
    Chain c;
    for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED); // 0..1 pre-fork
    CBlockIndex* base = c.Add(ST_AUTHENTICATED);             // height 2 authenticated
    CBlockIndex* gap = c.Add(ST_HEADER_ONLY);                // height 3 body missing
    CBlockIndex* child = c.Add(ST_AUTHENTICATED);            // height 4 body arrived first
    c.Recompute(params);

    const arith_uint256 prefix_work = base->nAuthenticatedChainWork;
    BOOST_CHECK(!IsBlockAuthenticated(*gap, params));
    BOOST_CHECK(!IsBlockAuthenticated(*child, params));
    BOOST_CHECK_EQUAL(gap->nAuthenticatedChainWork.GetHex(), prefix_work.GetHex());
    BOOST_CHECK_EQUAL(child->nAuthenticatedChainWork.GetHex(), prefix_work.GetHex());

    // Filling the gap promotes both the gap and its already-verified child in
    // parent-first order, exactly as ReceivedBlockTransactions' descendant
    // propagation does in production.
    gap->nStatus = ST_AUTHENTICATED;
    c.Recompute(params);
    const arith_uint256 expected = prefix_work + GetBlockProof(*gap) + GetBlockProof(*child);
    BOOST_CHECK(IsBlockAuthenticated(*gap, params));
    BOOST_CHECK(IsBlockAuthenticated(*child, params));
    BOOST_CHECK_EQUAL(child->nAuthenticatedChainWork.GetHex(), expected.GetHex());
    BOOST_CHECK_EQUAL(child->nAuthenticatedChainWork.GetHex(), child->nChainWork.GetHex());
}

// A body that fails validation can NEVER contribute authenticated work, even if
// some VALID_* bits are set alongside the FAILED bit.
BOOST_AUTO_TEST_CASE(invalid_body_never_promotes)
{
    LOCK(::cs_main);
    const int32_t kFork = 2;
    const Consensus::Params params = ParamsWithFork(kFork);
    Chain c;
    for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED); // 0..1 pre-fork
    CBlockIndex* base = c.Add(ST_AUTHENTICATED);             // height 2 authenticated
    // Height 3: body arrived but MatMul proof failed.
    CBlockIndex* failed = c.Add(BLOCK_VALID_TRANSACTIONS | BLOCK_FAILED_VALID);
    CBlockIndex* child = c.Add(BLOCK_FAILED_CHILD);          // descends from failed
    c.Recompute(params);

    BOOST_CHECK(!IsBlockAuthenticated(*failed, params));
    BOOST_CHECK_EQUAL(GetBlockAuthenticatedProof(*failed, params).GetHex(), arith_uint256{}.GetHex());
    // Failed block and its child carry no additional authenticated work.
    BOOST_CHECK_EQUAL(failed->nAuthenticatedChainWork.GetHex(), base->nAuthenticatedChainWork.GetHex());
    BOOST_CHECK_EQUAL(child->nAuthenticatedChainWork.GetHex(), base->nAuthenticatedChainWork.GetHex());
    // But provisional work still grew (the attack surface we are neutralizing).
    BOOST_CHECK(failed->nChainWork > base->nChainWork);
}

// Restart/reindex preserves the provisional/authenticated split: recomputing from
// persisted nStatus reproduces the incrementally-built values exactly.
BOOST_AUTO_TEST_CASE(restart_recompute_is_deterministic)
{
    LOCK(::cs_main);
    const int32_t kFork = 4;
    const Consensus::Params params = ParamsWithFork(kFork);
    Chain c;
    for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED);
    c.Add(ST_AUTHENTICATED);   // height 4 authenticated
    c.Add(ST_HEADER_ONLY);     // height 5 forged
    c.Add(ST_AUTHENTICATED);   // height 6 authenticated body (out-of-order arrival)
    c.Add(ST_HEADER_ONLY);     // height 7 forged
    c.Recompute(params);

    std::vector<std::string> snapshot;
    for (const CBlockIndex& idx : c.blocks) snapshot.push_back(idx.nAuthenticatedChainWork.GetHex());

    // Simulate a restart: wipe derived work and recompute from persisted nStatus.
    for (CBlockIndex& idx : c.blocks) {
        idx.nChainWork = arith_uint256{};
        idx.nAuthenticatedChainWork = arith_uint256{};
    }
    c.Recompute(params);

    for (size_t i = 0; i < c.blocks.size(); ++i) {
        BOOST_CHECK_EQUAL(c.blocks[i].nAuthenticatedChainWork.GetHex(), snapshot[i]);
    }
}

// A competing genuinely-authenticated chain must be selected over a longer forged
// chain: authenticated work orders them correctly even while provisional work does not.
BOOST_AUTO_TEST_CASE(authenticated_chain_selected_over_longer_forged_chain)
{
    LOCK(::cs_main);
    const int32_t kFork = 2;
    const Consensus::Params params = ParamsWithFork(kFork);

    // Shared authenticated base at heights 0..2.
    Chain base;
    for (int i = 0; i < kFork; ++i) base.Add(ST_AUTHENTICATED);
    CBlockIndex* fork_point = base.Add(ST_AUTHENTICATED); // height 2, authenticated
    base.Recompute(params);

    // Fork A: 3 authenticated MatMul blocks (real work, shorter).
    std::deque<CBlockIndex> forkA;
    CBlockIndex* prevA = fork_point;
    for (int i = 0; i < 3; ++i) {
        forkA.emplace_back();
        CBlockIndex& idx = forkA.back();
        idx.pprev = prevA; idx.nHeight = prevA->nHeight + 1; idx.nBits = TEST_NBITS; idx.nStatus = ST_AUTHENTICATED;
        idx.nChainWork = idx.pprev->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        prevA = &idx;
    }

    // Fork B: 100 forged header-only blocks (no real work, longer).
    std::deque<CBlockIndex> forkB;
    CBlockIndex* prevB = fork_point;
    for (int i = 0; i < 100; ++i) {
        forkB.emplace_back();
        CBlockIndex& idx = forkB.back();
        idx.pprev = prevB; idx.nHeight = prevB->nHeight + 1; idx.nBits = TEST_NBITS; idx.nStatus = ST_HEADER_ONLY;
        idx.nChainWork = idx.pprev->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        prevB = &idx;
    }

    const CBlockIndex& tipA = forkA.back();
    const CBlockIndex& tipB = forkB.back();

    // Provisional work favors the longer forged chain (the vulnerability)...
    BOOST_CHECK(tipB.nChainWork > tipA.nChainWork);
    // ...but authenticated work correctly favors the real, shorter chain.
    BOOST_CHECK(tipA.nAuthenticatedChainWork > tipB.nAuthenticatedChainWork);
    // The forged tip earned zero authenticated work beyond the shared base.
    BOOST_CHECK_EQUAL(tipB.nAuthenticatedChainWork.GetHex(), fork_point->nAuthenticatedChainWork.GetHex());
}

// Pre-fork (v3) heights must be byte-identical: authenticated == provisional for
// every block regardless of body/validity status, so legacy behavior is untouched.
BOOST_AUTO_TEST_CASE(pre_fork_heights_are_byte_identical)
{
    LOCK(::cs_main);
    // Fork far in the future => every test height is pre-fork (like INT32_MAX today).
    const Consensus::Params params = ParamsWithFork(std::numeric_limits<int32_t>::max());
    Chain c;
    c.Add(ST_AUTHENTICATED);
    c.Add(ST_HEADER_ONLY);   // header-only, but pre-fork => still fully credited
    c.Add(BLOCK_VALID_TREE);
    c.Add(ST_AUTHENTICATED);
    c.Recompute(params);

    for (const CBlockIndex& idx : c.blocks) {
        BOOST_CHECK(IsBlockAuthenticated(idx, params));
        BOOST_CHECK_EQUAL(idx.nAuthenticatedChainWork.GetHex(), idx.nChainWork.GetHex());
    }
}

// WP-8 / C1/H2: GetTrustAdjustedChainWork must be EXACTLY nChainWork pre-fork
// (the routed peer-selection sites are then behavior-identical). Post-fork,
// production credits at most TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS of unverified
// suffix — never the full claimed flood.
BOOST_AUTO_TEST_CASE(trust_adjusted_work_identity_and_bounded_credit)
{
    LOCK(::cs_main);
    constexpr unsigned int kAllowance{TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS};
    // Bound equals EMERGENCY park_depth so chase preference cannot outrun the
    // depth at which PARK refuses activation of a rewrite.
    static_assert(kAllowance == 6);
    static_assert(kAllowance == kernel::GetReorgProtectionProfileSettings(
                                    kernel::ReorgProtectionProfile::EMERGENCY)
                                    .park_depth);

    // Pre-fork (fork disabled, like INT32_MAX today): identity on every status mix.
    {
        const Consensus::Params params = ParamsWithFork(std::numeric_limits<int32_t>::max());
        Chain c;
        c.Add(ST_AUTHENTICATED);
        c.Add(ST_HEADER_ONLY);
        c.Add(BLOCK_VALID_TREE);
        c.Add(ST_AUTHENTICATED);
        c.Recompute(params);
        for (const CBlockIndex& idx : c.blocks) {
            BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(idx, kAllowance).GetHex(), idx.nChainWork.GetHex());
        }
    }

    // Post-fork: one unverified header receives exactly one proof of credit;
    // a forged 100-header suffix is capped at the allowance (not full claimed).
    {
        const int32_t kFork = 3;
        const Consensus::Params params = ParamsWithFork(kFork);
        Chain c;
        for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED); // pre-fork base
        CBlockIndex* last_auth = c.Add(ST_AUTHENTICATED);        // first v4 block, body-verified
        for (int i = 0; i < 100; ++i) c.Add(ST_HEADER_ONLY);     // forged suffix
        c.Recompute(params);

        const CBlockIndex& forged_tip = c.blocks.back();
        const CBlockIndex& first_unverified = c.blocks[kFork + 1];
        const arith_uint256 one_proof{GetBlockProof(first_unverified)};
        arith_uint256 allowance_work{one_proof};
        allowance_work *= kAllowance;

        // One-header credit: auth + 1 proof.
        BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(first_unverified, kAllowance).GetHex(),
                          (last_auth->nAuthenticatedChainWork + one_proof).GetHex());
        // Deep forged tip: capped at auth + allowance, never full claimed work.
        BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(forged_tip, kAllowance).GetHex(),
                          (last_auth->nAuthenticatedChainWork + allowance_work).GetHex());
        BOOST_CHECK(GetTrustAdjustedChainWork(forged_tip, kAllowance) < forged_tip.nChainWork);
        BOOST_CHECK(GetTrustAdjustedChainWork(forged_tip, kAllowance) >
                    last_auth->nAuthenticatedChainWork);

        // Fully authenticated chains are always identity, post-fork included.
        BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(*last_auth, kAllowance).GetHex(),
                          last_auth->nChainWork.GetHex());
    }
}

// An Epoch-A RC header extending an authenticated tip has greater raw claimed
// work. With the production bounded allowance it MUST be able to displace that
// tip as operational best header so the body can be chased — otherwise a node
// that is only one header behind never requests it. Zero-allowance previously
// forbade this and stranded tips; the bound (not zero) is the escape valve.
BOOST_AUTO_TEST_CASE(one_unverified_rc_header_can_displace_authenticated_tip_for_chase)
{
    LOCK(::cs_main);
    const int32_t kFork = 2;
    Consensus::Params params = ParamsWithFork(kFork);
    params.nMatMulRCHeight = kFork;
    params.nMatMulRCProfile = 1;

    Chain c;
    for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED);
    CBlockIndex* authenticated_tip = c.Add(ST_AUTHENTICATED);
    CBlockIndex* unverified_rc_header = c.Add(ST_HEADER_ONLY);
    c.Recompute(params);

    BOOST_REQUIRE(params.IsMatMulRCActive(unverified_rc_header->nHeight));
    BOOST_CHECK(unverified_rc_header->nChainWork > authenticated_tip->nChainWork);
    BOOST_CHECK(GetTrustAdjustedChainWork(*unverified_rc_header, TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS) >
                authenticated_tip->nAuthenticatedChainWork);
    BOOST_CHECK(PreferTrustAdjustedHeader(*authenticated_tip, *unverified_rc_header));
    BOOST_CHECK(!PreferTrustAdjustedHeader(*unverified_rc_header, *authenticated_tip));
}

// Same-height race: the losing authenticated tip must be displaceable by a
// competing headers-only branch that is only a few headers ahead, otherwise
// m_best_header stays pinned and bodies on the winning branch are never chased.
BOOST_AUTO_TEST_CASE(bounded_allowance_rescues_losing_same_height_tip)
{
    LOCK(::cs_main);
    constexpr unsigned int kAllowance{TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS};
    const Consensus::Params params = ParamsWithFork(1);

    Chain base;
    CBlockIndex* fork = base.Add(ST_AUTHENTICATED);
    base.Recompute(params);

    // Losing tip: one authenticated sibling past the fork.
    std::deque<CBlockIndex> losing;
    losing.emplace_back();
    CBlockIndex& lose = losing.back();
    lose.pprev = fork;
    lose.nHeight = fork->nHeight + 1;
    lose.nBits = TEST_NBITS;
    lose.nStatus = ST_AUTHENTICATED;
    lose.nChainWork = fork->nChainWork + GetBlockProof(lose);
    UpdateAuthenticatedChainWork(lose, params);

    // Winning branch: allowance headers of header-only work past the same fork
    // (the production stall was hundreds ahead; allowance blocks is enough).
    std::deque<CBlockIndex> winning;
    CBlockIndex* win = fork;
    for (unsigned int i = 0; i < kAllowance; ++i) {
        winning.emplace_back();
        CBlockIndex& idx = winning.back();
        idx.pprev = win;
        idx.nHeight = win->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = ST_HEADER_ONLY;
        idx.nChainWork = win->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        win = &idx;
    }

    BOOST_CHECK(win->nChainWork > lose.nChainWork);
    BOOST_CHECK(PreferTrustAdjustedHeader(lose, *win, kAllowance));
    BOOST_CHECK(!PreferTrustAdjustedHeader(*win, lose, kAllowance));
}

BOOST_AUTO_TEST_CASE(prefer_trust_adjusted_header_rejects_forged_long_chain)
{
    LOCK(::cs_main);
    const int32_t kFork = 2;
    const Consensus::Params params = ParamsWithFork(kFork);

    // Shared authenticated base through the fork height.
    Chain base;
    for (int i = 0; i < kFork; ++i) base.Add(ST_AUTHENTICATED);
    CBlockIndex* fork = base.Add(ST_AUTHENTICATED);
    base.Recompute(params);

    // Honest tip: many body-authenticated blocks past the fork (deeper than
    // the unauth allowance, so authenticated work alone outranks any forged
    // suffix capped at the allowance).
    std::deque<CBlockIndex> auth_branch;
    CBlockIndex* auth_tip = fork;
    for (int i = 0; i < 40; ++i) {
        auth_branch.emplace_back();
        CBlockIndex& idx = auth_branch.back();
        idx.pprev = auth_tip;
        idx.nHeight = auth_tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        idx.nChainWork = idx.pprev->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        auth_tip = &idx;
    }

    // Forged tip: long header-only suffix (claimed work >> authenticated).
    std::deque<CBlockIndex> forged_branch;
    CBlockIndex* forged_tip = fork;
    for (int i = 0; i < 80; ++i) {
        forged_branch.emplace_back();
        CBlockIndex& idx = forged_branch.back();
        idx.pprev = forged_tip;
        idx.nHeight = forged_tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = BLOCK_VALID_TREE;
        idx.nChainWork = idx.pprev->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        forged_tip = &idx;
    }

    // Raw claimed work prefers the forged tip; trust-adjusted selection must
    // still prefer the genuinely verified branch because unauth credit is capped
    // well below 40 authenticated proofs.
    BOOST_CHECK(forged_tip->nChainWork > auth_tip->nChainWork);
    BOOST_CHECK(PreferTrustAdjustedHeader(*forged_tip, *auth_tip));
    BOOST_CHECK(!PreferTrustAdjustedHeader(*auth_tip, *forged_tip));
}

// On the allowance-capped plateau (both tips have >= allowance unauth headers
// from the same auth ancestor) prefer the shallowest claimed suffix so a
// million-header forged flood cannot pin m_best_header via index iteration.
BOOST_AUTO_TEST_CASE(prefer_trust_adjusted_header_chooses_shallow_capped_tip)
{
    LOCK(::cs_main);
    constexpr unsigned int kAllowance{TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS};
    static_assert(kAllowance > 0);
    const Consensus::Params params = ParamsWithFork(1);

    Chain c;
    CBlockIndex* base = c.Add(ST_AUTHENTICATED);
    c.Recompute(params);

    std::deque<CBlockIndex> suffix;
    CBlockIndex* shallow = nullptr;
    CBlockIndex* tip = base;
    for (unsigned int i = 1; i <= 100; ++i) {
        suffix.emplace_back();
        CBlockIndex& idx = suffix.back();
        idx.pprev = tip;
        idx.nHeight = tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = ST_HEADER_ONLY;
        idx.nChainWork = tip->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        tip = &idx;
        if (i == kAllowance) shallow = tip;
    }

    BOOST_REQUIRE(shallow != nullptr);
    // Both are at the allowance cap → equal adjusted work.
    BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(*shallow, kAllowance).GetHex(),
                      GetTrustAdjustedChainWork(*tip, kAllowance).GetHex());
    // Tie-break: prefer shallower unauth suffix.
    BOOST_CHECK(PreferTrustAdjustedHeader(*tip, *shallow, kAllowance));
    BOOST_CHECK(!PreferTrustAdjustedHeader(*shallow, *tip, kAllowance));
}

// Chase ranking must not become a back-door past PARK. A headers-only branch
// deeper than EMERGENCY park_depth may win PreferTrustAdjustedHeader for chase,
// but ActivateBestChain with PARK still refuses the deep rewrite (covered by
// chainstate_deep_reorg_rejection_prunes_candidate_branch). This unit test pins
// the invariant that allowance == park_depth and that a forged branch beyond
// park_depth still cannot outrank an authenticated tip of park_depth blocks.
BOOST_AUTO_TEST_CASE(allowance_bound_does_not_outrank_park_depth_authenticated)
{
    LOCK(::cs_main);
    constexpr unsigned int kAllowance{TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS};
    constexpr uint32_t kPark =
        kernel::GetReorgProtectionProfileSettings(
            kernel::ReorgProtectionProfile::EMERGENCY)
            .park_depth;
    static_assert(kAllowance == kPark);
    const Consensus::Params params = ParamsWithFork(1);

    Chain base;
    CBlockIndex* fork = base.Add(ST_AUTHENTICATED);
    base.Recompute(params);

    std::deque<CBlockIndex> auth_branch;
    CBlockIndex* auth_tip = fork;
    for (uint32_t i = 0; i < kPark; ++i) {
        auth_branch.emplace_back();
        CBlockIndex& idx = auth_branch.back();
        idx.pprev = auth_tip;
        idx.nHeight = auth_tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = ST_AUTHENTICATED;
        idx.nChainWork = auth_tip->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        auth_tip = &idx;
    }

    std::deque<CBlockIndex> forged_branch;
    CBlockIndex* forged_tip = fork;
    // Deeper than park_depth (and allowance): still capped at allowance proofs.
    for (uint32_t i = 0; i < kPark + 20; ++i) {
        forged_branch.emplace_back();
        CBlockIndex& idx = forged_branch.back();
        idx.pprev = forged_tip;
        idx.nHeight = forged_tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = ST_HEADER_ONLY;
        idx.nChainWork = forged_tip->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        forged_tip = &idx;
    }

    // Equal adjusted work at the allowance/park_depth proof count → prefer the
    // authenticated branch (more authenticated work in the tie-break).
    BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(*auth_tip, kAllowance).GetHex(),
                      GetTrustAdjustedChainWork(*forged_tip, kAllowance).GetHex());
    BOOST_CHECK(PreferTrustAdjustedHeader(*forged_tip, *auth_tip, kAllowance));
    BOOST_CHECK(!PreferTrustAdjustedHeader(*auth_tip, *forged_tip, kAllowance));
}

// DOWNLOAD must use claimed nChainWork, not trust-adjusted work. Geometry:
// authenticated tip deeper than the unauth allowance past the fork, competing
// headers-only branch even deeper. Trust-adjusted(competing) < tip.nChainWork
// (allowance caps at +6), but claimed(competing) > tip.nChainWork. Gating fetch
// on trust-adjusted recreates the stranding deadlock; claimed lets bodies land
// so authentication can catch up. Preference/acceptance still uses trust-adjusted
// (PreferTrustAdjustedHeader below still refuses to rank the forged tip over the
// deep authenticated tip for chase once auth depth >= allowance).
BOOST_AUTO_TEST_CASE(claimed_work_exceeds_tip_while_trust_adjusted_does_not)
{
    LOCK(::cs_main);
    constexpr unsigned int kAllowance{TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS};
    const Consensus::Params params = ParamsWithFork(1);

    Chain base;
    CBlockIndex* fork = base.Add(ST_AUTHENTICATED);
    base.Recompute(params);

    // Authenticated tip: allowance + 4 blocks past the fork (outranks any
    // headers-only suffix on trust-adjusted work alone).
    std::deque<CBlockIndex> auth_branch;
    CBlockIndex* auth_tip = fork;
    for (unsigned int i = 0; i < kAllowance + 4; ++i) {
        auth_branch.emplace_back();
        CBlockIndex& idx = auth_branch.back();
        idx.pprev = auth_tip;
        idx.nHeight = auth_tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = ST_AUTHENTICATED;
        idx.nChainWork = auth_tip->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        auth_tip = &idx;
    }

    // Competing headers-only: deeper still, so claimed work beats the tip.
    std::deque<CBlockIndex> competing;
    CBlockIndex* comp_tip = fork;
    for (unsigned int i = 0; i < kAllowance + 20; ++i) {
        competing.emplace_back();
        CBlockIndex& idx = competing.back();
        idx.pprev = comp_tip;
        idx.nHeight = comp_tip->nHeight + 1;
        idx.nBits = TEST_NBITS;
        idx.nStatus = ST_HEADER_ONLY;
        idx.nChainWork = comp_tip->nChainWork + GetBlockProof(idx);
        UpdateAuthenticatedChainWork(idx, params);
        comp_tip = &idx;
    }

    BOOST_CHECK(comp_tip->nChainWork > auth_tip->nChainWork);
    BOOST_CHECK(GetTrustAdjustedChainWork(*comp_tip, kAllowance) <
                auth_tip->nChainWork);
    // Preference still refuses to let the capped headers-only tip displace the
    // deeper authenticated tip — download policy must not copy this metric.
    BOOST_CHECK(PreferTrustAdjustedHeader(*comp_tip, *auth_tip, kAllowance));
    BOOST_CHECK(!PreferTrustAdjustedHeader(*auth_tip, *comp_tip, kAllowance));
}

BOOST_AUTO_TEST_SUITE_END()
