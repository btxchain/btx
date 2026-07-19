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
// (the routed peer-selection sites are then behavior-identical), give full
// credit to an honest short unauthenticated suffix, and clamp a long forged
// suffix to the allowance above the last authenticated ancestor.
BOOST_AUTO_TEST_CASE(trust_adjusted_work_identity_and_clamp)
{
    LOCK(::cs_main);
    constexpr unsigned int kAllowance{32}; // net_processing's UNAUTH_WORK_ALLOWANCE_BLOCKS

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

    // Post-fork: forged 100-block header-only suffix is clamped to
    // authenticated + kAllowance * W; an honest 10-block suffix keeps full credit.
    {
        const int32_t kFork = 3;
        const Consensus::Params params = ParamsWithFork(kFork);
        Chain c;
        for (int i = 0; i < kFork; ++i) c.Add(ST_AUTHENTICATED); // pre-fork base
        CBlockIndex* last_auth = c.Add(ST_AUTHENTICATED);        // first v4 block, body-verified
        for (int i = 0; i < 100; ++i) c.Add(ST_HEADER_ONLY);     // forged suffix
        c.Recompute(params);

        const CBlockIndex& forged_tip = c.blocks.back();
        const arith_uint256 W = GetBlockProof(forged_tip);
        arith_uint256 allowance{W};
        allowance *= kAllowance;

        // Clamped: authenticated prefix + exactly the allowance.
        BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(forged_tip, kAllowance).GetHex(),
                          (last_auth->nAuthenticatedChainWork + allowance).GetHex());
        BOOST_CHECK(GetTrustAdjustedChainWork(forged_tip, kAllowance) < forged_tip.nChainWork);

        // A suffix shorter than the allowance keeps full claimed credit: block
        // 10 past the last authenticated one has unauth == 10*W <= 32*W.
        const CBlockIndex& shallow = c.blocks[kFork + 1 + 10 - 1]; // 10th header-only block
        BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(shallow, kAllowance).GetHex(),
                          shallow.nChainWork.GetHex());

        // Fully authenticated chains are always identity, post-fork included.
        BOOST_CHECK_EQUAL(GetTrustAdjustedChainWork(*last_auth, kAllowance).GetHex(),
                          last_auth->nChainWork.GetHex());
    }
}

BOOST_AUTO_TEST_SUITE_END()
