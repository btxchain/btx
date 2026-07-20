// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc_coupled.h>

#include <consensus/params.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_coupled_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeCoupHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

} // namespace

BOOST_AUTO_TEST_CASE(rc_coup_inactive_and_constants)
{
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!consensus.IsMatMulRCActive(0));
    BOOST_CHECK_EQUAL(rc::kRCCoupRounds, 4u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobes, 4u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobeWidth, 32u);
    BOOST_CHECK_EQUAL(rc::kRCCoupStateBytes, 128u);
    BOOST_CHECK_EQUAL(rc::kRCCoupBankPages, 8u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobeWidth % 32, 0u);
    BOOST_CHECK_EQUAL(rc::kRCCoupStateBytes % 32, 0u);
}

BOOST_AUTO_TEST_CASE(rc_coup_golden_digest_stable)
{
    // FREEZE toy golden for MakeCoupHeader(42) @ height 0.
    // If the coupled algorithm changes, update this hex deliberately (no silent replace).
    const auto header = MakeCoupHeader(42);
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0);
    const uint256 d2 = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "c9ac99d002ba26105ef259bfc09fbc0e2ad57bae14b9558d68b82719fa811363");
}

BOOST_AUTO_TEST_CASE(rc_coup_mode_equivalence_sequential_vs_checkpointed)
{
    const auto header = MakeCoupHeader(7);
    rc::RCCoupOptions seq;
    seq.mode = rc::RCCoupExecMode::SequentialLobes;
    rc::RCCoupOptions ckpt;
    ckpt.mode = rc::RCCoupExecMode::Checkpointed;
    const uint256 a = rc::RecomputeCoupledPuzzleReference(header, 0, seq);
    const uint256 b = rc::RecomputeCoupledPuzzleReference(header, 0, ckpt);
    BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_CASE(rc_coup_shortcut_skip_barrier_changes_digest)
{
    const auto header = MakeCoupHeader(9);
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0);
    rc::RCCoupOptions bad;
    bad.skip_barrier = true;
    bad.skip_barrier_index = 2;
    const uint256 cheated = rc::RecomputeCoupledPuzzleReference(header, 0, bad);
    BOOST_CHECK(honest != cheated);
}

BOOST_AUTO_TEST_CASE(rc_coup_shortcut_skip_page_changes_digest)
{
    const auto header = MakeCoupHeader(11);
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0);
    rc::RCCoupOptions bad;
    bad.skip_bank_page = true;
    bad.skip_page_index = 3;
    const uint256 cheated = rc::RecomputeCoupledPuzzleReference(header, 0, bad);
    BOOST_CHECK(honest != cheated);
}

BOOST_AUTO_TEST_CASE(rc_coup_balanced_perm_hits_every_index_once)
{
    const auto header = MakeCoupHeader(42);
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    for (uint32_t b = 0; b < rc::kRCCoupRounds; ++b) {
        const auto pi = rc::DeriveCoupledBalancedPermutation(sigma, b);
        BOOST_CHECK(rc::IsBalancedPermutation(pi));
        // Explicit: every output index appears exactly once.
        std::array<int, rc::kRCCoupStateBytes> hits{};
        for (uint32_t i = 0; i < rc::kRCCoupStateBytes; ++i) {
            BOOST_REQUIRE(pi[i] < rc::kRCCoupStateBytes);
            hits[pi[i]] += 1;
        }
        for (uint32_t j = 0; j < rc::kRCCoupStateBytes; ++j) {
            BOOST_CHECK_EQUAL(hits[j], 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(rc_coup_nonce_fresh_digest_differs)
{
    const auto h0 = MakeCoupHeader(100);
    const auto h1 = MakeCoupHeader(101);
    const uint256 d0 = rc::RecomputeCoupledPuzzleReference(h0, 0);
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(h1, 0);
    BOOST_CHECK(d0 != d1);
}

BOOST_AUTO_TEST_SUITE_END()
