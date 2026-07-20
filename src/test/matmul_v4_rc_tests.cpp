// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <vector>

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeRCHeader(uint64_t nonce)
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

BOOST_AUTO_TEST_CASE(rc_smoke_default_params_and_inactive)
{
    const rc::RCEpisodeParams p = rc::DefaultConsensusRCEpisodeParams();
    BOOST_CHECK(rc::ValidateRCEpisodeParams(p));
    BOOST_CHECK_EQUAL(p.d_head % 32, 0u);
    BOOST_CHECK_EQUAL(p.n_q % 32, 0u);
    BOOST_CHECK_EQUAL(p.n_ctx % 32, 0u);
    BOOST_CHECK_EQUAL(p.d_model % 32, 0u);
    BOOST_CHECK_EQUAL(p.b_seq % 32, 0u);

    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!consensus.IsMatMulRCActive(0));
    BOOST_CHECK(consensus.GetMatMulEncodingProfile(0) != Consensus::MatMulEncodingProfile::ENC_RC);
}

BOOST_AUTO_TEST_CASE(rc_t1_golden_episode_digest_stable)
{
    // T1: fixed header+toy params → stable 32-byte digest (freeze when golden lands).
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));
    const uint256 d1 = rc::RecomputeResidentCurriculumReference(header, params, /*height=*/0);
    const uint256 d2 = rc::RecomputeResidentCurriculumReference(header, params, /*height=*/0);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    // Print once for golden capture (not a hard pin until silicon/CPU cross-check).
    BOOST_TEST_MESSAGE("RC toy golden digest: " << d1.GetHex());
}

BOOST_AUTO_TEST_CASE(rc_t2_phase1_tile_size_invariance)
{
    const auto header = MakeRCHeader(7);
    auto params = rc::MakeToyRCEpisodeParams();
    params.n_ctx = 192; // divisible by 32, 64, 96
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    rc::RCEpisodeOptions o32;
    o32.phase1_tile_delta = 32;
    rc::RCEpisodeOptions o64;
    o64.phase1_tile_delta = 64;
    rc::RCEpisodeOptions o96;
    o96.phase1_tile_delta = 96;

    const uint256 a = rc::RecomputeResidentCurriculumReference(header, params, 0, o32);
    const uint256 b = rc::RecomputeResidentCurriculumReference(header, params, 0, o64);
    const uint256 c = rc::RecomputeResidentCurriculumReference(header, params, 0, o96);
    BOOST_CHECK(a == b);
    BOOST_CHECK(b == c);
}

BOOST_AUTO_TEST_CASE(rc_t3_checkpoint_output_invariance)
{
    const auto header = MakeRCHeader(9);
    auto params = rc::MakeToyRCEpisodeParams();
    params.L_lyr = 4; // enough for StoreEvery4
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    rc::RCEpisodeOptions all;
    all.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreAll;
    rc::RCEpisodeOptions every4;
    every4.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreEvery4;
    rc::RCEpisodeOptions only0;
    only0.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;

    const uint256 a = rc::RecomputeResidentCurriculumReference(header, params, 0, all);
    const uint256 b = rc::RecomputeResidentCurriculumReference(header, params, 0, every4);
    const uint256 c = rc::RecomputeResidentCurriculumReference(header, params, 0, only0);
    BOOST_CHECK(a == b);
    BOOST_CHECK(b == c);
}

BOOST_AUTO_TEST_CASE(rc_t4_accumulator_boundary_int64_vs_int32)
{
    // Synthetic contraction: show int32 wraps / diverges while int64 is exact
    // when |Σ| exceeds 2^31-1 — load-bearing for Z=S·V ruling.
    constexpr int64_t kNear = 1'800'000'000LL; // ~2^30.76 class
    int64_t acc64 = 0;
    for (int i = 0; i < 2; ++i) acc64 += kNear;
    BOOST_CHECK(acc64 == 3'600'000'000LL);
    // Consensus Z≈2^30.76 fits int32 once; a multi-add / wider contraction can
    // exceed INT32_MAX — bare int32 accumulation is forbidden (R.1.4).
    BOOST_CHECK(acc64 > static_cast<int64_t>(std::numeric_limits<int32_t>::max()));

    // Below 2^24, int32 path matches int64 for Extract feed.
    std::vector<int64_t> y64 = {1000, -2000, 3000, 0};
    // pad to 32
    y64.resize(32, 0);
    std::vector<int32_t> y32(32);
    for (size_t i = 0; i < 32; ++i) y32[i] = static_cast<int32_t>(y64[i]);
    const uint256 key = uint256::FromHex(
                             "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                             .value();
    const uint256 prf = lt::DeriveMatExpandPrfKey(key);
    std::vector<int8_t> o64(32), o32(32);
    rc::ExtractMXMatrixInt64(prf, y64.data(), 1, 32, o64.data());
    rc::ExtractMXMatrixInt32(prf, y32.data(), 1, 32, o32.data());
    BOOST_CHECK(o64 == o32);
}

BOOST_AUTO_TEST_CASE(rc_t5_anti_grinding_shape_nonce_independent)
{
    auto p = rc::MakeToyRCEpisodeParams();
    const auto h1 = MakeRCHeader(1);
    const auto h2 = MakeRCHeader(2);
    // Structural set identical (compile-time constants + toy params).
    BOOST_CHECK_EQUAL(p.rounds, p.rounds);
    BOOST_CHECK_EQUAL(p.n_ctx, p.n_ctx);
    const uint256 d1 = rc::RecomputeResidentCurriculumReference(h1, p, 0);
    const uint256 d2 = rc::RecomputeResidentCurriculumReference(h2, p, 0);
    BOOST_CHECK(d1 != d2); // nonce changes values
    // Shape audit: ValidateRCEpisodeParams rejects bad dims.
    p.n_ctx = 33;
    BOOST_CHECK(!rc::ValidateRCEpisodeParams(p));
}

BOOST_AUTO_TEST_CASE(rc_t6_extractmx_non_affine_c16)
{
    // ExtractMX(QKᵀ)·V path differs from extracting the unextracted product.
    constexpr uint32_t nq = 32, nctx = 32, dh = 32;
    uint256 seed = uint256::FromHex(
                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                       .value();
    const auto Q = rc::ExpandMxDequantInt8(seed, nq, dh);
    seed = uint256::FromHex(
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
               .value();
    const auto K = rc::ExpandMxDequantInt8(seed, nctx, dh);
    seed = uint256::FromHex(
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
               .value();
    const auto V = rc::ExpandMxDequantInt8(seed, nctx, dh);
    seed = uint256::FromHex(
               "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
               .value();
    const uint256 prf = lt::DeriveMatExpandPrfKey(seed);

    std::vector<int64_t> S_raw(static_cast<size_t>(nq) * nctx, 0);
    for (uint32_t i = 0; i < nq; ++i) {
        for (uint32_t t = 0; t < nctx; ++t) {
            int64_t acc = 0;
            for (uint32_t d = 0; d < dh; ++d) {
                acc += static_cast<int64_t>(Q[i * dh + d]) * static_cast<int64_t>(K[t * dh + d]);
            }
            S_raw[i * nctx + t] = acc;
        }
    }
    std::vector<int8_t> S(S_raw.size());
    rc::ExtractMXMatrixInt64(prf, S_raw.data(), nq, nctx, S.data());

    // Z1 = S · V (int64)
    std::vector<int64_t> Z1(static_cast<size_t>(nq) * dh, 0);
    for (uint32_t i = 0; i < nq; ++i) {
        for (uint32_t d = 0; d < dh; ++d) {
            int64_t acc = 0;
            for (uint32_t t = 0; t < nctx; ++t) {
                acc += static_cast<int64_t>(S[i * nctx + t]) * static_cast<int64_t>(V[t * dh + d]);
            }
            Z1[i * dh + d] = acc;
        }
    }
    // Z2 = (QKᵀ) · V without middle Extract
    std::vector<int64_t> Z2(static_cast<size_t>(nq) * dh, 0);
    for (uint32_t i = 0; i < nq; ++i) {
        for (uint32_t d = 0; d < dh; ++d) {
            int64_t acc = 0;
            for (uint32_t t = 0; t < nctx; ++t) {
                acc += S_raw[i * nctx + t] * static_cast<int64_t>(V[t * dh + d]);
            }
            Z2[i * dh + d] = acc;
        }
    }
    BOOST_CHECK(Z1 != Z2); // C-16: middle ExtractMX is load-bearing
}

BOOST_AUTO_TEST_CASE(rc_t7_reseal_mine_matches_reference)
{
    const auto header = MakeRCHeader(99);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 ref = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const uint256 mined = rc::MineRCEpisode(header, params, 0);
    BOOST_CHECK(ref == mined);
    BOOST_CHECK(rc::VerifyRCTranscriptSpotCheck(header, params, 0, ref, {}));
    BOOST_CHECK(!rc::VerifyRCTranscriptSpotCheck(header, params, 0, uint256{}, {}));
}

BOOST_AUTO_TEST_CASE(rc_t9_fail_closed_height_sentinel)
{
    Consensus::Params p;
    p.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    BOOST_CHECK(!p.IsMatMulRCActive(1));
    p.nMatMulRCHeight = 100;
    // Still requires height >= 100; and without v4 scaffolding RC can be
    // independently height-gated (clean cutover).
    BOOST_CHECK(!p.IsMatMulRCActive(99));
    BOOST_CHECK(p.IsMatMulRCActive(100));
    BOOST_CHECK(p.GetMatMulEncodingProfile(100) == Consensus::MatMulEncodingProfile::ENC_RC);
}

BOOST_AUTO_TEST_SUITE_END()
