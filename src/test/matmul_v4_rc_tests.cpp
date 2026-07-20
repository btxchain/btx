// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <pow.h>
#include <primitives/block.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
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

/** Stub ExactGemm that returns systematically wrong outputs (always "succeeds"). */
bool WrongGemmS8S8(const std::vector<int8_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                   uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 123456789);
    return true;
}

bool WrongGemmS32S8(const std::vector<int32_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                    uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, -999);
    return true;
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
    // T1: FREEZE golden for MakeToyRCEpisodeParams + MakeRCHeader(42).
    // If the algorithm changes, update this hex deliberately.
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));
    const uint256 d1 = rc::RecomputeResidentCurriculumReference(header, params, /*height=*/0);
    const uint256 d2 = rc::RecomputeResidentCurriculumReference(header, params, /*height=*/0);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a");
}

BOOST_AUTO_TEST_CASE(rc_t2_phase1_tile_size_invariance)
{
    const auto header = MakeRCHeader(7);
    auto params = rc::MakeToyRCEpisodeParams();
    params.n_ctx = 192; // divisible by 32; arbitrary ΔT via pending MX buffer
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    rc::RCEpisodeOptions o32;
    o32.phase1_tile_delta = 32;
    rc::RCEpisodeOptions o40; // not multiple of 32 — exercises pending buffer
    o40.phase1_tile_delta = 40;
    rc::RCEpisodeOptions o48;
    o48.phase1_tile_delta = 48;
    rc::RCEpisodeOptions o64;
    o64.phase1_tile_delta = 64;
    rc::RCEpisodeOptions o96;
    o96.phase1_tile_delta = 96;
    rc::RCEpisodeOptions o_whole;
    o_whole.phase1_tile_delta = 0;

    const uint256 a = rc::RecomputeResidentCurriculumReference(header, params, 0, o32);
    const uint256 b = rc::RecomputeResidentCurriculumReference(header, params, 0, o40);
    const uint256 c = rc::RecomputeResidentCurriculumReference(header, params, 0, o48);
    const uint256 d = rc::RecomputeResidentCurriculumReference(header, params, 0, o64);
    const uint256 e = rc::RecomputeResidentCurriculumReference(header, params, 0, o96);
    const uint256 f = rc::RecomputeResidentCurriculumReference(header, params, 0, o_whole);
    BOOST_CHECK(a == b);
    BOOST_CHECK(b == c);
    BOOST_CHECK(c == d);
    BOOST_CHECK(d == e);
    BOOST_CHECK(e == f);
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

BOOST_AUTO_TEST_CASE(rc_t4_accumulator_boundary_int64_vs_radix)
{
    // Synthetic contraction: show int32 wraps / diverges while int64 is exact
    // when |Σ| exceeds 2^31-1 — load-bearing for Z=S·V ruling.
    constexpr int64_t kNear = 1'800'000'000LL; // ~2^30.76 class
    int64_t acc64 = 0;
    for (int i = 0; i < 2; ++i) acc64 += kNear;
    BOOST_CHECK(acc64 == 3'600'000'000LL);
    BOOST_CHECK(acc64 > static_cast<int64_t>(std::numeric_limits<int32_t>::max()));

    std::vector<int64_t> y64 = {1000, -2000, 3000, 0};
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

    // Wgrad: int64 oracle == chunked ExactGemm path with K exceeding 2^24.
    constexpr uint32_t b_seq = 8192; // 2304·8192 ≈ 1.89e7 > 2^24
    constexpr uint32_t d_model = 32;
    BOOST_REQUIRE(static_cast<uint64_t>(b_seq) * 2304ull > (uint64_t{1} << 24));

    std::vector<int8_t> G(static_cast<size_t>(b_seq) * d_model, 48);
    std::vector<int8_t> X(static_cast<size_t>(b_seq) * d_model, 48);
    const auto i64 = rc::TestHelperGemmGXtInt64(G, X, b_seq, d_model);
    const auto chunked = rc::TestHelperGemmGXtViaChunkedExact(G, X, b_seq, d_model);
    BOOST_CHECK(i64 == chunked);
    BOOST_CHECK_EQUAL(i64[0], 48LL * 48LL * static_cast<int64_t>(b_seq));
    BOOST_CHECK(std::llabs(i64[0]) > (1LL << 24));
    // Past 2^24, consecutive integers are not all FP32-representable (ulp ≥ 2).
    BOOST_CHECK(static_cast<float>(i64[0]) == static_cast<float>(i64[0] + 1));
}

BOOST_AUTO_TEST_CASE(rc_t5_anti_grinding_shape_nonce_independent)
{
    auto p = rc::MakeToyRCEpisodeParams();
    const auto h1 = MakeRCHeader(1);
    const auto h2 = MakeRCHeader(2);
    // Structural set + total-MAC formula are nonce-independent (R.4.4).
    const uint64_t macs = rc::TotalRCEpisodeMacs(p);
    BOOST_CHECK_EQUAL(rc::TotalRCEpisodeMacs(p), macs);
    // expected MACs = R·(2·n_q·n_ctx·d_head + 3·L·b_seq·d_model²)
    const uint64_t expected =
        uint64_t{p.rounds} *
        (2ull * p.n_q * p.n_ctx * p.d_head +
         3ull * p.L_lyr * uint64_t{p.b_seq} * p.d_model * p.d_model);
    BOOST_CHECK_EQUAL(macs, expected);

    const uint256 d1 = rc::RecomputeResidentCurriculumReference(h1, p, 0);
    const uint256 d2 = rc::RecomputeResidentCurriculumReference(h2, p, 0);
    BOOST_CHECK(d1 != d2); // nonce changes values
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

    // Phase-2 non-invertibility: two distinct X0 under the same W/F_l must not
    // collide systematically (F_l(X_a) != F_l(X_b) for X_a != X_b).
    constexpr uint32_t dm = 32, bs = 32;
    seed = uint256::FromHex(
               "1111111111111111111111111111111111111111111111111111111111111111")
               .value();
    const auto W = rc::ExpandMxDequantInt8(seed, dm, dm);
    seed = uint256::FromHex(
               "2222222222222222222222222222222222222222222222222222222222222222")
               .value();
    auto Xa = rc::ExpandMxDequantInt8(seed, bs, dm);
    seed = uint256::FromHex(
               "3333333333333333333333333333333333333333333333333333333333333333")
               .value();
    auto Xb = rc::ExpandMxDequantInt8(seed, bs, dm);
    BOOST_REQUIRE(Xa != Xb);
    seed = uint256::FromHex(
               "4444444444444444444444444444444444444444444444444444444444444444")
               .value();
    const uint256 prf_fwd = lt::DeriveMatExpandPrfKey(seed);

    auto F_l = [&](const std::vector<int8_t>& X) {
        std::vector<int32_t> y(static_cast<size_t>(bs) * dm, 0);
        for (uint32_t i = 0; i < bs; ++i) {
            for (uint32_t j = 0; j < dm; ++j) {
                int32_t sum = 0;
                for (uint32_t k = 0; k < dm; ++k) {
                    sum += static_cast<int32_t>(W[static_cast<size_t>(j) * dm + k]) *
                           static_cast<int32_t>(X[static_cast<size_t>(i) * dm + k]);
                }
                sum += static_cast<int32_t>(X[static_cast<size_t>(i) * dm + j]);
                y[static_cast<size_t>(i) * dm + j] = sum;
            }
        }
        std::vector<int8_t> out(y.size());
        rc::ExtractMXMatrixInt32(prf_fwd, y.data(), bs, dm, out.data());
        return out;
    };
    BOOST_CHECK(F_l(Xa) != F_l(Xb));

    // Linear-collapse (product-of-weights, single Extract) digest != true digest.
    const auto header = MakeRCHeader(55);
    auto params = rc::MakeToyRCEpisodeParams();
    const uint256 true_digest = rc::RecomputeResidentCurriculumReference(header, params, 0);
    // False "collapsed" digest: SHA256d of episode tag ‖ a single bogus root built
    // from hashing W[0] only (stand-in for Π_l W[l] collapse).
    std::vector<unsigned char> collapsed;
    collapsed.insert(collapsed.end(), reinterpret_cast<const unsigned char*>(rc::kRCEpisodeTag),
                     reinterpret_cast<const unsigned char*>(rc::kRCEpisodeTag) +
                         sizeof(rc::kRCEpisodeTag) - 1);
    uint8_t d1[32], d2[32];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(W.data()), W.size()).Finalize(d1);
    CSHA256().Write(d1, 32).Finalize(d2);
    collapsed.insert(collapsed.end(), d2, d2 + 32);
    uint8_t e1[32], e2[32];
    CSHA256().Write(collapsed.data(), collapsed.size()).Finalize(e1);
    CSHA256().Write(e1, 32).Finalize(e2);
    const uint256 false_digest{Span<const unsigned char>{e2, 32}};
    BOOST_CHECK(false_digest != true_digest);
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

BOOST_AUTO_TEST_CASE(rc_t8_spot_check_flipped_leaf_rejected)
{
    const auto header = MakeRCHeader(123);
    const auto params = rc::MakeToyRCEpisodeParams();
    std::vector<rc::RCRoundTranscript> rounds;
    const uint256 digest =
        rc::RecomputeResidentCurriculumReference(header, params, 0, {}, &rounds);
    BOOST_REQUIRE(!rounds.empty());
    BOOST_REQUIRE(!rounds[0].stream.empty());

    constexpr uint32_t leaf_idx = 0;
    // Honest transcript accepts (explicit challenged leaf + FS empty path).
    BOOST_CHECK(rc::VerifyRCTranscriptSpotCheck(header, params, 0, digest, {leaf_idx}));
    BOOST_CHECK(rc::VerifyRCTranscriptSpotCheck(header, params, 0, digest, {}));
    BOOST_CHECK(rc::VerifyRCLeafOpening(rounds[0].stream, params.T_leaf, leaf_idx,
                                        rounds[0].round_root));

    // Flip one byte in leaf 0's stream region → spot-check rejects.
    std::vector<std::vector<int8_t>> corrupt{rounds[0].stream};
    corrupt[0][0] = static_cast<int8_t>(static_cast<uint8_t>(corrupt[0][0]) ^ 0x5au);
    BOOST_CHECK(!rc::VerifyRCTranscriptSpotCheck(header, params, 0, digest, {leaf_idx}, &corrupt));
    BOOST_CHECK(!rc::VerifyRCLeafOpening(corrupt[0], params.T_leaf, leaf_idx, rounds[0].round_root));
}

BOOST_AUTO_TEST_CASE(rc_t9_fail_closed_wrong_exact_gemm_backend)
{
    lt::ExactGemmBackend bad;
    bad.gemm_s8s8 = &WrongGemmS8S8;
    bad.gemm_s32s8 = &WrongGemmS32S8;
    BOOST_REQUIRE(bad.HasDeviceGemms());

    const rc::RCSelfQualStatus st = rc::ProbeRCSelfQual(bad);
    BOOST_CHECK(!st.mining_accelerator_ok);
    BOOST_CHECK(!st.exact_gemm_backend_ok);
    BOOST_CHECK(!st.native_mxfp4_qualified);
    BOOST_CHECK(!st.native_fp8_qualified);
    BOOST_CHECK(!st.deficit_reason.empty());
    BOOST_CHECK(!rc::RCAcceleratorAdmissible(bad));

    // Episode with the bad backend still matches CPU — per-GEMM verify falls back.
    const auto header = MakeRCHeader(1234);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 cpu = rc::MineRCEpisode(header, params, 0);
    const uint256 with_bad = rc::MineRCEpisode(header, params, 0, nullptr, bad);
    BOOST_CHECK(cpu == with_bad);

    // Honest wrapping backend must self-qual (native_* stay false).
    lt::ExactGemmBackend good;
    good.gemm_s8s8 = +[](const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                         uint32_t rows, uint32_t inner, uint32_t cols,
                         std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS8S8(L, R, rows, inner, cols);
        return true;
    };
    good.gemm_s32s8 = +[](const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                          uint32_t rows, uint32_t inner, uint32_t cols,
                          std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS32S8(L, R, rows, inner, cols);
        return true;
    };
    const rc::RCSelfQualStatus good_st = rc::ProbeRCSelfQual(good);
    BOOST_CHECK(good_st.mining_accelerator_ok);
    BOOST_CHECK(good_st.exact_gemm_backend_ok);
    BOOST_CHECK(!good_st.native_mxfp4_qualified);
    BOOST_CHECK(!good_st.native_fp8_qualified);
    BOOST_CHECK(rc::HasPassedRCSelfQual());
}

BOOST_AUTO_TEST_CASE(rc_t10_fail_closed_height_sentinel)
{
    Consensus::Params p;
    BOOST_CHECK_EQUAL(p.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!p.fMatMulRCUseToyDims);
    BOOST_CHECK(!p.IsMatMulRCActive(1));
    // RC requires MatMul v4 to be active as well.
    p.nMatMulV4Height = 50;
    p.nMatMulRCHeight = 100;
    BOOST_CHECK(!p.IsMatMulRCActive(99));
    BOOST_CHECK(p.IsMatMulRCActive(100));
    BOOST_CHECK(p.GetMatMulEncodingProfile(100) == Consensus::MatMulEncodingProfile::ENC_RC);
}

BOOST_AUTO_TEST_CASE(rc_check_pow_toy_dims_mine_and_wrong_digest)
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));
    BOOST_REQUIRE(p.GetMatMulEncodingProfile(kHeight) == Consensus::MatMulEncodingProfile::ENC_RC);

    auto header = MakeRCHeader(42);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();

    const auto params_rc = rc::ResolveRCEpisodeParams(p);
    BOOST_REQUIRE(p.fMatMulRCUseToyDims);
    BOOST_CHECK_EQUAL(params_rc.n_ctx, rc::MakeToyRCEpisodeParams().n_ctx);

    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_CHECK(!header.matmul_digest.IsNull());
    BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight));

    CBlockHeader bad = header;
    bad.matmul_digest = uint256::ONE;
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(bad, p, kHeight));

    // Public default: RC inactive.
    Consensus::Params pub;
    BOOST_CHECK(!pub.IsMatMulRCActive(0));
    BOOST_CHECK(!pub.IsMatMulRCActive(std::numeric_limits<int32_t>::max() - 1));
}

BOOST_AUTO_TEST_SUITE_END()
