// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_mx_layout.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <cuda/matmul_v4_rc_mx_ozaki_native.h>
#include <matmul/matmul_v4_rc_scale.h>
#include <matmul/matmul_v4_rc_scale_axes.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/exact_gemm_resolve.h>
#include <pow.h>
#include <primitives/block.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

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
    // T1: FREEZE ENC_RC_V1 toy golden (MakeToyRCEpisodeParams + MakeRCHeader(42)).
    // V1 stream; kRCSegmentLeavesEnabled=false. Silent replacement forbidden —
    // bump kRCTranscriptVersion / ENC_RC_V1 and keep BOTH goldens for V2
    // (contrib/matmul-v4/rc-golden-gate.py).
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersion, rc::ENC_RC_V1);
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersion, 1u);
    BOOST_CHECK(!rc::kRCSegmentLeavesEnabled);
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

BOOST_AUTO_TEST_CASE(rc_p11_streaming_merkle_equals_full_buffer)
{
    // P1.1: RoundMerkleStream must match BuildTileTreeLeaves/Root byte-for-byte
    // for identical concatenations (including empty, exact T_leaf multiples, and
    // partial final leaves).
    constexpr uint32_t t_leaf = 64;
    auto check_eq = [&](const std::vector<int8_t>& bytes) {
        const auto full_leaves = rc::BuildTileTreeLeaves(bytes, t_leaf);
        const auto full_root = rc::BuildTileTreeRoot(bytes, t_leaf);
        rc::RoundMerkleStream streamed(t_leaf);
        // Absorb in uneven chunks to exercise the partial buffer.
        size_t off = 0;
        const size_t chunks[] = {1, 7, 13, 32, 64, 100, 3};
        size_t ci = 0;
        while (off < bytes.size()) {
            const size_t n = std::min(chunks[ci % 7], bytes.size() - off);
            streamed.Absorb(bytes.data() + off, n);
            off += n;
            ++ci;
        }
        const auto stream_leaves = streamed.FinalizeLeaves();
        BOOST_REQUIRE_EQUAL(stream_leaves.size(), full_leaves.size());
        BOOST_CHECK(stream_leaves == full_leaves);
        rc::RoundMerkleStream streamed2(t_leaf);
        streamed2.Absorb(bytes);
        BOOST_CHECK(streamed2.FinalizeRoot() == full_root);
    };

    check_eq({});
    check_eq(std::vector<int8_t>(t_leaf, 0x11));
    check_eq(std::vector<int8_t>(t_leaf * 3, 0x22));
    check_eq(std::vector<int8_t>(t_leaf * 2 + 17, 0x33));

    // Multi-absorb concatenation equals one-shot over the joined buffer.
    std::vector<int8_t> a(100, 1), b(200, 2), c(50, 3);
    std::vector<int8_t> joined = a;
    joined.insert(joined.end(), b.begin(), b.end());
    joined.insert(joined.end(), c.begin(), c.end());
    rc::RoundMerkleStream parts(t_leaf);
    parts.Absorb(a);
    parts.Absorb(b);
    parts.Absorb(c);
    BOOST_CHECK(parts.FinalizeRoot() == rc::BuildTileTreeRoot(joined, t_leaf));
}

BOOST_AUTO_TEST_CASE(rc_p11_streaming_episode_matches_collected_stream_root)
{
    // Consensus path streams into the Merkle tree; collecting out_rounds must
    // yield the same round_root as BuildTileTreeRoot(stream).
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    std::vector<rc::RCRoundTranscript> rounds;
    const uint256 d = rc::RecomputeResidentCurriculumReference(header, params, 0, {}, &rounds);
    BOOST_REQUIRE(!rounds.empty());
    BOOST_CHECK_EQUAL(d.GetHex(),
                      "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a");
    const uint256 from_buf = rc::BuildTileTreeRoot(rounds[0].stream, params.T_leaf);
    BOOST_CHECK(from_buf == rounds[0].round_root);

    // Checkpoint low-mem path: same digest, and collected stream still matches root.
    rc::RCEpisodeOptions only0;
    only0.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;
    std::vector<rc::RCRoundTranscript> rounds_x0;
    const uint256 d_x0 =
        rc::RecomputeResidentCurriculumReference(header, params, 0, only0, &rounds_x0);
    BOOST_CHECK(d_x0 == d);
    BOOST_REQUIRE(!rounds_x0.empty());
    BOOST_CHECK(rounds_x0[0].stream == rounds[0].stream);
    BOOST_CHECK(rc::BuildTileTreeRoot(rounds_x0[0].stream, params.T_leaf) ==
                rounds_x0[0].round_root);
}

#if defined(__linux__)
BOOST_AUTO_TEST_CASE(rc_p11_toy_peak_rss_bounded)
{
    // Soft bound for the toy episode on Linux (VmHWM). Not a production-dim
    // claim — only guards against accidental multi-GiB retention on toy.
    auto read_vmhwm_kb = []() -> long {
        FILE* f = std::fopen("/proc/self/status", "r");
        if (!f) return -1;
        char line[256];
        long kb = -1;
        while (std::fgets(line, sizeof(line), f)) {
            if (std::sscanf(line, "VmHWM: %ld", &kb) == 1) break;
        }
        std::fclose(f);
        return kb;
    };

    const long before = read_vmhwm_kb();
    const auto header = MakeRCHeader(42);
    auto params = rc::MakeToyRCEpisodeParams();
    // Modest custom shape (still tiny vs consensus): a few layers, 128-wide.
    params.L_lyr = 4;
    params.d_model = 128;
    params.b_seq = 128;
    params.d_head = 64;
    params.n_q = 64;
    params.n_ctx = 128;
    params.T_leaf = 64;
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    rc::RCEpisodeOptions low;
    low.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;
    const uint256 d =
        rc::RecomputeResidentCurriculumReference(header, params, 0, low);
    BOOST_CHECK(!d.IsNull());

    const long after = read_vmhwm_kb();
    BOOST_REQUIRE(before >= 0);
    BOOST_REQUIRE(after >= 0);
    const long delta_kb = after - before;
    BOOST_TEST_MESSAGE("P1.1 toy+modest StoreOnlyX0 VmHWM delta_kb=" << delta_kb
                                                                     << " after_kb=" << after);
    // 512 MiB soft ceiling on delta for this tiny shape — failure means a
    // multi-GiB stream/tensor retention regression, not a production proof.
    BOOST_CHECK_LT(delta_kb, 512L * 1024L);
}
#endif

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

    // P0.5: value > INT32_MAX extracts without int32 truncation.
    {
        std::vector<int64_t> wide(32, 0);
        wide[0] = 3600000000LL;
        wide[1] = -3600000000LL;
        std::vector<int8_t> o_wide(32), o_trunc(32);
        rc::ExtractMXMatrixInt64(prf, wide.data(), 1, 32, o_wide.data());
        std::vector<int64_t> trunc64(32, 0);
        trunc64[0] = static_cast<int32_t>(wide[0]);
        trunc64[1] = static_cast<int32_t>(wide[1]);
        rc::ExtractMXMatrixInt64(prf, trunc64.data(), 1, 32, o_trunc.data());
        BOOST_CHECK(o_wide[0] != o_trunc[0] || o_wide[1] != o_trunc[1]);
        BOOST_CHECK_EQUAL(o_wide[2], o_trunc[2]);
    }

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
    BOOST_CHECK(!d1.IsNull());
    p.n_ctx = 33;
    BOOST_CHECK(!rc::ValidateRCEpisodeParams(p));
    // Malformed dims → REJECT (null digest), never assert/crash.
    BOOST_CHECK(rc::RecomputeResidentCurriculumReference(h1, p, 0).IsNull());
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
    BOOST_CHECK_EQUAL(st.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!st.native_fp8_qualified);
    BOOST_CHECK(!st.deficit_reason.empty());
    BOOST_CHECK(!rc::RCAcceleratorAdmissible(bad));

    // P0.3: bad ExactGemm is used as-is (device replaces CPU). Episode digest
    // must diverge from the CPU oracle — no silent per-GEMM CPU rescue.
    const auto header = MakeRCHeader(1234);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 cpu = rc::MineRCEpisode(header, params, 0);
    const uint256 with_bad = rc::MineRCEpisode(header, params, 0, nullptr, bad);
    BOOST_CHECK(cpu != with_bad);

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
    BOOST_CHECK_EQUAL(good_st.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!good_st.native_fp8_qualified);
    BOOST_CHECK(rc::HasPassedRCSelfQual());
}

BOOST_AUTO_TEST_CASE(rc_f5_selfqual_cached_across_nonce_resolves)
{
    // F5: GateExactGemmWithRCSelfQualCached must invoke ProbeRCSelfQual ≤1× per
    // {provider, gemm_fn, epoch} across an N-nonce-style resolve grind.
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();

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

    const uint64_t before = rc::RCSelfQualProbeInvocationCountForTest();
    constexpr int kNonces = 8;
    lt::ExactGemmBackend last;
    for (int i = 0; i < kNonces; ++i) {
        last = matmul_v4::accel::GateExactGemmWithRCSelfQualCached(good, "test-f5", /*epoch=*/-1);
    }
    const uint64_t after = rc::RCSelfQualProbeInvocationCountForTest();
    BOOST_CHECK_EQUAL(after - before, 1u);
    BOOST_CHECK(last.gemm_s8s8 != nullptr);
    BOOST_CHECK(rc::HasPassedRCSelfQual());

    // Distinct epoch key → second probe allowed (new cache entry).
    (void)matmul_v4::accel::GateExactGemmWithRCSelfQualCached(good, "test-f5", /*epoch=*/7);
    BOOST_CHECK_EQUAL(rc::RCSelfQualProbeInvocationCountForTest() - before, 2u);

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
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
    // Profile 1 = ExactReplay authority (the default is now profile 2 = Freivalds
    // sampled, which requires a stored episode proof; this test exercises the
    // unchanged ExactReplay path).
    p.nMatMulRCProfile = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));
    BOOST_REQUIRE(p.GetMatMulEncodingProfile(kHeight) == Consensus::MatMulEncodingProfile::ENC_RC);

    auto header = MakeRCHeader(42);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();

    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
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

BOOST_AUTO_TEST_CASE(rc_f4_null_committed_digest_rejected)
{
    // F4: RC ExactReplay must REJECT a null header.matmul_digest (coupled already does).
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int32_t kHeight = 10;
    auto header = MakeRCHeader(42);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    const uint256 honest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!honest.IsNull());

    header.matmul_digest = uint256{}; // null committed digest
    BOOST_REQUIRE(header.matmul_digest.IsNull());
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));

    const auto bn = UintToArith256(p.powLimit);
    const auto replay = rc::VerifyBoundedExactReplay(header, params_rc, kHeight, &bn);
    BOOST_CHECK(!replay.ok);
    BOOST_CHECK(replay.note.find("null header.matmul_digest") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rc_tfp4_segmentation_exactness)
{
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCSegLen) * 2304ull < (uint64_t{1} << 62));
    BOOST_CHECK_EQUAL(rc::kRCSegLen % 32, 0u);
    BOOST_CHECK(!rc::kRCSegmentLeavesEnabled);

    {
        const auto header = MakeRCHeader(42);
        const auto toy = rc::MakeToyRCEpisodeParams();
        BOOST_REQUIRE_LT(toy.n_ctx, rc::kRCSegLen);
        std::vector<rc::RCRoundTranscript> rounds;
        const uint256 d = rc::RecomputeResidentCurriculumReference(header, toy, 0, {}, &rounds);
        BOOST_REQUIRE(!rounds.empty());
        const size_t z_bytes = static_cast<size_t>(toy.n_q) * toy.d_head;
        BOOST_REQUIRE_GE(rounds[0].stream.size(), z_bytes);
        BOOST_CHECK_LT(rounds[0].stream.size(), rc::RCSegZBytes(toy) + z_bytes);
        BOOST_CHECK_EQUAL(d.GetHex(), "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a");
    }

    {
        constexpr uint32_t b_seq = 32800;
        constexpr uint32_t d_model = 32;
        std::vector<int8_t> G(static_cast<size_t>(b_seq) * d_model, 3);
        std::vector<int8_t> X(static_cast<size_t>(b_seq) * d_model, 5);
        const auto mono = rc::TestHelperGemmGXtInt64(G, X, b_seq, d_model);
        const auto segs = rc::TestHelperGemmGXtSegmented(G, X, b_seq, d_model);
        BOOST_REQUIRE_EQUAL(segs.size(), 2u);
        std::vector<int64_t> acc(mono.size(), 0);
        for (const auto& seg : segs) {
            for (size_t i = 0; i < acc.size(); ++i) acc[i] += seg[i];
        }
        BOOST_CHECK(acc == mono);
    }
}

// --- §R.7 future-proofing tests (T-FP1..9) ---------------------------------

BOOST_AUTO_TEST_CASE(rc_tfp1_epoch0_reparam_equivalence)
{
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;

    const auto ep0 = rc::ConsensusRCEpisodeParamsForHeight(1, p);
    BOOST_CHECK_EQUAL(ep0.n_ctx, rc::kRCContextLen);
    BOOST_CHECK_EQUAL(ep0.b_seq, rc::kRCBatchSeq);
    BOOST_CHECK_EQUAL(ep0.n_q, rc::kRCQueryRows);
    BOOST_CHECK_EQUAL(ep0.d_head, rc::kRCHeadDim);
    BOOST_CHECK_EQUAL(ep0.d_model, rc::kRCModelDim);
    BOOST_CHECK_EQUAL(ep0.L_lyr, rc::kRCLayers);
    BOOST_CHECK_EQUAL(ep0.rounds, rc::kRCRounds);

    const auto from_scale = rc::EpisodeParamsFromScale({rc::kRCW0Res, rc::kRCW0Cap});
    BOOST_CHECK_EQUAL(from_scale.n_ctx, rc::kRCContextLen);
    BOOST_CHECK_EQUAL(from_scale.b_seq, rc::kRCBatchSeq);
    BOOST_CHECK_EQUAL(from_scale.n_q, rc::kRCQueryRows);

    const auto def = rc::DefaultConsensusRCEpisodeParams();
    BOOST_CHECK_EQUAL(def.n_ctx, rc::kRCContextLen);
    BOOST_CHECK_EQUAL(def.b_seq, rc::kRCBatchSeq);

    // Toy golden T1 path must remain unchanged (digest regression gate).
    const auto header = MakeRCHeader(42);
    const auto toy = rc::MakeToyRCEpisodeParams();
    const uint256 d = rc::RecomputeResidentCurriculumReference(header, toy, /*height=*/0);
    BOOST_CHECK_EQUAL(d.GetHex(),
                      "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a");
}

BOOST_AUTO_TEST_CASE(rc_tfp2_schedule_monotonic_ratchet)
{
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulRCHeight = 100;
    p.nRCScaleEpochBlocks = 10;
    BOOST_CHECK(!rc::kRCGrowthScheduleEnabled);
    for (int32_t epoch = 0; epoch < 12; ++epoch) {
        const int32_t h = p.nMatMulRCHeight + epoch * p.nRCScaleEpochBlocks;
        const auto s = rc::RCScaleForHeight(h, p);
        BOOST_CHECK_EQUAL(s.W_res, rc::kRCW0Res);
        BOOST_CHECK_EQUAL(s.W_cap, rc::kRCW0Cap);
        const auto ep = rc::ConsensusRCEpisodeParamsForHeight(h, p);
        BOOST_CHECK_EQUAL(ep.n_ctx, rc::kRCContextLen);
        BOOST_CHECK_EQUAL(ep.b_seq, rc::kRCBatchSeq);
    }
}

BOOST_AUTO_TEST_CASE(rc_tfp3_derived_dims_mod32)
{
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulRCHeight = 50;
    p.nRCScaleEpochBlocks = 7;

    for (int32_t epoch : {0, 1, 2, 5, 10, 20, 39}) {
        const int32_t h = p.nMatMulRCHeight + epoch * p.nRCScaleEpochBlocks;
        const auto ep = rc::ConsensusRCEpisodeParamsForHeight(h, p);
        BOOST_CHECK_EQUAL(ep.n_ctx % 32, 0u);
        BOOST_CHECK_EQUAL(ep.b_seq % 32, 0u);
        BOOST_CHECK_EQUAL(ep.n_q % 32, 0u);
        BOOST_CHECK_EQUAL(ep.d_head % 32, 0u);
        BOOST_CHECK_EQUAL(ep.d_model % 32, 0u);
    }
}

BOOST_AUTO_TEST_CASE(rc_tfp5_segment_bound_and_fp32_note)
{
    static_assert(2304ull * rc::kRCSegLen < (1ull << 62));
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCSegLen) * 2304ull < (uint64_t{1} << 62));
    // Per-segment 2304·kRCSegLen ≈ 2^26.2 exceeds the FP32 mantissa ceiling (2^24);
    // a naive FP32 accumulate over one full segment diverges unless sub-chunked
    // with kRCWgradExactChunk (2304·4096 < 2^24).
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCSegLen) * 2304ull > (uint64_t{1} << 24));
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCWgradExactChunk) * 2304ull < (uint64_t{1} << 24));
    BOOST_TEST_MESSAGE(
        "T-FP5: FP32/t=24 accumulate over one kRCSegLen segment diverges without "
        "kRCWgradExactChunk sub-chunking (ULP note; int64 reference is exact).");
}

BOOST_AUTO_TEST_CASE(rc_tfp6_brake_skips_or_applies_growth)
{
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulRCHeight = 1000;
    p.nRCScaleEpochBlocks = 100;
    const auto base = rc::RCScaleForHeight(p.nMatMulRCHeight, p);
    const int32_t h1 = p.nMatMulRCHeight + p.nRCScaleEpochBlocks;
    BOOST_CHECK(!rc::kRCGrowthScheduleEnabled);
    const auto paused = rc::RCScaleForHeight(h1, p, [](int32_t) { return false; });
    BOOST_CHECK_EQUAL(paused.W_res, rc::kRCW0Res);
    BOOST_CHECK_EQUAL(paused.W_cap, rc::kRCW0Cap);
    const auto grown = rc::RCScaleForHeight(h1, p, [](int32_t) { return true; });
    BOOST_CHECK_EQUAL(grown.W_res, base.W_res);
    BOOST_CHECK_EQUAL(grown.W_cap, base.W_cap);
    // A3 / F6: BrakeAllowsStep is OMITTED — always allows (never pauses).
    BOOST_CHECK(rc::BrakeAllowsStep(0, p, nullptr));
    BOOST_CHECK(rc::BrakeAllowsStep(99, p, nullptr));
}

BOOST_AUTO_TEST_CASE(rc_tfp7_epoch_assert_fallback_prior)
{
    const auto prior = rc::EpisodeParamsFromScale({rc::kRCW0Res, rc::kRCW0Cap});
    BOOST_REQUIRE(rc::CheckRCEpochInvariants(prior));

    // Zero dials force invariant-fail path → prior_ok returned.
    const auto fell_back = rc::EpisodeParamsFromScale(rc::RCScale{0, 0}, &prior);
    BOOST_CHECK_EQUAL(fell_back.n_ctx, prior.n_ctx);
    BOOST_CHECK_EQUAL(fell_back.b_seq, prior.b_seq);
    BOOST_CHECK_EQUAL(fell_back.n_q, prior.n_q);

    // Without prior, best-effort base epoch-0 shape.
    const auto base = rc::EpisodeParamsFromScale(rc::RCScale{0, 0}, nullptr);
    BOOST_CHECK_EQUAL(base.n_ctx, rc::kRCContextLen);
    BOOST_CHECK(rc::ValidateRCEpisodeParams(base));
}

BOOST_AUTO_TEST_CASE(rc_tfp8_rcscale_pure_deterministic)
{
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulRCHeight = 200;
    p.nRCScaleEpochBlocks = 50;

    for (int32_t epoch = 0; epoch < 8; ++epoch) {
        const int32_t h = p.nMatMulRCHeight + epoch * p.nRCScaleEpochBlocks;
        const auto a = rc::RCScaleForHeight(h, p);
        const auto b = rc::RCScaleForHeight(h, p);
        BOOST_CHECK_EQUAL(a.W_res, b.W_res);
        BOOST_CHECK_EQUAL(a.W_cap, b.W_cap);
    }
}

BOOST_AUTO_TEST_CASE(rc_tfp9_selfqual_tracks_epoch_shape)
{
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;

    const auto live = rc::ConsensusRCEpisodeParamsForHeight(1, p);
    BOOST_CHECK_EQUAL(live.n_ctx, rc::kRCContextLen);

    // Empty backend fail-closes mining (no device ExactGemm).
    const auto st_cpu = rc::ProbeRCSelfQual(lt::ExactGemmBackend{}, /*height=*/1, &p);
    BOOST_CHECK(!st_cpu.mining_accelerator_ok);
    BOOST_CHECK_EQUAL(st_cpu.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!st_cpu.native_fp8_qualified);

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
    const auto st = rc::ProbeRCSelfQual(good, /*height=*/1, &p);
    BOOST_CHECK(st.mining_accelerator_ok);
    BOOST_CHECK(st.exact_gemm_backend_ok);
    BOOST_CHECK_EQUAL(st.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!st.native_fp8_qualified);
}

BOOST_AUTO_TEST_CASE(rc_p12_mx_layout_helpers_row_matches_oracle)
{
    // Row-block packed dequant must match ExpandMxDequantInt8 (digest oracle).
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = static_cast<unsigned char>(0xA0 + i);
    constexpr uint32_t rows = 64;
    constexpr uint32_t cols = 32;
    const auto oracle = rc::ExpandMxDequantInt8(seed, rows, cols);
    const auto packed = rc::ExpandMxPacked(seed, rows, cols, rc::RCMxScaleAxis::RowBlock);
    BOOST_CHECK(rc::DequantMxPacked(packed) == oracle);
    BOOST_CHECK(packed.axis == rc::RCMxScaleAxis::RowBlock);
    BOOST_CHECK_EQUAL(packed.scales.size(), static_cast<size_t>(rows) * (cols / 32));

    // Col-block uses a different scale indexing → generally ≠ row-block dequant.
    const auto col = rc::PrepareMxPackedForValueV(seed, rows, cols);
    BOOST_CHECK(col.axis == rc::RCMxScaleAxis::ColBlock);
    BOOST_CHECK_EQUAL(col.scales.size(), static_cast<size_t>(rows / 32) * cols);
    BOOST_CHECK(rc::DequantMxPacked(col) != oracle);

    BOOST_CHECK(rc::RequiredMxScaleAxis(rc::RCMxGemmStage::Phase1ValueSV, /*left=*/false) ==
                rc::RCMxScaleAxis::ColBlock);
    BOOST_CHECK(rc::RequiredMxScaleAxis(rc::RCMxGemmStage::Phase2Backward, /*left=*/false) ==
                rc::RCMxScaleAxis::ColBlock);
    BOOST_CHECK(rc::RequiredMxScaleAxis(rc::RCMxGemmStage::Phase2Wgrad, /*left=*/true) ==
                rc::RCMxScaleAxis::ColBlock);

    // Packed MX device stub stays fail-closed (no native claim).
    std::vector<int32_t> stub_out;
    BOOST_CHECK(!rc::TryDeviceMxGemmPackedStub(packed, col, rows, cols, cols, stub_out));
    BOOST_CHECK(stub_out.empty());
}

BOOST_AUTO_TEST_CASE(rc_p12_phase2_exactgemm_device_probe)
{
    // Exercises MakeResolvedExactGemmBackendForRC → LaunchGemmS8S8 when a GPU
    // backend is present. Without a device, reports backend_resolved=false and
    // must not claim native MX. Digests are not at risk (CPU oracle path).
    const auto probe = rc::ProbeRCPhase2ExactGemmDevice();
    BOOST_CHECK(!probe.detail.empty());
    if (!probe.backend_resolved) {
        BOOST_CHECK_EQUAL(probe.provider, "cpu");
        BOOST_TEST_MESSAGE("RC Phase-2 ExactGemm device path skipped (no admitted backend): "
                           << probe.detail);
        return;
    }
    if (!probe.device_gemm_returned || !probe.matched_cpu_exactgemm) {
        // Honesty: decline/mismatch must CLEAR provider (never leave "device").
        BOOST_CHECK(probe.provider != "device");
        BOOST_CHECK(probe.provider.empty());
        BOOST_TEST_MESSAGE("RC Phase-2 ExactGemm declined/mismatched: " << probe.detail);
        return;
    }
    BOOST_REQUIRE(probe.device_gemm_returned);
    BOOST_CHECK(probe.matched_cpu_exactgemm);
    BOOST_CHECK(probe.provider != "device");
    BOOST_TEST_MESSAGE("RC Phase-2 ExactGemm device path exercised provider="
                       << probe.provider
                       << " tensor_imma_or_mfma=" << (probe.used_tensor_imma_or_mfma ? 1 : 0));

    // ExactGemm device path alone must not invent native FP8; MXFP4 follows Ozaki latch.
    const auto st = rc::ProbeRCSelfQual(matmul_v4::accel::MakeResolvedExactGemmBackendForRC());
    BOOST_CHECK_EQUAL(st.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!st.native_fp8_qualified);
}

BOOST_AUTO_TEST_CASE(rc_dos_admission_separate_from_v4_lt)
{
    // P0.4: RC must not inherit v4's 1-unit / 16-pending / 4-per-min admission.
    Consensus::Params p;
    p.nMatMulV4Height = 1;
    p.nMatMulBMX4CHeight = 1;
    p.nMatMulDRLTHeight = 1;
    p.fMatMulLTSealAsPoW = false;
    p.nMatMulMaxPendingVerifications = 16;
    p.nMatMulV4GlobalVerifyBudgetPerMin = 4;
    p.nMatMulV4PeerVerifyBudgetPerMin = 2;
    p.nMatMulLTMaxPendingVerifications = 2;
    p.nMatMulLTGlobalVerifyBudgetPerMin = 1;
    p.nMatMulLTPeerVerifyBudgetPerMin = 1;
    p.nMatMulRCMaxPendingVerifications = 1;
    p.nMatMulRCGlobalVerifyBudgetPerMin = 1;
    p.nMatMulRCPeerVerifyBudgetPerMin = 1;

    // Inert while RC height is INT32_MAX.
    BOOST_CHECK(!p.IsMatMulRCActive(100));
    BOOST_CHECK_EQUAL(MatMulRCWorkUnits(p, 100), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCMaxPendingVerifications(p, 100), 0U);
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(p, 100), 2U);
    BOOST_CHECK_EQUAL(MatMulEncDrWorkUnits(p, 100), 1U);

    // Activate RC with toy dims (MAC unit collapses to 1).
    p.nMatMulRCHeight = 50;
    p.fMatMulRCUseToyDims = true;
    BOOST_REQUIRE(p.IsMatMulRCActive(100));
    BOOST_CHECK_EQUAL(MatMulRCWorkUnits(p, 100), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCMaxPendingVerifications(p, 100), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCGlobalVerifyBudgetPerMin(p, 100), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCPeerVerifyBudgetPerMin(p, false, 100), 1U);
    // EncDr/LT pending path stays on its own knobs (not overwritten by RC).
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(p, 100), 2U);

    BOOST_CHECK(CanStartMatMulRCVerification(/*pending=*/0, /*work_units=*/1, p, 100));
    BOOST_CHECK(!CanStartMatMulRCVerification(/*pending=*/1, /*work_units=*/1, p, 100));
    BOOST_CHECK(!CanStartMatMulRCVerification(/*pending=*/0, /*work_units=*/1, p, 49));

    // Consensus dims: work units scale by TotalRCEpisodeMacs / 2^40 (~49 at epoch 0).
    p.fMatMulRCUseToyDims = false;
    Consensus::FillDefaultRCGrowthTables(p);
    const uint32_t wu = MatMulRCWorkUnits(p, 100);
    BOOST_CHECK_GE(wu, 40U);
    BOOST_CHECK_LE(wu, 64U);
    BOOST_CHECK_EQUAL(EffectiveMatMulRCMaxPendingVerifications(p, 100), wu);
    BOOST_CHECK(CanStartMatMulRCVerification(0, wu, p, 100));
    BOOST_CHECK(!CanStartMatMulRCVerification(1, wu, p, 100));
    BOOST_CHECK(!CanStartMatMulRCVerification(0, wu + 1, p, 100));
}

// --- Stage H required-test scaffolding (final-form build spec) -------------

BOOST_AUTO_TEST_CASE(rc_stage_h_v1_golden_preserved)
{
    // H: Preserve V1 golden (segment leaves OFF). Silent replacement forbidden.
    constexpr const char* kV1 =
        "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a";
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 d = rc::RecomputeResidentCurriculumReference(header, params, 0);
    BOOST_CHECK_EQUAL(d.GetHex(), kV1);
    BOOST_CHECK(!rc::kRCSegmentLeavesEnabled);
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight,
                      std::numeric_limits<int32_t>::max());
}

BOOST_AUTO_TEST_CASE(rc_stage_h_resident_checkpointed_streamed_digest_equiv)
{
    // H: Resident (StoreAll) / Checkpointed (StoreEvery4, StoreOnlyX0) /
    // Streamed (phase1 tiles + streaming Merkle) → byte-identical digests.
    // Stage B/C modes map onto today's RCEpisodeOptions + RoundMerkleStream.
    const auto header = MakeRCHeader(11);
    auto params = rc::MakeToyRCEpisodeParams();
    params.L_lyr = 4;
    params.n_ctx = 192;
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    rc::RCEpisodeOptions resident;
    resident.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreAll;
    resident.phase1_tile_delta = 0;

    rc::RCEpisodeOptions checkpointed_every4;
    checkpointed_every4.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreEvery4;
    checkpointed_every4.phase1_tile_delta = 0;

    rc::RCEpisodeOptions checkpointed_x0;
    checkpointed_x0.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;
    checkpointed_x0.phase1_tile_delta = 0;

    rc::RCEpisodeOptions streamed;
    streamed.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;
    streamed.phase1_tile_delta = 40; // non-32 ΔT exercises streamed MX buffer

    const uint256 d_res =
        rc::RecomputeResidentCurriculumReference(header, params, 0, resident);
    const uint256 d_e4 =
        rc::RecomputeResidentCurriculumReference(header, params, 0, checkpointed_every4);
    const uint256 d_x0 =
        rc::RecomputeResidentCurriculumReference(header, params, 0, checkpointed_x0);
    const uint256 d_st =
        rc::RecomputeResidentCurriculumReference(header, params, 0, streamed);
    BOOST_CHECK(d_res == d_e4);
    BOOST_CHECK(d_e4 == d_x0);
    BOOST_CHECK(d_x0 == d_st);

    // Incremental streaming Merkle root ≡ materialized stream root (Stage B sink).
    std::vector<rc::RCRoundTranscript> rounds;
    (void)rc::RecomputeResidentCurriculumReference(header, params, 0, resident, &rounds);
    BOOST_REQUIRE(!rounds.empty());
    BOOST_CHECK(rc::BuildTileTreeRoot(rounds[0].stream, params.T_leaf) ==
                rounds[0].round_root);
}

BOOST_AUTO_TEST_CASE(rc_stage_h_topology_parity_pointer_stage_d)
{
    // H: Topology / device-count / reduction-order parity → Stage D suite.
    // See src/test/matmul_v4_rc_distributed_tests.cpp (landed scaffolding).
    BOOST_CHECK_EQUAL(rc::kRCSegLen % 32, 0u);
    BOOST_CHECK_EQUAL(rc::kRCMxBlockLen, 32u);
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCSegLen) * 2304ull < (uint64_t{1} << 62));
    BOOST_TEST_MESSAGE(
        "Stage H scaffold: topology parity → matmul_v4_rc_distributed_tests (Stage D)");
}

BOOST_AUTO_TEST_CASE(rc_stage_h_memory_budget_soft_streamed)
{
    // H: Soft memory-budget test — Streamed/Checkpointed path completes under
    // toy dims (not a production 8 GiB proof; Stage C toy ≠ HBM-scale).
    const auto header = MakeRCHeader(13);
    auto params = rc::MakeToyRCEpisodeParams();
    params.L_lyr = 4;
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    rc::RCEpisodeOptions streamed;
    streamed.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;
    streamed.phase1_tile_delta = 32;

    const uint256 d =
        rc::RecomputeResidentCurriculumReference(header, params, 0, streamed);
    BOOST_CHECK(!d.IsNull());
    // Soft cap: toy streamed episode must stay well under an 8 GiB host budget.
    // Production-dim proof is Stage G / Stage I gate — not asserted here.
    constexpr uint64_t kSoftToyBudgetBytes = 256ull * 1024 * 1024;
    const uint64_t approx_peak =
        static_cast<uint64_t>(params.b_seq) * params.d_model * 2 + // X[0] + G temps
        static_cast<uint64_t>(params.d_model) * params.d_model +   // W
        static_cast<uint64_t>(params.n_q) * params.d_head * 4;     // Q/KV tiles
    BOOST_CHECK_LT(approx_peak, kSoftToyBudgetBytes);
}

BOOST_AUTO_TEST_CASE(rc_stage_h_golden_diff_gate)
{
    // H: Golden-diff gate — C++ frozen-hex check + required python gate script.
    // CMake also registers `ctest -R rc_golden_gate` so drift fails the build.
    constexpr const char* kV1 =
        "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a";
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    BOOST_CHECK_EQUAL(
        rc::RecomputeResidentCurriculumReference(header, params, 0).GetHex(), kV1);
    BOOST_CHECK(rc::kRCThreeAxisScheduleEnabled);

    // Prefer absolute path via env (set by CI) then relative tree roots.
    const char* env_script = std::getenv("BTX_RC_GOLDEN_GATE");
    std::vector<std::string> candidates;
    if (env_script && env_script[0] != '\0') {
        candidates.emplace_back(env_script);
    }
    candidates.insert(candidates.end(),
                      {"contrib/matmul-v4/rc-golden-gate.py",
                       "../contrib/matmul-v4/rc-golden-gate.py",
                       "../../contrib/matmul-v4/rc-golden-gate.py",
                       "../../../contrib/matmul-v4/rc-golden-gate.py"});

    bool ran = false;
    int last_status = -1;
    for (const auto& script : candidates) {
        // Existence probe via fopen — avoid treating "missing" as drift FAIL.
        FILE* f = std::fopen(script.c_str(), "r");
        if (!f) continue;
        std::fclose(f);
        const std::string cmd =
            std::string("python3 ") + script + " --expect " + kV1;
        last_status = std::system(cmd.c_str());
        ran = true;
        break;
    }
    BOOST_REQUIRE_MESSAGE(ran, "rc-golden-gate.py not found relative to cwd; "
                               "set BTX_RC_GOLDEN_GATE or run from repo root / "
                               "use ctest -R rc_golden_gate");
#if defined(WIFEXITED) && defined(WEXITSTATUS)
    if (WIFEXITED(last_status)) {
        BOOST_CHECK_EQUAL(WEXITSTATUS(last_status), 0);
    } else {
        BOOST_CHECK_MESSAGE(last_status == 0,
                            "rc-golden-gate.py exited abnormally");
    }
#else
    BOOST_CHECK_EQUAL(last_status, 0);
#endif
}

BOOST_AUTO_TEST_CASE(rc_stage_f_three_axis_schedule_configured)
{
    // Stage F: HBM/fabric dials configured; schedule ON (public height still INT32_MAX).
    BOOST_CHECK(rc::kRCThreeAxisScheduleEnabled);
    BOOST_CHECK_EQUAL(rc::kRCAxisW0State, 48ull << 30);
    BOOST_CHECK_EQUAL(rc::kRCAxisX0Exchange, 4ull << 30);
    Consensus::Params p;
    Consensus::FillDefaultRCGrowthTables(p);
    p.nMatMulRCHeight = 100;
    p.nRCScaleEpochBlocks = 10;

    const auto s0 = rc::RCThreeAxisScaleForHeight(100, p);
    BOOST_CHECK_EQUAL(s0.W_state, rc::kRCAxisW0State);
    BOOST_CHECK_EQUAL(s0.C_local, rc::kRCAxisC0Local);
    BOOST_CHECK_EQUAL(s0.X_exchange, rc::kRCAxisX0Exchange);

    // Pre-activation → epoch-0.
    const auto s_pre = rc::RCThreeAxisScaleForHeight(99, p);
    BOOST_CHECK_EQUAL(s_pre.W_state, rc::kRCAxisW0State);

    // Later epochs may grow (pause-only); never shrink below epoch-0.
    const auto s_far = rc::RCThreeAxisScaleForHeight(100 + 39 * 10, p);
    BOOST_CHECK_GE(s_far.W_state, rc::kRCAxisW0State);
    BOOST_CHECK_LE(s_far.W_state, rc::kRCAxisHardCapState);

    // Checked fallback: zero dials → prior_ok, never assert.
    const auto prior = rc::EpisodeParamsFromThreeAxis(s0);
    const auto fell = rc::EpisodeParamsFromThreeAxis(rc::RCThreeAxisScale{0, 0, 0}, &prior);
    BOOST_CHECK_EQUAL(fell.n_ctx, prior.n_ctx);
    BOOST_CHECK_EQUAL(fell.b_seq, prior.b_seq);

    std::string reason;
    BOOST_CHECK(rc::CheckRCThreeAxisInvariants(s0, prior, &reason));
    BOOST_CHECK(reason.empty());
    BOOST_CHECK_LT(rc::EstimateRCStreamedPeakBytes(prior), rc::kRCAxisStreamedPeakHardCap);

    rc::RCThreeAxisScale over = s0;
    over.W_state = rc::kRCAxisHardCapState + 1;
    BOOST_CHECK(!rc::CheckRCThreeAxisInvariants(over, prior, &reason));
    BOOST_CHECK(!reason.empty());
    const auto fell_cap = rc::EpisodeParamsFromThreeAxis(over, &prior);
    BOOST_CHECK_EQUAL(fell_cap.n_ctx, prior.n_ctx);

    // Episode n_ctx stays on the capped proxy (== Class-A context) even when
    // W_state is multi-GiB (HBM bank target ≠ episode matrix inflate).
    const auto ep = rc::ConsensusRCThreeAxisParamsForHeight(1000, p);
    BOOST_CHECK_EQUAL(ep.n_ctx, rc::kRCContextLen);
    BOOST_CHECK_EQUAL(ep.b_seq, rc::kRCBatchSeq);

    // Toy episode golden unchanged (curriculum path independent of coupled levers).
    const auto header = MakeRCHeader(42);
    const auto toy = rc::MakeToyRCEpisodeParams();
    BOOST_CHECK_EQUAL(
        rc::RecomputeResidentCurriculumReference(header, toy, 0).GetHex(),
        "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a");
}

BOOST_AUTO_TEST_CASE(rc_stage_h_extract_extremes_int64)
{
    // H: int64 Extract extreme + negative vectors (no int32 narrow).
    const uint256 key = uint256::FromHex(
                             "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                             .value();
    const uint256 prf = lt::DeriveMatExpandPrfKey(key);

    std::vector<int64_t> extremes(32, 0);
    extremes[0] = std::numeric_limits<int64_t>::max();
    extremes[1] = std::numeric_limits<int64_t>::min();
    extremes[2] = -1;
    extremes[3] = 1;
    extremes[4] = static_cast<int64_t>(std::numeric_limits<int32_t>::max()) + 1;
    extremes[5] = static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1;
    extremes[6] = -(1LL << 40);
    extremes[7] = (1LL << 40);

    std::vector<int8_t> out(32);
    rc::ExtractMXMatrixInt64(prf, extremes.data(), 1, 32, out.data());
    // Deterministic + non-all-zero for extreme inputs (mantissas mixed).
    BOOST_CHECK(std::any_of(out.begin(), out.end(), [](int8_t v) { return v != 0; }));

    // Truncating to int32 before Extract changes at least one extreme lane.
    std::vector<int64_t> trunc(32, 0);
    for (size_t i = 0; i < 32; ++i) {
        trunc[i] = static_cast<int32_t>(extremes[i]);
    }
    std::vector<int8_t> out_trunc(32);
    rc::ExtractMXMatrixInt64(prf, trunc.data(), 1, 32, out_trunc.data());
    BOOST_CHECK(out != out_trunc);
}

BOOST_AUTO_TEST_CASE(rc_stage_h_device_fault_reseal)
{
    // H: device-fault / corrupted ExactGemm → digest diverges; CPU reseal
    // (empty backend) restores the reference oracle.
    lt::ExactGemmBackend bad;
    bad.gemm_s8s8 = &WrongGemmS8S8;
    bad.gemm_s32s8 = &WrongGemmS32S8;
    BOOST_REQUIRE(bad.HasDeviceGemms());

    const auto header = MakeRCHeader(4242);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 cpu = rc::RecomputeResidentCurriculumReference(header, params, 0);
    const uint256 mined_cpu = rc::MineRCEpisode(header, params, 0);
    BOOST_CHECK(cpu == mined_cpu);

    const uint256 mined_bad = rc::MineRCEpisode(header, params, 0, nullptr, bad);
    BOOST_CHECK(mined_bad != cpu); // device fault / corruption visible

    // Reseal path: empty backend recomputes the honest digest (miner must
    // compare before sealing — see SolveMatMulV4RC).
    const uint256 resealed = rc::RecomputeResidentCurriculumReference(header, params, 0);
    BOOST_CHECK(resealed == cpu);
    BOOST_CHECK(resealed != mined_bad);
}

BOOST_AUTO_TEST_CASE(rc_stage_h_production_boundary_ci_safe)
{
    // H: production-size *boundary* tests at CI-safe sizes — segment, MX block,
    // 2^24 chunk rollover, multi-barrier. Not full HBM dims.
    BOOST_CHECK_EQUAL(rc::kRCSegLen % 32, 0u);
    BOOST_CHECK_EQUAL(rc::kRCMxBlockLen, 32u);
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCSegLen) * 2304ull > (uint64_t{1} << 24));
    BOOST_CHECK(static_cast<uint64_t>(rc::kRCWgradExactChunk) * 2304ull < (uint64_t{1} << 24));

    // Segment boundary: n_ctx exactly one / two segments (mod32).
    {
        auto p = rc::MakeToyRCEpisodeParams();
        p.n_ctx = rc::kRCSegLen;
        BOOST_REQUIRE(rc::ValidateRCEpisodeParams(p));
        BOOST_CHECK_EQUAL(rc::RCNumSegs(p.n_ctx), 1u);
        p.n_ctx = rc::kRCSegLen * 2;
        BOOST_REQUIRE(rc::ValidateRCEpisodeParams(p));
        BOOST_CHECK_EQUAL(rc::RCNumSegs(p.n_ctx), 2u);
        const auto header = MakeRCHeader(77);
        const uint256 d1 = rc::RecomputeResidentCurriculumReference(header, p, 0);
        BOOST_CHECK(!d1.IsNull());
    }

    // MX scale-block boundary: cols = 32 and 64 Extract tiles.
    {
        const uint256 key = uint256::FromHex(
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                                 .value();
        const uint256 prf = lt::DeriveMatExpandPrfKey(key);
        for (uint32_t cols : {32u, 64u}) {
            std::vector<int64_t> y(cols, -123456789LL);
            std::vector<int8_t> o(cols);
            rc::ExtractMXMatrixInt64(prf, y.data(), 1, cols, o.data());
            BOOST_CHECK_EQUAL(cols % rc::kRCMxBlockLen, 0u);
            BOOST_CHECK(std::any_of(o.begin(), o.end(), [](int8_t v) { return v != 0; }));
        }
    }

    // 2^24 panel edge via chunked ExactGemm (CI-safe). kRCWgradExactChunk keeps
    // 2304·chunk < 2^24; medium b_seq=8192 (self-qual) is the >2^24 case.
    {
        constexpr uint32_t b_seq = rc::kRCWgradExactChunk;
        constexpr uint32_t d_model = 32;
        BOOST_CHECK_LT(static_cast<uint64_t>(b_seq) * 2304ull, uint64_t{1} << 24);
        std::vector<int8_t> G(static_cast<size_t>(b_seq) * d_model, 7);
        std::vector<int8_t> X(static_cast<size_t>(b_seq) * d_model, 9);
        const auto i64 = rc::TestHelperGemmGXtInt64(G, X, b_seq, d_model);
        const auto chunked = rc::TestHelperGemmGXtViaChunkedExact(G, X, b_seq, d_model);
        BOOST_CHECK(i64 == chunked);
    }

    // Multi-barrier: coupled toy has ≥4 barriers; modes stay digest-equivalent.
    {
        BOOST_CHECK_GE(rc::kRCCoupRounds, 4u);
        CBlockHeader ch;
        ch.nVersion = 0x20000004;
        ch.nTime = 1'770'000'000;
        ch.nBits = 0x207fffff;
        ch.nNonce64 = 88;
        ch.nNonce = 88;
        for (int i = 0; i < 32; ++i) {
            ch.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
            ch.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
            ch.seed_a.data()[i] = static_cast<unsigned char>(0x11);
            ch.seed_b.data()[i] = static_cast<unsigned char>(0x22);
        }
        const uint256 a = rc::RecomputeCoupledPuzzleReference(ch, 0);
        rc::RCCoupOptions streamed;
        streamed.mode = rc::RCCoupExecMode::Streamed;
        const uint256 b = rc::RecomputeCoupledPuzzleReference(ch, 0, streamed);
        BOOST_CHECK(a == b);
        BOOST_CHECK_GE(rc::MakeToyRCCoupParams().barriers, 4u);
    }
}

BOOST_AUTO_TEST_CASE(rc_ozaki_exact_panels_qualify_and_match_oracle)
{
    // ExactGemm K-panel Ozaki must qualify on CPU (and CUDA IMMA when present).
    rc::ResetRcOzakiQualForTest();
    BOOST_REQUIRE(rc::SelfQualifyRcOzakiExactPanelsOnce());
    BOOST_CHECK(rc::IsRcOzakiExactPanelsQualified());

    auto DenseOracle = [](const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                          uint32_t rows, uint32_t inner, uint32_t cols) {
        std::vector<int64_t> dense(static_cast<size_t>(rows) * cols, 0);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t c = 0; c < cols; ++c) {
                int64_t acc = 0;
                for (uint32_t k = 0; k < inner; ++k) {
                    acc += static_cast<int64_t>(L[static_cast<size_t>(r) * inner + k]) *
                           static_cast<int64_t>(R[static_cast<size_t>(k) * cols + c]);
                }
                dense[static_cast<size_t>(r) * cols + c] = acc;
            }
        }
        return dense;
    };

    constexpr uint32_t rows = 8, cols = 8;
    for (uint32_t inner : {8u, 4095u, 4096u, 4097u, 8192u}) {
        std::vector<int8_t> L(static_cast<size_t>(rows) * inner);
        std::vector<int8_t> R(static_cast<size_t>(inner) * cols);
        for (uint32_t i = 0; i < rows * inner; ++i) {
            L[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 13) - 6);
        }
        for (uint32_t i = 0; i < inner * cols; ++i) {
            R[i] = static_cast<int8_t>((static_cast<int32_t>(i * 5) % 11) - 5);
        }
        std::vector<int64_t> out;
        BOOST_REQUIRE(rc::TryRcOzakiExactPanelsGemmS8S8Int64(L, R, rows, inner, cols, out));
        BOOST_CHECK(out == DenseOracle(L, R, rows, inner, cols));
    }

    // Adversarial max ±M11/E8M0 vectors (always, including CPU Exact panels).
    for (uint8_t e : {uint8_t{0}, uint8_t{1}, uint8_t{2}, uint8_t{3}}) {
        const int32_t mag = 6 * (1 << e);
        std::vector<int8_t> L(static_cast<size_t>(rows) * 4096u);
        std::vector<int8_t> R(static_cast<size_t>(4096u) * cols);
        for (size_t i = 0; i < L.size(); ++i) {
            L[i] = static_cast<int8_t>(((i + e) & 1u) ? -mag : mag);
        }
        for (size_t i = 0; i < R.size(); ++i) {
            R[i] = static_cast<int8_t>(((i * 3u + e) & 1u) ? -mag : mag);
        }
        std::vector<int64_t> out;
        BOOST_REQUIRE(rc::TryRcOzakiExactPanelsGemmS8S8Int64(L, R, rows, 4096u, cols, out));
        BOOST_CHECK(out == DenseOracle(L, R, rows, 4096u, cols));
    }

    // Exact panels must not imply native MXFP4 without a real MX device path.
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    BOOST_CHECK(oz.exact_panels_qualified);
    if (!oz.qualified) {
        BOOST_CHECK(!rc::IsRcOzakiMxfp4Qualified());
        std::vector<int8_t> L(64, 1), R(64, 1);
        std::vector<int64_t> oz_out;
        BOOST_CHECK(!rc::TryRcOzakiMxfp4GemmS8S8Int64(L, R, 8, 8, 8, oz_out));
    }

    // Empty ExactGemmBackend probe: mining stay fail-closed, but native_mxfp4
    // still reflects Ozaki TC latch when a real device path qualified.
    const auto st_cpu = rc::ProbeRCSelfQual(lt::ExactGemmBackend{});
    BOOST_CHECK(!st_cpu.mining_accelerator_ok);
    BOOST_CHECK_EQUAL(st_cpu.native_mxfp4_qualified, oz.qualified);
    BOOST_CHECK(!st_cpu.native_fp8_qualified);
}

BOOST_AUTO_TEST_CASE(rc_ozaki_mxfp4_native_gate)
{
    // Native MXFP4: only after THAT backend's COMPLETE suite quals.
    // Selected backend is Unqualified | SM120_MMA | SM100_CUBLASLT — never
    // mislabeled cutlass from hand-MMA, never scalar-decode / dense INT8.
    rc::ResetRcOzakiQualForTest();
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    if (!rc::IsRcOzakiMxfp4Qualified()) {
        BOOST_CHECK(!oz.qualified);
        BOOST_CHECK(oz.attempted);
        BOOST_CHECK_EQUAL(static_cast<int>(oz.selected),
                          static_cast<int>(rc::RCOzakiMxfp4SelectedBackend::Unqualified));
        BOOST_CHECK(!oz.deficit_reason.empty());
        if (oz.backend.find("scalar-decode") != std::string::npos) {
            BOOST_CHECK(oz.deficit_reason.find("scalar-decode") != std::string::npos ||
                        oz.deficit_reason.find("not_native") != std::string::npos);
        }
        BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
        std::vector<int8_t> L(64, 6), R(64, -6);
        std::vector<int64_t> oz_out;
        BOOST_CHECK(!rc::TryRcOzakiMxfp4GemmS8S8Int64(L, R, 8, 8, 8, oz_out));
        BOOST_CHECK(oz_out.empty());
        const auto st_cpu = rc::ProbeRCSelfQual(lt::ExactGemmBackend{});
        BOOST_CHECK_EQUAL(st_cpu.native_mxfp4_qualified, false);
        BOOST_CHECK(!st_cpu.native_fp8_qualified);
        return;
    }
    BOOST_CHECK(oz.attempted);
    BOOST_CHECK(oz.qualified);
    BOOST_CHECK(oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM120_MMA ||
                oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM100_CUBLASLT);
    BOOST_CHECK(oz.backend == "SM120_MMA" || oz.backend == "SM100_CUBLASLT");
    BOOST_CHECK(oz.backend.find("exactgemm") == std::string::npos);
    BOOST_CHECK(oz.backend.find("scalar-decode") == std::string::npos);
    BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
    BOOST_CHECK(oz.arch_key.find("sm_10") != std::string::npos ||
                oz.arch_key.find("sm_12") != std::string::npos);
    if (oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM120_MMA) {
        BOOST_CHECK(oz.arch_key.find("sm_12") != std::string::npos);
        BOOST_CHECK(oz.backend == "SM120_MMA");
    }
    if (oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM100_CUBLASLT) {
        BOOST_CHECK(oz.arch_key.find("sm_10") != std::string::npos);
        BOOST_CHECK(oz.backend == "SM100_CUBLASLT");
    }

    constexpr uint32_t rows = 8, cols = 8;
    static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (uint32_t inner : {1u, 8u, 31u, 32u, 33u, 4095u, 4096u, 4097u, 8192u, 16384u}) {
        std::vector<int8_t> L(static_cast<size_t>(rows) * inner);
        std::vector<int8_t> R(static_cast<size_t>(inner) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t k = 0; k < inner; ++k) {
                const uint8_t e = static_cast<uint8_t>((k / 32u) % 4);
                L[static_cast<size_t>(r) * inner + k] =
                    static_cast<int8_t>(kM11[(r + k) % 11] * (1 << e));
            }
        }
        for (uint32_t k = 0; k < inner; ++k) {
            for (uint32_t c = 0; c < cols; ++c) {
                const uint8_t e = static_cast<uint8_t>((k / 32u + 1) % 4);
                R[static_cast<size_t>(k) * cols + c] =
                    static_cast<int8_t>(kM11[(c + k) % 11] * (1 << e));
            }
        }
        std::vector<int64_t> dense(static_cast<size_t>(rows) * cols, 0);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t c = 0; c < cols; ++c) {
                int64_t acc = 0;
                for (uint32_t k = 0; k < inner; ++k) {
                    acc += static_cast<int64_t>(L[static_cast<size_t>(r) * inner + k]) *
                           static_cast<int64_t>(R[static_cast<size_t>(k) * cols + c]);
                }
                dense[static_cast<size_t>(r) * cols + c] = acc;
            }
        }
        std::vector<int64_t> out;
        BOOST_REQUIRE(rc::TryRcOzakiMxfp4GemmS8S8Int64(L, R, rows, inner, cols, out));
        BOOST_CHECK(out == dense);
        if (!out.empty()) {
            auto bad = out;
            bad[0] += 1;
            BOOST_CHECK(bad != dense);
        }
    }

    const auto st = rc::ProbeRCSelfQual(lt::ExactGemmBackend{});
    BOOST_CHECK(st.native_mxfp4_qualified);
    BOOST_CHECK(!st.native_fp8_qualified);
}

BOOST_AUTO_TEST_CASE(rc_ozaki_mxfp4_scalar_decode_never_sets_native)
{
    // Assessment #4: scalar-decode block-scaled path must not set
    // native_mxfp4_qualified / IsRcOzakiMxfp4Qualified (BMX4C C6 honesty).
    // When a real SM120_MMA / SM100_CUBLASLT path quals, backend must not be
    // scalar-decode and must not claim cutlass for hand MMA.
    rc::ResetRcOzakiQualForTest();
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    BOOST_CHECK(oz.attempted);

    if (oz.backend.find("scalar-decode") != std::string::npos) {
        BOOST_CHECK(!oz.qualified);
        BOOST_CHECK(!rc::IsRcOzakiMxfp4Qualified());
        BOOST_CHECK_EQUAL(static_cast<int>(oz.selected),
                          static_cast<int>(rc::RCOzakiMxfp4SelectedBackend::Unqualified));
        BOOST_CHECK(!oz.deficit_reason.empty());
        BOOST_CHECK(oz.deficit_reason.find("scalar-decode") != std::string::npos ||
                    oz.deficit_reason.find("not_native_tensor") != std::string::npos);
        const auto st = rc::ProbeRCSelfQual(lt::ExactGemmBackend{});
        BOOST_CHECK(!st.native_mxfp4_qualified);
        BOOST_CHECK(!st.native_fp8_qualified);
        std::vector<int8_t> L(64, 1), R(64, 1);
        std::vector<int64_t> out;
        BOOST_CHECK(!rc::TryRcOzakiMxfp4GemmS8S8Int64(L, R, 8, 8, 8, out));
        BOOST_CHECK(out.empty());
        return;
    }

    if (oz.qualified) {
        BOOST_CHECK(rc::IsRcOzakiMxfp4Qualified());
        BOOST_CHECK(oz.backend.find("scalar-decode") == std::string::npos);
        BOOST_CHECK(oz.backend == "SM120_MMA" || oz.backend == "SM100_CUBLASLT");
        BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
        return;
    }

    BOOST_CHECK(!rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK(!oz.deficit_reason.empty());
}

BOOST_AUTO_TEST_CASE(rc_ozaki_mxfp4_selected_backend_honesty)
{
    // Unqualified reporting: deficit present; never cutlass mislabel; never
    // dense INT8 as native MXFP4. Device-pointer / arena APIs fail-closed on stub.
    rc::ResetRcOzakiQualForTest();
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    BOOST_CHECK(oz.attempted);
    if (!oz.qualified) {
        BOOST_CHECK(oz.selected == rc::RCOzakiMxfp4SelectedBackend::Unqualified);
        BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
        BOOST_CHECK(oz.backend.find("exactgemm") == std::string::npos);
    }
#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    BOOST_CHECK(!matmul_v4::cuda::IsRcOzakiCudaCompiled());
    BOOST_CHECK_EQUAL(
        static_cast<int>(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend()),
        static_cast<int>(matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::Unqualified));
    BOOST_CHECK_EQUAL(matmul_v4::cuda::RcOzakiCudaMxfp4NativeTensorLaunchCount(), 0u);
    BOOST_CHECK_EQUAL(matmul_v4::cuda::RcOzakiCudaMxfp4ScalarTailLaunchCount(), 0u);
    std::string err;
    BOOST_CHECK(!matmul_v4::cuda::EnsureRcOzakiMxfp4DeviceArena(64, 64, 8, 8, 16));
    BOOST_CHECK(!matmul_v4::cuda::TryLaunchRcOzakiMxfp4GemmS8S8Int64Device(
        nullptr, nullptr, nullptr, 4, 4, 4, nullptr, &err));
    BOOST_CHECK(!err.empty());
#endif
}

BOOST_AUTO_TEST_CASE(rc_ozaki_sm120_native_capability_cpu_stub)
{
    // PR #89: plain packaging / CPU stub must not advertise SM120_MMA native.
    // Full adversarial suite: matmul_v4_rc_sm120_native_capability_tests.
    rc::ResetRcOzakiQualForTest();
#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    BOOST_CHECK(!matmul_v4::cuda::IsRcOzakiCudaCompiled());
    BOOST_CHECK(!rc::IsRcOzakiMxfp4Qualified());
    BOOST_CHECK_EQUAL(
        static_cast<int>(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend()),
        static_cast<int>(matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::Unqualified));
    const auto st = rc::ProbeRCSelfQual(lt::ExactGemmBackend{});
    BOOST_CHECK(!st.native_mxfp4_qualified);
    BOOST_CHECK(!st.native_fp8_qualified);
#endif
#if !defined(BTX_CUDA_SM120_MXFP4_NATIVE)
    // Without the dedicated sm_120a object option, native SM120_MMA is not a
    // packaging claim — see measure-hardware.sh two-recipe docs.
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    if (oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM120_MMA) {
        BOOST_CHECK(oz.qualified); // latch only after full suite
    } else if (!oz.qualified) {
        BOOST_CHECK_EQUAL(static_cast<int>(oz.selected),
                          static_cast<int>(rc::RCOzakiMxfp4SelectedBackend::Unqualified));
    }
#endif
    Consensus::Params p;
    BOOST_CHECK_EQUAL(p.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
}

BOOST_AUTO_TEST_CASE(rc_ozaki_base4_decomp_total_for_all_int8)
{
    // F4: x = sign(x)·Σ digit_j·2^(2j), digit_j∈{0,1,2,3} — every int8 incl. -128.
    for (int v = -128; v <= 127; ++v) {
        const int8_t x = static_cast<int8_t>(v);
        int8_t one = x;
        std::vector<int8_t> planes[4];
        rc::DecomposeInt8Base4Planes(&one, 1, planes);
        int32_t recon = 0;
        for (uint32_t j = 0; j < 4; ++j) {
            BOOST_REQUIRE_LE(std::abs(static_cast<int>(planes[j][0])), 3);
            recon += static_cast<int32_t>(planes[j][0]) * (1 << (2 * j));
        }
        BOOST_CHECK_EQUAL(recon, v);
    }
}

BOOST_AUTO_TEST_CASE(rc_ozaki_high_scale_mixed_base4_matches_oracle)
{
    // F4 HighScaleMixed: unsafe direct Factor/single-MMA fails; base-4 matches int64.
    constexpr uint32_t rows = 4, cols = 4, inner = 64;
    std::vector<int8_t> L, R;
    rc::FillHighScaleMixedPanels(L, R, rows, inner, cols);
    BOOST_REQUIRE(!rc::RcOzakiOperandsFitMxFastPathAbs(L, R));

    auto Dense = [](const std::vector<int8_t>& L, const std::vector<int8_t>& R, uint32_t rows,
                    uint32_t inner, uint32_t cols) {
        std::vector<int64_t> dense(static_cast<size_t>(rows) * cols, 0);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t c = 0; c < cols; ++c) {
                int64_t acc = 0;
                for (uint32_t k = 0; k < inner; ++k) {
                    acc += static_cast<int64_t>(L[static_cast<size_t>(r) * inner + k]) *
                           static_cast<int64_t>(R[static_cast<size_t>(k) * cols + c]);
                }
                dense[static_cast<size_t>(r) * cols + c] = acc;
            }
        }
        return dense;
    };

    const auto dense = Dense(L, R, rows, inner, cols);
    std::vector<int64_t> base4;
    BOOST_REQUIRE(rc::RcOzakiBase4LimbGemmS8S8Int64(L, R, rows, inner, cols, base4));
    BOOST_CHECK(base4 == dense);

    // Arbitrary int8 (incl. values outside MX alphabet) must also match.
    for (size_t i = 0; i < L.size(); ++i) {
        L[i] = static_cast<int8_t>(static_cast<int32_t>(i * 17u) - 128);
    }
    for (size_t i = 0; i < R.size(); ++i) {
        R[i] = static_cast<int8_t>(127 - static_cast<int32_t>(i * 13u % 256));
    }
    const auto dense2 = Dense(L, R, rows, inner, cols);
    BOOST_REQUIRE(rc::RcOzakiBase4LimbGemmS8S8Int64(L, R, rows, inner, cols, base4));
    BOOST_CHECK(base4 == dense2);

    // Fail-closed until native MXFP4 qualifies (after once-only self-qual).
    rc::ResetRcOzakiQualForTest();
    (void)rc::SelfQualifyRcOzakiMxfp4Once();
    if (!rc::IsRcOzakiMxfp4Qualified()) {
        std::vector<int64_t> oz;
        rc::FillHighScaleMixedPanels(L, R, rows, inner, cols);
        BOOST_CHECK(!rc::TryRcOzakiMxfp4GemmS8S8Int64(L, R, rows, inner, cols, oz));
    } else {
        rc::FillHighScaleMixedPanels(L, R, rows, inner, cols);
        const auto dense3 = Dense(L, R, rows, inner, cols);
        std::vector<int64_t> oz;
        BOOST_REQUIRE(rc::TryRcOzakiMxfp4GemmS8S8Int64(L, R, rows, inner, cols, oz));
        BOOST_CHECK(oz == dense3);
    }
}

BOOST_AUTO_TEST_CASE(rc_wgrad_chunked_exact_matches_medium_shape)
{
    // A4/F10: medium b_seq=8192 exceeds 2^24; chunked ExactGemm == int64 oracle.
    constexpr uint32_t b_seq = 8192;
    constexpr uint32_t d_model = 16;
    BOOST_CHECK_GT(static_cast<uint64_t>(b_seq) * 2304ull, uint64_t{1} << 24);
    std::vector<int8_t> G(static_cast<size_t>(b_seq) * d_model, 48);
    std::vector<int8_t> X(static_cast<size_t>(b_seq) * d_model, -48);
    const auto oracle = rc::TestHelperGemmGXtInt64(G, X, b_seq, d_model);
    const auto chunked = rc::TestHelperGemmGXtViaChunkedExact(G, X, b_seq, d_model);
    BOOST_REQUIRE_EQUAL(oracle.size(), chunked.size());
    BOOST_CHECK(oracle == chunked);
    BOOST_CHECK_GT(std::llabs(oracle[0]), 1LL << 24);

    const auto med = rc::MakeMediumRCEpisodeParams();
    BOOST_CHECK_EQUAL(med.b_seq, 8192u);
    CBlockHeader hdr = MakeRCHeader(7);
    const uint256 cpu = rc::MineRCEpisode(hdr, med, /*height=*/0);
    BOOST_CHECK(!cpu.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
