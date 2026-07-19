// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_lt.h>
#include <matmul/accel_v4.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <cuda/matmul_v4_lt_accel.h>
#include <hip/matmul_v4_lt_accel.h>
#include <metal/matmul_v4_lt_accel.h>
#include <pow.h>
#include <primitives/block.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace lt = matmul::v4::lt;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_lt_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 64;

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeLTHeader(uint64_t nonce, uint32_t n)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.hashPrevBlock = ParseUint256("5151515151515151515151515151515151515151515151515151515151515151");
    header.hashMerkleRoot = ParseUint256("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.seed_b = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");
    return header;
}

// Device-backend stand-ins for the MatExpand GEMMs. The "mock" pair wraps the
// CPU ExactGemm* reference bit-for-bit (a device backend MUST reproduce it), so
// routing through it MUST leave every digest byte-identical. The "fail" pair
// returns false to exercise the CPU fallback contract.
int g_mock_s8s8_calls = 0;
int g_mock_s32s8_calls = 0;

bool MockGemmS8S8(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                  uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    ++g_mock_s8s8_calls;
    out = lt::ExactGemmS8S8(L, R, rows, inner, cols);
    return true;
}

bool MockGemmS32S8(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                   uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    ++g_mock_s32s8_calls;
    out = lt::ExactGemmS32S8(L, R, rows, inner, cols);
    return true;
}

bool FailGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                  uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool FailGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                   uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

} // namespace

BOOST_AUTO_TEST_CASE(fold_int32_to_emax48_range)
{
    // Legacy linear fold — non-normative; retained for differential tests.
    for (int32_t y = -5000; y <= 5000; y += 97) {
        const int32_t v = lt::FoldInt32ToEmax48(y);
        BOOST_CHECK(v >= -48 && v <= 48);
    }
    BOOST_CHECK_EQUAL(lt::FoldInt32ToEmax48(0), -48);
    BOOST_CHECK_EQUAL(lt::FoldInt32ToEmax48(48), 0);
    BOOST_CHECK_EQUAL(lt::FoldInt32ToEmax48(96), 48);
}

BOOST_AUTO_TEST_CASE(matexpand_extract_range_and_determinism)
{
    constexpr uint64_t salt = 0xC0FFEEULL;
    for (int32_t raw = -2000; raw <= 2000; raw += 17) {
        const int8_t a = lt::ExtractDequantMatExpand(raw, 3, 5, salt);
        const int8_t b = lt::ExtractDequantMatExpand(raw, 3, 5, salt);
        BOOST_CHECK_EQUAL(a, b);
        BOOST_CHECK(a >= -48 && a <= 48);
    }
}

BOOST_AUTO_TEST_CASE(matexpand_not_affine_in_raw)
{
    // Linear fold satisfies f(x+d)-f(x) period structure; Mix+M11 Extract must not
    // coincide with Fold on a dense sample (non-collapse witness).
    constexpr uint64_t salt = 0xA5A5A5A5ULL;
    int disagreements = 0;
    for (int32_t y = -500; y <= 500; ++y) {
        if (lt::ExtractDequantMatExpand(y, 0, 0, salt) !=
            static_cast<int8_t>(lt::FoldInt32ToEmax48(y))) {
            ++disagreements;
        }
    }
    BOOST_CHECK(disagreements > 100);

    // Homogeneity collapse f(2x)=2f(x) must fail for a non-zero sample point.
    bool homogeneity_broken = false;
    for (int32_t x = 1; x <= 200; ++x) {
        const int8_t fx = lt::ExtractDequantMatExpand(x, 1, 2, salt);
        const int8_t f2x = lt::ExtractDequantMatExpand(2 * x, 1, 2, salt);
        if (fx != 0 && f2x != static_cast<int8_t>(2 * fx)) {
            homogeneity_broken = true;
            break;
        }
    }
    BOOST_CHECK(homogeneity_broken);
}

BOOST_AUTO_TEST_CASE(matexpand_position_salt_differential)
{
    constexpr uint64_t salt = 0x1234567890ABCDEFULL;
    const int32_t raw = 42;
    BOOST_CHECK(lt::ExtractDequantMatExpand(raw, 0, 0, salt) !=
                    lt::ExtractDequantMatExpand(raw, 1, 0, salt) ||
                lt::MixMatExpandEntry(raw, 0, 0, salt) !=
                    lt::MixMatExpandEntry(raw, 1, 0, salt));
    BOOST_CHECK(lt::MixMatExpandEntry(raw, 0, 0, salt) !=
                lt::MixMatExpandEntry(raw, 0, 1, salt));
    BOOST_CHECK(lt::MixMatExpandEntry(raw, 0, 0, salt) !=
                lt::MixMatExpandEntry(raw, 0, 0, salt ^ 1));
}

BOOST_AUTO_TEST_CASE(plan_lt_accel_known_classes)
{
    const auto b200 = lt::PlanLTAccel("b200");
    BOOST_CHECK(b200.projection == matmul::v4::bmx4::ProjectionLane::ScalePartitionedMxfp4);
    const auto cpu = lt::PlanLTAccel("cpu");
    BOOST_CHECK(cpu.projection == matmul::v4::bmx4::ProjectionLane::CanonicalInt8);
}

BOOST_AUTO_TEST_CASE(accel_dispatch_matches_reference)
{
    auto header = MakeLTHeader(21, kTestDim);
    std::vector<CBlockHeader> headers{header};
    std::vector<uint256> digests;
    std::vector<std::vector<unsigned char>> payloads;
    BOOST_REQUIRE(matmul_v4::accel::ComputeDigestsBMX4CLTDispatched(
        headers, kTestDim, /*rounds=*/2, uint256::ONE, digests, payloads));
    BOOST_REQUIRE_EQUAL(digests.size(), 1U);
    BOOST_REQUIRE_EQUAL(payloads.size(), 1U);
    uint256 ref;
    std::vector<unsigned char> ref_payload;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, ref, ref_payload));
    BOOST_CHECK(digests[0] == ref);
    BOOST_CHECK(payloads[0] == ref_payload);
}

BOOST_AUTO_TEST_CASE(qstar_128_seal_distinct)
{
    BOOST_CHECK(lt::IsValidConsensusQStar(128));
    std::vector<uint256> digests(128);
    for (size_t i = 0; i < digests.size(); ++i) {
        unsigned char b[32]{};
        b[0] = static_cast<unsigned char>(i);
        b[1] = static_cast<unsigned char>(i >> 8);
        digests[i] = uint256{Span<const unsigned char>{b, sizeof(b)}};
    }
    const uint256 root = lt::ComputeWindowMerkleRoot(digests);
    const uint256 sigma = ParseUint256(
        "3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK(lt::SealWindowCommit(sigma, root, 128) !=
                lt::SealWindowCommit(sigma, root, 64));
}

BOOST_AUTO_TEST_CASE(matexpand_a_template_invariant_b_nonce_fresh)
{
    auto h0 = MakeLTHeader(1, kTestDim);
    auto h1 = MakeLTHeader(2, kTestDim);
    BOOST_CHECK(lt::ExpandOperandAMatExpand(h0, kTestDim) ==
                lt::ExpandOperandAMatExpand(h1, kTestDim));
    BOOST_CHECK(lt::ExpandOperandBMatExpand(h0, kTestDim) !=
                lt::ExpandOperandBMatExpand(h1, kTestDim));
}

BOOST_AUTO_TEST_CASE(digest_determinism_and_nonce_sensitivity)
{
    auto header = MakeLTHeader(7, kTestDim);
    uint256 d1, d2;
    std::vector<unsigned char> p1, p2;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, d1, p1));
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, d2, p2));
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(p1 == p2);

    header.nNonce64 = 8;
    header.nNonce = 8;
    uint256 d3;
    std::vector<unsigned char> p3;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, d3, p3));
    BOOST_CHECK(d1 != d3);
}

BOOST_AUTO_TEST_CASE(verify_accepts_compute_digest)
{
    auto header = MakeLTHeader(9, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, digest, payload));
    header.matmul_digest = digest;
    uint256 vout;
    BOOST_CHECK(lt::VerifySketchBMX4CLT(header, kTestDim, 2, payload, vout));
    BOOST_CHECK(vout == digest);
}

BOOST_AUTO_TEST_CASE(window_merkle_and_seal)
{
    std::vector<uint256> digests;
    for (int i = 0; i < 4; ++i) {
        char hex[65];
        for (int j = 0; j < 64; ++j) hex[j] = "0123456789abcdef"[(i + j) % 16];
        hex[64] = 0;
        digests.push_back(ParseUint256(hex));
    }
    const uint256 root = lt::ComputeWindowMerkleRoot(digests);
    BOOST_CHECK(!root.IsNull());
    const uint256 sigma = ParseUint256(
        "3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK(lt::SealWindowCommit(sigma, root, 64) !=
                lt::SealWindowCommit(sigma, root, 128));
    BOOST_CHECK(lt::IsValidConsensusQStar(64));
    BOOST_CHECK(!lt::IsValidConsensusQStar(32));
}

BOOST_AUTO_TEST_CASE(window_miner_matches_reference)
{
    auto tmpl = MakeLTHeader(0, kTestDim);
    lt::WindowSketchMinerLT miner{tmpl, kTestDim};
    BOOST_REQUIRE(miner.Valid());
    const std::vector<uint64_t> nonces{11, 12, 13};
    std::vector<lt::DigestOnlyResultLT> results;
    BOOST_REQUIRE(miner.Mine(nonces, uint256::ONE, results, nullptr));
    BOOST_REQUIRE_EQUAL(results.size(), nonces.size());
    for (size_t i = 0; i < nonces.size(); ++i) {
        auto h = tmpl;
        h.nNonce64 = nonces[i];
        h.nNonce = static_cast<uint32_t>(nonces[i]);
        uint256 ref;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(h, kTestDim, ref, payload));
        BOOST_CHECK(results[i].digest == ref);
    }
}

BOOST_AUTO_TEST_CASE(exact_gemm_backend_mock_matches_cpu)
{
    // Injectable backend that wraps ExactGemm* must be byte-identical to the
    // default CPU path (the contract device backends must also satisfy).
    lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = +[](const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                            uint32_t rows, uint32_t inner, uint32_t cols,
                            std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS8S8(L, R, rows, inner, cols);
        return true;
    };
    backend.gemm_s32s8 = +[](const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                             uint32_t rows, uint32_t inner, uint32_t cols,
                             std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS32S8(L, R, rows, inner, cols);
        return true;
    };
    BOOST_CHECK(backend.HasDeviceGemms());

    auto h = MakeLTHeader(42, kTestDim);
    uint256 cpu_d, backend_d;
    std::vector<unsigned char> cpu_p, backend_p;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(h, kTestDim, cpu_d, cpu_p));
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(h, kTestDim, backend, backend_d, backend_p));
    BOOST_CHECK(cpu_d == backend_d);
    BOOST_CHECK(cpu_p == backend_p);

    lt::WindowSketchMinerLT miner{h, kTestDim, backend};
    BOOST_REQUIRE(miner.Valid());
    BOOST_CHECK(miner.UsingDeviceGemms());
    std::vector<lt::DigestOnlyResultLT> results;
    BOOST_REQUIRE(miner.Mine({42}, uint256::ONE, results, nullptr));
    BOOST_REQUIRE_EQUAL(results.size(), 1U);
    BOOST_CHECK(results[0].digest == cpu_d);
}

BOOST_AUTO_TEST_CASE(exact_gemm_backend_default_matches_cpu)
{
    // A default-constructed (all-nullptr) backend MUST be the CPU reference.
    auto header = MakeLTHeader(31, kTestDim);
    uint256 ref_d, be_d;
    std::vector<unsigned char> ref_p, be_p;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, ref_d, ref_p));
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, lt::ExactGemmBackend{}, be_d, be_p));
    BOOST_CHECK(be_d == ref_d);
    BOOST_CHECK(be_p == ref_p);

    // Operand expansion via the empty backend is byte-identical too.
    const lt::ExactGemmBackend cpu{};
    BOOST_CHECK(lt::ExpandOperandAMatExpand(header, kTestDim) ==
                lt::ExpandOperandAMatExpand(header, kTestDim, cpu));
    BOOST_CHECK(lt::ExpandOperandBMatExpand(header, kTestDim) ==
                lt::ExpandOperandBMatExpand(header, kTestDim, cpu));
}

BOOST_AUTO_TEST_CASE(exact_gemm_backend_mock_matches_reference)
{
    // A mock device backend that wraps ExactGemm* bit-for-bit must produce the
    // exact same digest / payload as the pure-CPU default path, and both GEMM
    // stages (s8s8 for G*W, s32s8 for (G*W)*H) must actually be invoked.
    auto header = MakeLTHeader(42, kTestDim);
    uint256 ref_d, mock_d;
    std::vector<unsigned char> ref_p, mock_p;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, ref_d, ref_p));

    lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &MockGemmS8S8;
    backend.gemm_s32s8 = &MockGemmS32S8;
    BOOST_CHECK(backend.HasDeviceGemms());

    g_mock_s8s8_calls = 0;
    g_mock_s32s8_calls = 0;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, backend, mock_d, mock_p));
    BOOST_CHECK(mock_d == ref_d);
    BOOST_CHECK(mock_p == ref_p);
    BOOST_CHECK(g_mock_s8s8_calls > 0);
    BOOST_CHECK(g_mock_s32s8_calls > 0);
}

BOOST_AUTO_TEST_CASE(exact_gemm_backend_falls_back_on_false)
{
    // A backend whose GEMMs always report failure must transparently fall back
    // to the CPU reference and still yield the identical digest.
    auto header = MakeLTHeader(43, kTestDim);
    uint256 ref_d, fb_d;
    std::vector<unsigned char> ref_p, fb_p;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, ref_d, ref_p));

    lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &FailGemmS8S8;
    backend.gemm_s32s8 = &FailGemmS32S8;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, backend, fb_d, fb_p));
    BOOST_CHECK(fb_d == ref_d);
    BOOST_CHECK(fb_p == ref_p);
}

BOOST_AUTO_TEST_CASE(exact_gemm_backend_partial_slot_matches)
{
    // Only one slot supplied: the other stage falls back to CPU. Result must
    // still match the all-CPU reference regardless of which slot is device-driven.
    auto header = MakeLTHeader(44, kTestDim);
    uint256 ref_d;
    std::vector<unsigned char> ref_p;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, ref_d, ref_p));

    lt::ExactGemmBackend only_s8s8;
    only_s8s8.gemm_s8s8 = &MockGemmS8S8;
    uint256 d1;
    std::vector<unsigned char> p1;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, only_s8s8, d1, p1));
    BOOST_CHECK(d1 == ref_d);
    BOOST_CHECK(p1 == ref_p);

    lt::ExactGemmBackend only_s32s8;
    only_s32s8.gemm_s32s8 = &MockGemmS32S8;
    uint256 d2;
    std::vector<unsigned char> p2;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, only_s32s8, d2, p2));
    BOOST_CHECK(d2 == ref_d);
    BOOST_CHECK(p2 == ref_p);
}

BOOST_AUTO_TEST_CASE(window_miner_backend_matches_reference)
{
    // WindowSketchMinerLT driven by the mock device backend must reproduce the
    // pure-CPU miner (and hence ComputeDigestBMX4CLT) for every nonce.
    auto tmpl = MakeLTHeader(0, kTestDim);
    const std::vector<uint64_t> nonces{101, 102, 103};

    lt::WindowSketchMinerLT cpu_miner{tmpl, kTestDim};
    BOOST_REQUIRE(cpu_miner.Valid());
    BOOST_CHECK(!cpu_miner.UsingDeviceGemms());
    std::vector<lt::DigestOnlyResultLT> cpu_res;
    BOOST_REQUIRE(cpu_miner.Mine(nonces, uint256::ONE, cpu_res, nullptr));

    lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &MockGemmS8S8;
    backend.gemm_s32s8 = &MockGemmS32S8;
    lt::WindowSketchMinerLT dev_miner{tmpl, kTestDim, backend};
    BOOST_REQUIRE(dev_miner.Valid());
    BOOST_CHECK(dev_miner.UsingDeviceGemms());
    std::vector<lt::DigestOnlyResultLT> dev_res;
    BOOST_REQUIRE(dev_miner.Mine(nonces, uint256::ONE, dev_res, nullptr));

    BOOST_REQUIRE_EQUAL(cpu_res.size(), dev_res.size());
    for (size_t i = 0; i < nonces.size(); ++i) {
        BOOST_CHECK(dev_res[i].digest == cpu_res[i].digest);
    }
}

BOOST_AUTO_TEST_CASE(phase_b_seal_round_trip_and_auth)
{
    // Phase B seal helpers: ε=0 seal matches Freivalds seal-auth; wrong merkle
    // / mutated payload fails commitment match. Slot seeds are identity (copy
    // template seeds) so the test does not need chain MTP.
    auto anchor = MakeLTHeader(7, kTestDim);
    const auto seed_fn = [](CBlockHeader& /*h*/) -> bool { return true; };
    constexpr uint32_t Q = 64; // use full consensus Q* for correctness; slowish at n=64

    uint256 seal;
    std::vector<lt::WindowSlot> slots;
    std::vector<std::vector<unsigned char>> payloads;
    BOOST_REQUIRE(lt::ComputeSealDigestBMX4CLT(anchor, kTestDim, Q, seed_fn, seal, &slots, &payloads));
    BOOST_CHECK(!seal.IsNull());
    BOOST_REQUIRE_EQUAL(slots.size(), Q);
    BOOST_REQUIRE_EQUAL(payloads.size(), Q);

    // Slot nonces are deterministic from sigma.
    const uint256 sigma = matmul::v4::DeriveSigma(anchor);
    for (uint32_t j = 0; j < Q; ++j) {
        BOOST_CHECK_EQUAL(slots[j].nonce, lt::DeriveWindowSlotNonce(sigma, j));
    }

    uint256 seal_fv;
    BOOST_REQUIRE(lt::VerifySealWindowFreivalds(anchor, kTestDim, Q, /*rounds=*/8, seed_fn,
                                                payloads, seal_fv));
    BOOST_CHECK(seal_fv == seal);

    anchor.matmul_digest = seal;
    BOOST_CHECK(lt::SealWindowProofMatchesCommitment(anchor, kTestDim, Q, seed_fn, payloads));

    // Mutate one payload byte → commitment mismatch.
    auto bad = payloads;
    BOOST_REQUIRE(!bad[0].empty());
    bad[0][0] ^= 0x01;
    BOOST_CHECK(!lt::SealWindowProofMatchesCommitment(anchor, kTestDim, Q, seed_fn, bad));

    // Wrong Q* rejected.
    uint256 junk;
    BOOST_CHECK(!lt::ComputeSealDigestBMX4CLT(anchor, kTestDim, /*Qstar=*/32, seed_fn, junk));
}

BOOST_AUTO_TEST_CASE(phase_b_seal_parent_mtp_slot_seeds_and_encdr)
{
    // EncDr seal recompute with parent-MTP-threaded V3 seeds (LT-Q2): changing
    // MTP must change the seal; missing MTP fails closed; digest matches the
    // library ComputeSealDigestBMX4CLT under the same SlotSeedFn.
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulBMX4CHeight = 1;
    p.nMatMulDRLTHeight = 1;
    p.nMatMulV4Dimension = kTestDim;
    p.nMatMulConsensusQStar = 64;
    p.nMatMulLTTranscriptBlockSize = 2;
    p.fMatMulLTSealAsPoW = true;
    p.nMatMulV4FreivaldsRounds = 8;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr int32_t kHeight = 10;
    constexpr int64_t kMtp = 1'700'000'000;
    BOOST_REQUIRE(p.IsMatMulLTSealAsPoWActive(kHeight));

    auto anchor = MakeLTHeader(11, kTestDim);
    anchor.nBits = UintToArith256(p.powLimit).GetCompact();
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(anchor, p, kHeight, kMtp));

    const auto slot_seed = [&](CBlockHeader& h) -> bool {
        return SetDeterministicMatMulSeeds(h, p, kHeight, kMtp);
    };

    uint256 seal;
    BOOST_REQUIRE(lt::ComputeSealDigestBMX4CLT(anchor, kTestDim, 64, slot_seed, seal));
    anchor.matmul_digest = seal;

    // Library seal == EncDr reference recompute.
    uint256 recomputed;
    std::vector<unsigned char> sketch;
    BOOST_REQUIRE(RecomputeMatMulV4SketchReference(anchor, p, kHeight, recomputed, sketch, kMtp));
    BOOST_CHECK(recomputed == seal);
    BOOST_CHECK(sketch.empty()); // seal mode leaves no Phase-A Chat payload

    // Missing MTP fails closed.
    uint256 no_mtp;
    BOOST_CHECK(!RecomputeMatMulV4SketchReference(anchor, p, kHeight, no_mtp, sketch, std::nullopt));

    CBlock block;
    static_cast<CBlockHeader&>(block) = anchor;
    BOOST_CHECK(CheckMatMulProofOfWork_V4EncDr(block, p, kHeight, kMtp));
    BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(block, p, kHeight, std::nullopt));

    // Different parent MTP ⇒ different sibling seeds ⇒ different seal.
    const auto slot_seed_other = [&](CBlockHeader& h) -> bool {
        return SetDeterministicMatMulSeeds(h, p, kHeight, kMtp + 1);
    };
    uint256 seal_other;
    BOOST_REQUIRE(lt::ComputeSealDigestBMX4CLT(anchor, kTestDim, 64, slot_seed_other, seal_other));
    BOOST_CHECK(seal_other != seal);
}

BOOST_AUTO_TEST_CASE(matexpand_additivity_noncollapse)
{
    // Linear fold satisfies f(x)+f(y) ≈ f(x+y) on a large fraction of samples;
    // Mix+M11 Extract must break additivity often enough to witness non-collapse.
    constexpr uint64_t salt = 0xDEADBEEF42ULL;
    int broken = 0;
    for (int32_t x = -80; x <= 80; x += 7) {
        for (int32_t y = -80; y <= 80; y += 11) {
            const int8_t fx = lt::ExtractDequantMatExpand(x, 2, 3, salt);
            const int8_t fy = lt::ExtractDequantMatExpand(y, 2, 3, salt);
            const int8_t fxy = lt::ExtractDequantMatExpand(x + y, 2, 3, salt);
            const int sum = static_cast<int>(fx) + static_cast<int>(fy);
            if (sum < -48 || sum > 48 || fxy != static_cast<int8_t>(sum)) {
                ++broken;
            }
        }
    }
    BOOST_CHECK(broken > 50);
}

BOOST_AUTO_TEST_CASE(matexpand_batch_algebra_optimal_equals_full)
{
    // Batch algebra: after MatExpand, optimal factoring must equal the full
    // product sketch (associativity of exact int GEMMs; Extract already applied).
    auto header = MakeLTHeader(3, kTestDim);
    uint32_t m = 0;
    BOOST_REQUIRE(lt::ValidateDimsBMX4CLT(kTestDim, m));
    const auto Ahat = lt::ExpandOperandAMatExpand(header, kTestDim);
    const auto Bhat = lt::ExpandOperandBMatExpand(header, kTestDim);
    const auto [seed_u, seed_v] = lt::DeriveProjectorSeedsBMX4CLT(header);
    const auto U = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_u, m, kTestDim);
    const auto V = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_v, kTestDim, m);

    const auto C = matmul::v4::ComputeExactProduct(Ahat, Bhat, kTestDim);
    const auto full = matmul::v4::ComputeSketch(U, C, V, kTestDim, m);
    const auto P = matmul::v4::ComputeProjectedLeft(U, Ahat, kTestDim, m);
    const auto Q = matmul::v4::ComputeProjectedRight(Bhat, V, kTestDim, m);
    const auto opt = matmul::v4::ComputeCombineModQ(P, Q, kTestDim, m);
    BOOST_CHECK(full == opt);
}

BOOST_AUTO_TEST_CASE(seal_binding_sigma_and_merkle_leaf)
{
    // Seal binds (sigma_anchor, merkle_root, Q*): flipping sigma or one leaf
    // digest must change SealWindowCommit (adversarial seal-binding witness).
    std::vector<uint256> digests(64);
    for (size_t i = 0; i < digests.size(); ++i) {
        unsigned char b[32]{};
        b[0] = static_cast<unsigned char>(i + 1);
        b[31] = static_cast<unsigned char>(0xA5 ^ i);
        digests[i] = uint256{Span<const unsigned char>{b, sizeof(b)}};
    }
    const uint256 root = lt::ComputeWindowMerkleRoot(digests);
    const uint256 sigma = ParseUint256(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const uint256 sigma2 = ParseUint256(
        "4444444444444444444444444444444444444444444444444444444444444444");
    const uint256 seal = lt::SealWindowCommit(sigma, root, 64);
    BOOST_CHECK(seal != lt::SealWindowCommit(sigma2, root, 64));

    digests[7] = uint256::ONE;
    const uint256 root_flip = lt::ComputeWindowMerkleRoot(digests);
    BOOST_CHECK(root_flip != root);
    BOOST_CHECK(lt::SealWindowCommit(sigma, root_flip, 64) != seal);

    // Distinct anchors ⇒ disjoint slot-nonce sets (LT-Q1 fat-window binding).
    BOOST_CHECK(lt::DeriveWindowSlotNonce(sigma, 0) != lt::DeriveWindowSlotNonce(sigma2, 0));
    BOOST_CHECK(lt::DeriveWindowSlotNonce(sigma, 0) != lt::DeriveWindowSlotNonce(sigma, 1));
}

BOOST_AUTO_TEST_CASE(lt_accel_entry_bit_identity_or_stub_decline)
{
    // ENABLE=OFF stubs decline; with calibrated GPU, digests must match CPU.
    auto tmpl = MakeLTHeader(3, kTestDim);
    const uint64_t nonces[] = {1, 2};
    std::vector<lt::DigestOnlyResultLT> out;

    auto check_backend = [&](bool available,
                             bool (*compute)(const CBlockHeader&, uint32_t, const uint64_t*, size_t,
                                             std::vector<lt::DigestOnlyResultLT>&)) {
        out.clear();
        if (!available) {
            BOOST_CHECK(!compute(tmpl, kTestDim, nonces, 2, out));
            BOOST_CHECK(out.empty());
            return;
        }
        BOOST_REQUIRE(compute(tmpl, kTestDim, nonces, 2, out));
        BOOST_REQUIRE_EQUAL(out.size(), 2);
        for (size_t i = 0; i < 2; ++i) {
            CBlockHeader h = tmpl;
            h.nNonce64 = nonces[i];
            h.nNonce = static_cast<uint32_t>(nonces[i]);
            uint256 d;
            std::vector<unsigned char> payload;
            BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(h, kTestDim, d, payload));
            BOOST_CHECK(out[i].digest == d);
        }
    };

    check_backend(matmul_v4::cuda::IsMatMulLTCudaAvailable(),
                  &matmul_v4::cuda::ComputeDigestsOnlyLTCuda);
    check_backend(matmul_v4::hip::IsMatMulLTHipAvailable(),
                  &matmul_v4::hip::ComputeDigestsOnlyLTHip);
    check_backend(matmul_v4::metal::IsMatMulLTMetalAvailable(),
                  &matmul_v4::metal::ComputeDigestsOnlyLTMetal);

    uint256 d;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(tmpl, kTestDim, d, payload));
    BOOST_CHECK(!d.IsNull());
    BOOST_CHECK(!payload.empty());
}

BOOST_AUTO_TEST_SUITE_END()
