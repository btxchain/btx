// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4.1 batched-sketch profile tests (design spec §K.2b, §A.2 v4.1,
// Appendix C-13; PR #89 follow-up):
//
//   1. The limb-tensor combine (16 s8xs8->s32 limb-pair GEMMs + O(m^2) mod-q
//      recombine) is BYTE-IDENTICAL to the direct integer-ALU mod-q combine —
//      the consensus semantics every GPU tensor-core combine must reproduce —
//      and its STACKED cross-nonce form slices back to the per-nonce result.
//   2. The cross-nonce batched miner (template-cached A/U/V and P = U*A,
//      per-nonce B, one stacked combine GEMM) reproduces
//      matmul_v4::ComputeDigest bit-for-bit for every nonce in a window,
//      including under per-nonce §H.4-style seed_a/seed_b churn.
//   3. A, U, V are TEMPLATE-scoped (their seeds ignore nNonce64 and the
//      nonce-derived seed_a/seed_b header fields) while operand B and sigma
//      remain nonce-fresh (§A.2 v4.1, invariant I1').

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_batch.h>
#include <matmul/pow_v4.h>

#include <primitives/block.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <iterator>
#include <limits>
#include <string_view>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(matmul_v4_batch_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 256; // fast unit-suite dimension (b=4 -> m=64)

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeV4Header(uint64_t nonce, uint32_t n)
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

} // namespace

// --- 1. Limb-tensor combine == direct mod-q combine -------------------------

BOOST_AUTO_TEST_CASE(limb_combine_matches_direct_combine_random)
{
    // Random exact-int32 P (m x n) and Q (n x m) with entries across the full
    // legal magnitude |x| <= 15,625 * n (the P = U*A / Q = B*V bound at the
    // largest supported dimension 8192 scaled down to the test n).
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 64;
    const uint32_t m = 16;
    const int64_t bound = static_cast<int64_t>(15625) * n;
    BOOST_REQUIRE(matmul::v4::CheckCombineLimbBound(n));

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);

    const auto direct = matmul::v4::ComputeCombineModQ(P, Q, n, m);
    const auto limb = matmul::v4::ComputeCombineLimbTensor(P, Q, n, m);
    BOOST_REQUIRE_EQUAL(direct.size(), static_cast<size_t>(m) * m);
    BOOST_CHECK(limb == direct);
}

BOOST_AUTO_TEST_CASE(limb_combine_matches_direct_combine_extremes)
{
    // Adversarial extremes: max-magnitude entries of both signs, zeros, and
    // the balanced-digit edge values (+-64, +-63, +-127, +-128 patterns).
    const uint32_t n = 8;
    const uint32_t m = 4;
    const int32_t big = 15625 * 8192 / 64; // scale the 8192-dim bound to n=8
    const int32_t edge_vals[] = {0, 1, -1, 63, -64, 64, -65, 127, -128, 128, -129,
                                 16384, -16384, big, -big, 15625 * 8, -15625 * 8};
    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (size_t i = 0; i < P.size(); ++i) P[i] = edge_vals[i % std::size(edge_vals)];
    for (size_t i = 0; i < Q.size(); ++i) Q[i] = edge_vals[(i * 7 + 3) % std::size(edge_vals)];

    const auto direct = matmul::v4::ComputeCombineModQ(P, Q, n, m);
    const auto limb = matmul::v4::ComputeCombineLimbTensor(P, Q, n, m);
    BOOST_CHECK(limb == direct);
}

BOOST_AUTO_TEST_CASE(limb_bound_window)
{
    // 4 balanced base-128 limbs must cover the whole 4096..8192 dimension
    // window and fail closed just above it (15,625 * n < 2^27 <=> n <= 8589).
    BOOST_CHECK(matmul::v4::CheckCombineLimbBound(4096));
    BOOST_CHECK(matmul::v4::CheckCombineLimbBound(8192));
    BOOST_CHECK(matmul::v4::CheckCombineLimbBound(8589));
    BOOST_CHECK(!matmul::v4::CheckCombineLimbBound(8590));
}

BOOST_AUTO_TEST_CASE(stacked_combine_slices_equal_per_nonce_combine)
{
    // The §K.2b single-GEMM form: P * [Q_0 | Q_1 | Q_2] must equal each
    // per-nonce P * Q_i on the corresponding column block, byte for byte.
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 32;
    const uint32_t m = 8;
    const uint32_t window = 3;
    const int64_t bound = static_cast<int64_t>(15625) * n;

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);

    std::vector<std::vector<int32_t>> Qs(window, std::vector<int32_t>(static_cast<size_t>(n) * m));
    for (auto& Q : Qs) {
        for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    }

    const uint32_t q_cols = window * m;
    std::vector<int32_t> Qstack(static_cast<size_t>(n) * q_cols);
    for (uint32_t i = 0; i < window; ++i) {
        for (uint32_t k = 0; k < n; ++k) {
            for (uint32_t c = 0; c < m; ++c) {
                Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(i) * m + c] =
                    Qs[i][static_cast<size_t>(k) * m + c];
            }
        }
    }

    const auto wide = matmul::v4::ComputeCombineLimbTensorStacked(P, Qstack, n, m, q_cols);
    BOOST_REQUIRE_EQUAL(wide.size(), static_cast<size_t>(m) * q_cols);
    for (uint32_t i = 0; i < window; ++i) {
        const auto single = matmul::v4::ComputeCombineModQ(P, Qs[i], n, m);
        for (uint32_t a = 0; a < m; ++a) {
            for (uint32_t c = 0; c < m; ++c) {
                BOOST_REQUIRE_EQUAL(
                    wide[static_cast<size_t>(a) * q_cols + static_cast<size_t>(i) * m + c],
                    single[static_cast<size_t>(a) * m + c]);
            }
        }
    }
}

// --- 2. Batched miner == single-nonce reference ------------------------------

BOOST_AUTO_TEST_CASE(batched_miner_matches_single_nonce_reference)
{
    const uint32_t n = kTestDim;
    const CBlockHeader tmpl = MakeV4Header(/*nonce=*/0, n);
    const matmul::v4::BatchedSketchMiner miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());
    BOOST_CHECK_EQUAL(miner.SketchDim(), n / matmul_v4::kTileB);

    const uint64_t start = 41;
    const uint32_t count = 4;
    std::vector<matmul::v4::BatchNonceResult> batch;
    BOOST_REQUIRE(miner.Mine(start, count, batch));
    BOOST_REQUIRE_EQUAL(batch.size(), count);

    for (uint32_t i = 0; i < count; ++i) {
        CBlockHeader header{tmpl};
        header.nNonce64 = start + i;
        header.nNonce = static_cast<uint32_t>(header.nNonce64);

        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(matmul_v4::ComputeDigest(header, n, matmul_v4::kFreivaldsRounds,
                                               digest, payload));
        BOOST_CHECK_EQUAL(batch[i].nonce, start + i);
        // Byte-exact across the two independent code paths: the batch miner
        // uses the template-cached A/U/V/P and the stacked limb-tensor
        // combine; the reference expands per nonce and combines directly mod q.
        BOOST_CHECK(batch[i].digest == digest);
        BOOST_CHECK(batch[i].payload == payload);

        // And the batched result verifies through the UNCHANGED consensus
        // verifier (O(n^2) sketch-Freivalds on the one winning nonce).
        header.matmul_digest = batch[i].digest;
        uint256 verified;
        BOOST_CHECK(matmul_v4::VerifySketch(header, n, /*rounds=*/2, batch[i].payload, verified));
        BOOST_CHECK(verified == batch[i].digest);
    }
}

BOOST_AUTO_TEST_CASE(batched_miner_matches_reference_under_seed_churn)
{
    // The real solve loop (SolveMatMulV4) re-derives the §H.4 nonce-bound
    // seed_a/seed_b header fields for EVERY candidate nonce. The template
    // projection zeroes those fields, so the cached A/U/V/P must remain valid
    // across such a window; pin that with per-candidate random seed fields.
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = kTestDim;
    const CBlockHeader tmpl = MakeV4Header(/*nonce=*/0, n);
    const matmul::v4::BatchedSketchMiner miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());

    const uint32_t count = 3;
    std::vector<CBlockHeader> candidates(count, tmpl);
    for (uint32_t i = 0; i < count; ++i) {
        candidates[i].nNonce64 = 9000 + i;
        candidates[i].nNonce = static_cast<uint32_t>(candidates[i].nNonce64);
        candidates[i].seed_a = rng.rand256(); // stand-in for the §H.4 per-nonce derivation
        candidates[i].seed_b = rng.rand256();
        BOOST_REQUIRE(matmul::v4::ComputeTemplateHash(candidates[i]) == miner.TemplateHash());
    }

    std::vector<matmul::v4::BatchNonceResult> batch;
    BOOST_REQUIRE(miner.Mine(candidates, batch));
    BOOST_REQUIRE_EQUAL(batch.size(), count);

    for (uint32_t i = 0; i < count; ++i) {
        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(matmul_v4::ComputeDigest(candidates[i], n, /*rounds=*/2, digest, payload));
        BOOST_CHECK(batch[i].digest == digest);
        BOOST_CHECK(batch[i].payload == payload);
        // Distinct seed_b/nonce => distinct sigma and B => distinct digest.
        if (i > 0) BOOST_CHECK(batch[i].digest != batch[i - 1].digest);
    }
}

BOOST_AUTO_TEST_CASE(batched_miner_fails_closed_on_template_mismatch)
{
    // A candidate from a DIFFERENT template (changed merkle root) must be
    // rejected outright: combining it with this template's cached A/U/V/P
    // would produce a non-consensus digest.
    const uint32_t n = kTestDim;
    const CBlockHeader tmpl = MakeV4Header(/*nonce=*/0, n);
    const matmul::v4::BatchedSketchMiner miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());

    std::vector<CBlockHeader> candidates(2, tmpl);
    candidates[0].nNonce64 = 1;
    candidates[1].nNonce64 = 2;
    candidates[1].hashMerkleRoot = ParseUint256("a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4");

    std::vector<matmul::v4::BatchNonceResult> batch;
    BOOST_CHECK(!miner.Mine(candidates, batch));
    BOOST_CHECK(batch.empty());
}

BOOST_AUTO_TEST_CASE(batched_miner_rejects_invalid_dims)
{
    // n not divisible by b.
    const matmul::v4::BatchedSketchMiner bad{MakeV4Header(0, 254), 254};
    BOOST_CHECK(!bad.Valid());
    std::vector<matmul::v4::BatchNonceResult> out;
    BOOST_CHECK(!bad.Mine(0, 1, out));
}

// --- 3. Template-scoped A/U/V, nonce-fresh B (invariant I1') -----------------

BOOST_AUTO_TEST_CASE(operands_a_u_v_are_template_scoped_b_is_nonce_fresh)
{
    const uint32_t n = kTestDim;
    CBlockHeader h1 = MakeV4Header(/*nonce=*/1000, n);
    CBlockHeader h2 = MakeV4Header(/*nonce=*/1001, n);
    // The §H.4 seed fields are nonce-derived in the real miner; vary them too
    // so the test pins that the template projection zeroes them.
    h2.seed_a = ParseUint256("7777777777777777777777777777777777777777777777777777777777777777");
    h2.seed_b = ParseUint256("8888888888888888888888888888888888888888888888888888888888888888");

    // seed_A ignores nNonce64 and seed_a/seed_b (template-scoped, §A.2 v4.1)...
    const uint256 a1 = matmul::v4::DeriveOperandSeed(h1, matmul::v4::Operand::A);
    const uint256 a2 = matmul::v4::DeriveOperandSeed(h2, matmul::v4::Operand::A);
    BOOST_CHECK(a1 == a2);

    // ...and so do the projector seeds (I1'; supersedes v4.0's I7).
    const auto [u1, v1] = matmul::v4::DeriveProjectorSeeds(h1);
    const auto [u2, v2] = matmul::v4::DeriveProjectorSeeds(h2);
    BOOST_CHECK(u1 == u2);
    BOOST_CHECK(v1 == v2);
    BOOST_CHECK(u1 != v1); // distinct U/V domains

    // ...but every template field still binds (parent, merkle root, time).
    CBlockHeader h3{h1};
    h3.hashMerkleRoot = ParseUint256("a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4");
    BOOST_CHECK(matmul::v4::DeriveOperandSeed(h3, matmul::v4::Operand::A) != a1);
    BOOST_CHECK(matmul::v4::DeriveProjectorSeeds(h3).first != u1);
    CBlockHeader h4{h1};
    h4.hashPrevBlock = ParseUint256("5252525252525252525252525252525252525252525252525252525252525252");
    BOOST_CHECK(matmul::v4::DeriveOperandSeed(h4, matmul::v4::Operand::A) != a1);
    BOOST_CHECK(matmul::v4::DeriveProjectorSeeds(h4).second != v1);
    CBlockHeader h5{h1};
    h5.nTime += 90;
    BOOST_CHECK(matmul::v4::DeriveOperandSeed(h5, matmul::v4::Operand::A) != a1);

    // seed_B stays nonce-fresh (invariant I1').
    const uint256 b1 = matmul::v4::DeriveOperandSeed(h1, matmul::v4::Operand::B);
    const uint256 b2 = matmul::v4::DeriveOperandSeed(h2, matmul::v4::Operand::B);
    BOOST_CHECK(b1 != b2);

    // A and B seeds are domain-separated even on the all-zero-nonce header
    // with zeroed seed fields (where the template hash equals the full hash).
    CBlockHeader h0 = MakeV4Header(/*nonce=*/0, n);
    h0.seed_a.SetNull();
    h0.seed_b.SetNull();
    BOOST_CHECK(matmul::v4::DeriveOperandSeed(h0, matmul::v4::Operand::A) !=
                matmul::v4::DeriveOperandSeed(h0, matmul::v4::Operand::B));
    // On that header the template projection is the identity, so seed_A
    // (template) == what the full-header derivation would give.
    BOOST_CHECK(matmul::v4::DeriveOperandSeed(h0, matmul::v4::Operand::A) == a1);

    // Digests still differ nonce-to-nonce (sigma and B are fresh).
    uint256 d1, d2;
    std::vector<unsigned char> p1, p2;
    BOOST_REQUIRE(matmul_v4::ComputeDigest(h1, n, 2, d1, p1));
    BOOST_REQUIRE(matmul_v4::ComputeDigest(h2, n, 2, d2, p2));
    BOOST_CHECK(d1 != d2);
    BOOST_CHECK(p1 != p2);
}

BOOST_AUTO_TEST_SUITE_END()
