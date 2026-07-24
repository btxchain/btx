// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4.2 / ENC-BMX4C batched-miner tests (doc/btx-matmul-v4.2-bmx4c-spec.md
// §7-§8). The ENC-BMX4C sibling of matmul_v4_batch_tests: the cross-nonce
// batched miner (template-cached Ahat/U/V and P = U*Ahat, per-nonce Bhat, one
// stacked base-2^6-referenced combine GEMM) is BYTE-IDENTICAL to the
// single-nonce reference matmul::v4::bmx4::ComputeDigestBMX4C for every nonce in
// a window, including under per-nonce §H.4-style seed_a/seed_b churn, and its
// results verify through the UNCHANGED matmul::v4::bmx4::VerifySketchBMX4C.

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_bmx4_batch.h>

#include <primitives/block.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(matmul_v4_bmx4_batch_tests, BasicTestingSetup)

namespace {

namespace bx = matmul::v4::bmx4;

// Fast unit dimension: b=4 -> m=64, and n % 32 == 0 (E8M0 block scales).
constexpr uint32_t kTestDim = 256;

// ENC-BMX4C runs no Freivalds in the miner, but the verifier uses R rounds.
constexpr uint32_t kRounds = 2;

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

BOOST_AUTO_TEST_CASE(bmx4c_batched_miner_matches_single_nonce_reference)
{
    const uint32_t n = kTestDim;
    const CBlockHeader tmpl = MakeV4Header(/*nonce=*/0, n);
    const bx::BatchedSketchMinerBMX4C miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());
    BOOST_CHECK_EQUAL(miner.SketchDim(), n / matmul::v4::kTileB);

    const uint64_t start = 41;
    const uint32_t count = 4;
    std::vector<bx::BatchNonceResultBMX4C> batch;
    BOOST_REQUIRE(miner.Mine(start, count, batch));
    BOOST_REQUIRE_EQUAL(batch.size(), count);

    for (uint32_t i = 0; i < count; ++i) {
        CBlockHeader header{tmpl};
        header.nNonce64 = start + i;
        header.nNonce = static_cast<uint32_t>(header.nNonce64);

        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, n, digest, payload));
        BOOST_CHECK_EQUAL(batch[i].nonce, start + i);
        // Byte-exact across the two independent code paths: the batch miner uses
        // the template-cached Ahat/U/V/P and the stacked limb-tensor combine; the
        // reference expands per nonce and combines directly mod q.
        BOOST_CHECK(batch[i].digest == digest);
        BOOST_CHECK(batch[i].payload == payload);

        // And the batched result verifies through the UNCHANGED ENC-BMX4C
        // O(n^2) sketch-Freivalds verifier on the one winning nonce.
        header.matmul_digest = batch[i].digest;
        uint256 verified;
        BOOST_CHECK(bx::VerifySketchBMX4C(header, n, kRounds, batch[i].payload, verified));
        BOOST_CHECK(verified == batch[i].digest);
    }
}

BOOST_AUTO_TEST_CASE(bmx4c_batched_miner_matches_reference_under_seed_churn)
{
    // The real solve loop re-derives the §H.4 nonce-bound seed_a/seed_b header
    // fields for EVERY candidate. The template projection zeroes those fields, so
    // the cached Ahat/U/V/P must stay valid across the window; pin that with
    // per-candidate random seed fields.
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = kTestDim;
    const CBlockHeader tmpl = MakeV4Header(/*nonce=*/0, n);
    const bx::BatchedSketchMinerBMX4C miner{tmpl, n};
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

    std::vector<bx::BatchNonceResultBMX4C> batch;
    BOOST_REQUIRE(miner.Mine(candidates, batch));
    BOOST_REQUIRE_EQUAL(batch.size(), count);

    for (uint32_t i = 0; i < count; ++i) {
        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(candidates[i], n, digest, payload));
        BOOST_CHECK(batch[i].digest == digest);
        BOOST_CHECK(batch[i].payload == payload);
        // Distinct seed_b/nonce => distinct sigma and Bhat => distinct digest.
        if (i > 0) BOOST_CHECK(batch[i].digest != batch[i - 1].digest);
    }
}

BOOST_AUTO_TEST_CASE(bmx4c_batched_miner_fails_closed_on_template_mismatch)
{
    // A candidate from a DIFFERENT template (changed merkle root) must be
    // rejected outright: combining it with this template's cached Ahat/U/V/P
    // would produce a non-consensus digest.
    const uint32_t n = kTestDim;
    const CBlockHeader tmpl = MakeV4Header(/*nonce=*/0, n);
    const bx::BatchedSketchMinerBMX4C miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());

    std::vector<CBlockHeader> candidates(2, tmpl);
    candidates[0].nNonce64 = 1;
    candidates[1].nNonce64 = 2;
    candidates[1].hashMerkleRoot = ParseUint256("a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4");

    std::vector<bx::BatchNonceResultBMX4C> batch;
    BOOST_CHECK(!miner.Mine(candidates, batch));
    BOOST_CHECK(batch.empty());
}

BOOST_AUTO_TEST_CASE(bmx4c_batched_miner_rejects_invalid_dims)
{
    // n not a multiple of 32 (E8M0 block scales) => ValidateDimsBMX4C fails.
    const bx::BatchedSketchMinerBMX4C bad_scale{MakeV4Header(0, 260), 260};
    BOOST_CHECK(!bad_scale.Valid());
    std::vector<bx::BatchNonceResultBMX4C> out;
    BOOST_CHECK(!bad_scale.Mine(0, 1, out));

    // n not divisible by b (kTileB=4). 288 is a multiple of 32 but 288 % 4 == 0,
    // so use 96 which is /32 but the s32 accum bound still holds — instead pick a
    // value that fails b|n: 288+32=... use 32*3=96 (96%4==0). Use 160? 160%4==0.
    // b|n fails at e.g. n=34 (not /32 either). The /32 check already covers the
    // common invalid shapes; assert the empty-window guard too.
    std::vector<bx::BatchNonceResultBMX4C> out2;
    const bx::BatchedSketchMinerBMX4C ok{MakeV4Header(0, kTestDim), kTestDim};
    BOOST_REQUIRE(ok.Valid());
    BOOST_CHECK(!ok.Mine(std::vector<CBlockHeader>{}, out2));
    BOOST_CHECK(out2.empty());
}

BOOST_AUTO_TEST_SUITE_END()
