// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4 PoW pipeline tests (design spec §A / §D / §0.7).
//
// Covers the ComputeDigest / VerifySketch contract:
//   - solver/verifier consistency for honest (header, payload) pairs;
//   - determinism: identical inputs always produce bit-identical digest
//     and payload bytes (the INT8 path is exact, §B.6);
//   - the digest is a fresh function of every header field it must bind
//     (prevhash, merkle, time, bits, dim, nNonce64 — §H.4, §C-I1');
//   - the verifier's inputs are O(m^2), never the O(n^2)-word product C,
//     and verification succeeds from (header, payload) alone — i.e. no C
//     is ever formed or shipped (§0.7-(1), §E.2);
//   - parameter validation (n = 0, n not a multiple of b, rounds = 0).
//
// Test dimensions are n = 256 / 512 (production n = 4096, §D.5); the
// contract under test is dimension-independent.

#include <matmul/pow_v4.h>

#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <set>
#include <string_view>
#include <vector>

namespace {

constexpr uint32_t kTestDim{256};

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeV4Header(uint64_t nonce = 1, uint32_t n = kTestDim)
{
    CBlockHeader header;
    header.nVersion = 0x20000000;
    header.hashPrevBlock = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.hashMerkleRoot = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");
    header.nTime = 1'770'000'090U;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    header.seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    return header;
}

struct ProofResult {
    uint256 digest;
    std::vector<unsigned char> payload;
};

ProofResult MustCompute(const CBlockHeader& header, uint32_t n,
                        uint32_t rounds = matmul_v4::kFreivaldsRounds)
{
    ProofResult out;
    BOOST_REQUIRE(matmul_v4::ComputeDigest(header, n, rounds, out.digest, out.payload));
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_v4_pow_tests, BasicTestingSetup)

// --- ComputeDigest / VerifySketch consistency -------------------------------

BOOST_AUTO_TEST_CASE(compute_then_verify_is_consistent)
{
    for (const uint64_t nonce : {uint64_t{0}, uint64_t{1}, uint64_t{42}, uint64_t{0xffffffffffffffffULL}}) {
        auto header = MakeV4Header(nonce);
        const auto proof = MustCompute(header, kTestDim);

        // Seal the mined digest into the header, exactly as SolveMatMulV4 does
        // before a block is finalized: VerifySketch recomputes the digest from
        // the payload and requires it to equal header.matmul_digest (§0.7-(1)).
        header.matmul_digest = proof.digest;

        uint256 verified;
        BOOST_CHECK(matmul_v4::VerifySketch(header, kTestDim, matmul_v4::kFreivaldsRounds,
                                            proof.payload, verified));
        BOOST_CHECK_EQUAL(verified, proof.digest);
    }
}

BOOST_AUTO_TEST_CASE(compute_then_verify_is_consistent_n512)
{
    auto header = MakeV4Header(/*nonce=*/7, /*n=*/512);
    const auto proof = MustCompute(header, 512);
    header.matmul_digest = proof.digest; // seal, as SolveMatMulV4 does

    uint256 verified;
    BOOST_CHECK(matmul_v4::VerifySketch(header, 512, matmul_v4::kFreivaldsRounds,
                                        proof.payload, verified));
    BOOST_CHECK_EQUAL(verified, proof.digest);
}

BOOST_AUTO_TEST_CASE(round_count_is_part_of_the_contract)
{
    // The verifier must run the consensus round count; an honest R = 3
    // proof is a valid product commitment regardless, but the two sides
    // must agree on R for digest/challenge derivation to line up.
    auto header = MakeV4Header(/*nonce=*/9);
    const auto proof2 = MustCompute(header, kTestDim, /*rounds=*/2);
    const auto proof3 = MustCompute(header, kTestDim, /*rounds=*/3);

    // The digest/payload are round-count-independent (ComputeDigest runs no
    // Freivalds), so proof2 and proof3 seal the same digest into the header.
    header.matmul_digest = proof3.digest;

    uint256 verified;
    BOOST_CHECK(matmul_v4::VerifySketch(header, kTestDim, 2, proof2.payload, verified));
    BOOST_CHECK(matmul_v4::VerifySketch(header, kTestDim, 3, proof3.payload, verified));
}

// --- Determinism (§B.6: bit-exact across runs, schedules, vendors) ----------

BOOST_AUTO_TEST_CASE(identical_inputs_yield_identical_bytes_across_runs)
{
    const auto header = MakeV4Header(/*nonce=*/123);

    const auto first = MustCompute(header, kTestDim);
    for (int run = 0; run < 4; ++run) {
        const auto again = MustCompute(header, kTestDim);
        BOOST_CHECK_EQUAL(again.digest, first.digest);
        BOOST_CHECK(again.payload == first.payload);
    }
}

BOOST_AUTO_TEST_CASE(identical_inputs_yield_identical_bytes_across_runs_n512)
{
    const auto header = MakeV4Header(/*nonce=*/124, /*n=*/512);
    const auto first = MustCompute(header, 512);
    const auto again = MustCompute(header, 512);
    BOOST_CHECK_EQUAL(again.digest, first.digest);
    BOOST_CHECK(again.payload == first.payload);
}

BOOST_AUTO_TEST_CASE(verify_is_deterministic_too)
{
    auto header = MakeV4Header(/*nonce=*/125);
    const auto proof = MustCompute(header, kTestDim);
    header.matmul_digest = proof.digest; // seal, as SolveMatMulV4 does

    for (int run = 0; run < 4; ++run) {
        uint256 verified;
        BOOST_CHECK(matmul_v4::VerifySketch(header, kTestDim, matmul_v4::kFreivaldsRounds,
                                            proof.payload, verified));
        BOOST_CHECK_EQUAL(verified, proof.digest);
    }
}

// --- Header binding (every attempt instantiates a fresh challenge) ----------

BOOST_AUTO_TEST_CASE(distinct_nonces_yield_distinct_digests)
{
    // §C-I1': sigma, operand B and the Fiat-Shamir challenges must be
    // nonce-fresh (A/U/V are template-scoped in v4.1), so distinct nonces
    // must still produce unrelated digests (and payloads).
    std::set<uint256> digests;
    std::set<std::vector<unsigned char>> payloads;
    for (uint64_t nonce = 0; nonce < 8; ++nonce) {
        const auto proof = MustCompute(MakeV4Header(nonce), kTestDim);
        digests.insert(proof.digest);
        payloads.insert(proof.payload);
    }
    BOOST_CHECK_EQUAL(digests.size(), 8U);
    BOOST_CHECK_EQUAL(payloads.size(), 8U);
}

BOOST_AUTO_TEST_CASE(digest_binds_each_header_field)
{
    const auto base = MakeV4Header(/*nonce=*/55);
    const auto base_proof = MustCompute(base, kTestDim);

    {
        auto h = base;
        h.hashPrevBlock = ParseUint256("3333333333333333333333333333333333333333333333333333333333333333");
        BOOST_CHECK(MustCompute(h, kTestDim).digest != base_proof.digest);
    }
    {
        auto h = base;
        h.hashMerkleRoot = ParseUint256("4444444444444444444444444444444444444444444444444444444444444444");
        BOOST_CHECK(MustCompute(h, kTestDim).digest != base_proof.digest);
    }
    {
        auto h = base;
        h.nTime += 90;
        BOOST_CHECK(MustCompute(h, kTestDim).digest != base_proof.digest);
    }
    {
        auto h = base;
        h.nBits = 0x1d00ffff;
        BOOST_CHECK(MustCompute(h, kTestDim).digest != base_proof.digest);
    }
}

BOOST_AUTO_TEST_CASE(verify_rejects_header_mutation_of_honest_proof)
{
    auto header = MakeV4Header(/*nonce=*/77);
    const auto proof = MustCompute(header, kTestDim);
    header.matmul_digest = proof.digest; // seal the honest proof first

    // Tampered headers inherit the sealed digest but re-derive a different
    // challenge chain, so VerifySketch must reject on the binding, not merely
    // on a null digest.
    auto tampered = header;
    tampered.nNonce64 += 1;
    uint256 digest;
    BOOST_CHECK(!matmul_v4::VerifySketch(tampered, kTestDim, matmul_v4::kFreivaldsRounds,
                                         proof.payload, digest));

    auto tampered_prev = header;
    tampered_prev.hashPrevBlock = ParseUint256("5555555555555555555555555555555555555555555555555555555555555555");
    BOOST_CHECK(!matmul_v4::VerifySketch(tampered_prev, kTestDim, matmul_v4::kFreivaldsRounds,
                                         proof.payload, digest));
}

// --- O(n^2) verification: C is never formed or shipped -----------------------

BOOST_AUTO_TEST_CASE(verifier_inputs_exclude_the_product_matrix)
{
    // The verification contract takes only (header, sketch payload). The
    // payload scales as 8 * (n/b)^2 bytes — a fixed factor b^2/2 below the
    // 4 * n^2-byte product — so the O(n^3)-derived C is provably not among
    // the verifier's inputs; the Freivalds identity reconstructs every
    // needed projection of C from two O(n^2) matvecs (§E.2).
    for (const uint32_t n : {kTestDim, uint32_t{512}}) {
        auto header = MakeV4Header(/*nonce=*/88, n);
        const auto proof = MustCompute(header, n);
        header.matmul_digest = proof.digest; // seal, as SolveMatMulV4 does

        const size_t m = n / matmul_v4::kTileB;
        BOOST_CHECK_EQUAL(proof.payload.size(), 8 * m * m);
        // At b = 4 the sketch is 8x smaller than full C (ratio b^2 / 2).
        BOOST_CHECK_EQUAL((static_cast<size_t>(4) * n * n) / proof.payload.size(),
                          static_cast<size_t>(matmul_v4::kTileB) * matmul_v4::kTileB / 2);

        uint256 verified;
        BOOST_CHECK(matmul_v4::VerifySketch(header, n, matmul_v4::kFreivaldsRounds,
                                            proof.payload, verified));
    }
}

// --- Parameter validation (§G.4 invariants) ----------------------------------

BOOST_AUTO_TEST_CASE(zero_dimension_is_rejected)
{
    auto header = MakeV4Header(/*nonce=*/1, /*n=*/0);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_CHECK(!matmul_v4::ComputeDigest(header, 0, matmul_v4::kFreivaldsRounds, digest, payload));
    BOOST_CHECK(!matmul_v4::VerifySketch(header, 0, matmul_v4::kFreivaldsRounds, payload, digest));
}

BOOST_AUTO_TEST_CASE(dimension_not_divisible_by_tile_is_rejected)
{
    // §G.4-#1: n % b == 0 for every accepted dimension.
    const uint32_t bad_n = kTestDim + 1; // 257, not a multiple of 8
    auto header = MakeV4Header(/*nonce=*/1, bad_n);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_CHECK(!matmul_v4::ComputeDigest(header, bad_n, matmul_v4::kFreivaldsRounds, digest, payload));
    BOOST_CHECK(!matmul_v4::VerifySketch(header, bad_n, matmul_v4::kFreivaldsRounds, payload, digest));
}

BOOST_AUTO_TEST_CASE(zero_rounds_is_rejected)
{
    // R = 0 would make the digest an unverified claim; the minimum
    // deployable round count is 2 (regtest), production is 3 (§0.7-(2)).
    const auto header = MakeV4Header(/*nonce=*/1);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_CHECK(!matmul_v4::ComputeDigest(header, kTestDim, 0, digest, payload));

    const auto honest = MustCompute(header, kTestDim);
    BOOST_CHECK(!matmul_v4::VerifySketch(header, kTestDim, 0, honest.payload, digest));
}

BOOST_AUTO_TEST_CASE(dimension_mismatch_between_sides_is_rejected)
{
    // An honest n = 256 proof must not verify when the verifier is told the
    // consensus dimension is 512 (payload shape alone already differs).
    const auto header = MakeV4Header(/*nonce=*/91);
    const auto proof = MustCompute(header, kTestDim);

    auto header512 = header;
    header512.matmul_dim = 512;
    uint256 digest;
    BOOST_CHECK(!matmul_v4::VerifySketch(header512, 512, matmul_v4::kFreivaldsRounds,
                                         proof.payload, digest));
}

BOOST_AUTO_TEST_SUITE_END()
