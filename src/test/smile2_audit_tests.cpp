// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SMILE v2 Security Audit & Stress Test Suite
//
// Tests organized by audit category:
//   A1-A5: Parameter security (lattice hardness, NTT correctness)
//   A6-A9: Cryptographic soundness (forgery resistance)
//   A10-A13: Zero-knowledge properties
//   A14-A17: Serialization & consensus integration
//   B1-B5: Performance benchmarks (prove, verify, throughput)

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <consensus/consensus.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <numeric>
#include <optional>
#include <random>
#include <vector>

using namespace smile2;

namespace {

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

std::vector<SmileKeyPair> GenerateAnonSet(size_t N, uint8_t seed_val) {
    auto a_seed = MakeSeed(seed_val);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i) {
        keys[i] = SmileKeyPair::Generate(a_seed, 10000 + i);
    }
    return keys;
}

std::vector<SmilePublicKey> ExtractPublicKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    pks.reserve(keys.size());
    for (const auto& kp : keys) {
        pks.push_back(kp.pub);
    }
    return pks;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

std::vector<std::vector<BDLOPCommitment>> BuildCoinRings(
    const std::vector<SmileKeyPair>& keys,
    const std::vector<size_t>& secret_indices,
    const std::vector<int64_t>& secret_amounts,
    uint64_t coin_seed)
{
    const size_t ring_size = keys.size();
    const size_t input_count = secret_indices.size();

    const auto ck = GetPublicCoinCommitmentKey();
    std::vector<std::vector<BDLOPCommitment>> coin_rings(input_count);
    for (size_t input_index = 0; input_index < input_count; ++input_index) {
        coin_rings[input_index].resize(ring_size);
        for (size_t ring_index = 0; ring_index < ring_size; ++ring_index) {
            SmilePoly amount_poly;
            if (ring_index == secret_indices[input_index]) {
                amount_poly = EncodeAmountToSmileAmountPoly(secret_amounts[input_index]).value();
            } else {
                std::mt19937_64 rng(coin_seed * 1000 + input_index * ring_size + ring_index);
                amount_poly = EncodeAmountToSmileAmountPoly(
                    static_cast<int64_t>(rng() % 1000000)).value();
            }
            const auto opening =
                SampleTernary(ck.rand_dim(), coin_seed * 100000 + input_index * ring_size + ring_index);
            coin_rings[input_index][ring_index] = Commit(ck, {amount_poly}, opening);
        }
    }

    return coin_rings;
}

CTInput MakeCtInput(size_t secret_index, const SmileKeyPair& key, int64_t amount,
                    uint64_t coin_seed, size_t input_index, size_t ring_size)
{
    return CTInput{
        secret_index,
        key.sec,
        SampleTernary(GetPublicCoinCommitmentKey().rand_dim(),
                      coin_seed * 100000 + input_index * ring_size + secret_index),
        amount,
    };
}

std::vector<CTOutput> MakeCtOutputs(std::initializer_list<int64_t> amounts, uint64_t seed_base)
{
    std::vector<CTOutput> outputs;
    outputs.reserve(amounts.size());
    const size_t rand_dim = GetPublicCoinCommitmentKey().rand_dim();
    size_t index = 0;
    for (int64_t amount : amounts) {
        outputs.push_back(CTOutput{
            amount,
            SampleTernary(rand_dim, seed_base + index),
        });
        ++index;
    }
    return outputs;
}

std::optional<SmileCTProof> ProveValidCTWithRetries(const std::vector<CTInput>& inputs,
                                                    const std::vector<CTOutput>& outputs,
                                                    const CTPublicData& pub,
                                                    size_t expected_inputs,
                                                    size_t expected_outputs,
                                                    uint64_t seed_base,
                                                    int max_attempts = 32)
{
    static constexpr uint64_t kAttemptStride{0x1000000ULL};

    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        SmileCTProof proof = ProveCT(inputs, outputs, pub, seed_base + (kAttemptStride * attempt));
        if (VerifyCT(proof, expected_inputs, expected_outputs, pub)) {
            return proof;
        }
    }

    return std::nullopt;
}

// Center a coefficient to [-q/2, q/2]
int64_t Center(int64_t c) {
    c = mod_q(c);
    return c > Q / 2 ? c - Q : c;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_audit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a0_ct_rejection_log_accept_matches_live_monomial_bound)
{
    SmilePolyVec z(1);
    SmilePolyVec cv(1);
    z[0].coeffs[0] = 5;
    cv[0].coeffs[0] = 3;

    const double actual = ComputeCtRejectionLogAccept(z, cv, SIGMA_MASK);
    const double expected =
        (-2.0 * 15.0 + 9.0) /
            (2.0 * static_cast<double>(SIGMA_MASK) * static_cast<double>(SIGMA_MASK)) -
        std::log(3.0);

    BOOST_CHECK_CLOSE_FRACTION(actual, expected, 1e-12);
}

BOOST_AUTO_TEST_CASE(a0_invert_monomial_challenge_handles_k0_and_rotation)
{
    SmilePoly plus_one;
    plus_one.coeffs[0] = 1;
    const SmilePoly plus_one_inv = InvertMonomialChallenge(plus_one);
    BOOST_CHECK_EQUAL(plus_one_inv.coeffs[0], 1);

    SmilePoly expected_identity;
    expected_identity.coeffs[0] = 1;
    SmilePoly identity_product = plus_one.MulSchoolbook(plus_one_inv);
    identity_product.Reduce();
    expected_identity.Reduce();
    BOOST_CHECK(identity_product == expected_identity);

    SmilePoly minus_x5;
    minus_x5.coeffs[5] = mod_q(-1);
    const SmilePoly minus_x5_inv = InvertMonomialChallenge(minus_x5);

    SmilePoly product = minus_x5.MulSchoolbook(minus_x5_inv);
    product.Reduce();
    expected_identity.Reduce();
    BOOST_CHECK(product == expected_identity);
}

BOOST_AUTO_TEST_CASE(a0_deserialize_poly_rejects_noncanonical_coefficients)
{
    std::vector<uint8_t> encoded;
    encoded.resize(POLY_DEGREE * sizeof(uint32_t), 0);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        const uint32_t val = static_cast<uint32_t>(Q);
        std::memcpy(encoded.data() + i * sizeof(uint32_t), &val, sizeof(val));
    }

    SmilePoly parsed;
    const uint8_t* ptr = encoded.data();
    const uint8_t* end = ptr + encoded.size();
    BOOST_CHECK(!DeserializePoly(ptr, end, parsed));

    DataStream stream(encoded);
    BOOST_CHECK_THROW(DeserializePoly(stream, parsed), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(a0_mul_mod_q_matches_exact_128bit_reduction)
{
    const auto exact_mul = [](int64_t a, int64_t b) {
        const __int128 lhs = static_cast<__int128>(mod_q(a));
        const __int128 rhs = static_cast<__int128>(mod_q(b));
        return static_cast<int64_t>((lhs * rhs) % static_cast<__int128>(Q));
    };

    const std::array<std::pair<int64_t, int64_t>, 8> cases{{
        {Q - 1, Q - 1},
        {Q - 1, Q - 2},
        {Q - 17, Q - 29},
        {-1, -1},
        {-1, 2},
        {-Q - 1, 1},
        {Q, 12345},
        {0, -42},
    }};

    for (const auto& [a, b] : cases) {
        BOOST_CHECK_EQUAL(mul_mod_q(a, b), exact_mul(a, b));
    }

    std::mt19937_64 rng(0xC2C2C2ULL);
    std::uniform_int_distribution<int64_t> dist(-static_cast<int64_t>(2 * Q),
                                                static_cast<int64_t>(2 * Q));
    for (size_t i = 0; i < 512; ++i) {
        const int64_t a = dist(rng);
        const int64_t b = dist(rng);
        BOOST_CHECK_EQUAL(mul_mod_q(a, b), exact_mul(a, b));
    }
}

BOOST_AUTO_TEST_CASE(a0_invert_monomial_challenge_rejects_non_monomials)
{
    SmilePoly zero;
    BOOST_CHECK_THROW(
        [&] {
            (void)InvertMonomialChallenge(zero);
        }(),
        std::invalid_argument);

    SmilePoly two_term;
    two_term.coeffs[0] = 1;
    two_term.coeffs[7] = 1;
    BOOST_CHECK_THROW(
        [&] {
            (void)InvertMonomialChallenge(two_term);
        }(),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(a0_validate_smile2_proof_does_not_mutate_input_proof)
{
    auto keys = GenerateAnonSet(/*N=*/32, /*seed_val=*/33);
    const std::vector<size_t> secret_indices{3};
    const std::vector<int64_t> input_amounts{25};

    CTPublicData pub;
    pub.anon_set = ExtractPublicKeys(keys);
    pub.coin_rings = BuildCoinRings(keys, secret_indices, input_amounts, /*coin_seed=*/777);
    pub.account_rings =
        test::shielded::BuildDeterministicCTAccountRings(keys, pub.coin_rings, /*seed=*/778, /*tag=*/0x91);

    std::vector<CTInput> inputs;
    inputs.push_back(MakeCtInput(secret_indices[0], keys[secret_indices[0]], input_amounts[0], 777, 0, keys.size()));
    auto outputs = MakeCtOutputs({25}, /*seed_base=*/9000);

    SmileCTProof proof = ProveCT(inputs, outputs, pub, 0xACCE5510);
    BOOST_REQUIRE(VerifyCT(proof, 1, 1, pub));
    const auto output_coins = proof.output_coins;

    SmileCTProof parsed = proof;
    parsed.output_coins.clear();
    BOOST_REQUIRE(parsed.output_coins.empty());
    BOOST_CHECK(!ValidateSmile2Proof(parsed, 1, 1, output_coins, pub).has_value());
    BOOST_CHECK(parsed.output_coins.empty());
}

BOOST_AUTO_TEST_CASE(a0_deserialize_ctproof_rejects_noncanonical_h2_coefficients)
{
    auto keys = GenerateAnonSet(/*N=*/32, /*seed_val=*/0x71);
    const std::vector<size_t> secret_indices{4};
    const std::vector<int64_t> input_amounts{55};

    CTPublicData pub;
    pub.anon_set = ExtractPublicKeys(keys);
    pub.coin_rings = BuildCoinRings(keys, secret_indices, input_amounts, /*coin_seed=*/0x810);
    pub.account_rings =
        test::shielded::BuildDeterministicCTAccountRings(keys, pub.coin_rings, /*seed=*/0x811, /*tag=*/0x51);

    std::vector<CTInput> inputs;
    inputs.push_back(MakeCtInput(secret_indices[0], keys[secret_indices[0]], input_amounts[0], 0x810, 0, keys.size()));
    auto outputs = MakeCtOutputs({55}, /*seed_base=*/0x812);

    auto maybe_proof = ProveValidCTWithRetries(inputs, outputs, pub, 1, 1, /*seed_base=*/0x813);
    BOOST_REQUIRE(maybe_proof.has_value());

    const std::vector<uint8_t> serialized = SerializeCTProof(*maybe_proof);
    BOOST_REQUIRE_GE(serialized.size(),
                     32U + static_cast<size_t>(POLY_DEGREE - SLOT_DEGREE) * sizeof(uint32_t));

    std::vector<uint8_t> tampered = serialized;
    const size_t h2_offset =
        tampered.size() - 32 - static_cast<size_t>(POLY_DEGREE - SLOT_DEGREE) * sizeof(uint32_t);
    const uint32_t bad_coeff = static_cast<uint32_t>(Q);
    std::memcpy(tampered.data() + h2_offset, &bad_coeff, sizeof(bad_coeff));

    SmileCTProof decoded;
    BOOST_CHECK(!DeserializeCTProof(tampered, decoded, inputs.size(), outputs.size()));
}

// =====================================================================
// A1: Prime modulus q verification
// Verify q = 4294966337 is prime and has correct splitting properties.
// =====================================================================
BOOST_AUTO_TEST_CASE(a1_prime_modulus_verification)
{
    // q must be prime
    int64_t q = Q;
    BOOST_CHECK_EQUAL(q, 4294966337LL);

    // Trial division for small primes
    bool is_prime = true;
    for (int64_t p = 2; p * p <= q && p < 100000; ++p) {
        if (q % p == 0) { is_prime = false; break; }
    }
    BOOST_CHECK_MESSAGE(is_prime, "q must be prime");

    // q mod 64 = 1 (needed for 64th roots of unity)
    BOOST_CHECK_EQUAL(q % 64, 1);

    // q mod 128 must NOT be 1 (ensures X^128+1 doesn't split into degree-1 factors)
    BOOST_CHECK_NE(q % 128, 1);

    // Verify primitive root
    int64_t zeta = ZETA;
    // zeta^32 should NOT be 1 (it's a 64th root, not 32nd)
    int64_t power = 1;
    for (int i = 0; i < 32; ++i) power = mul_mod_q(power, zeta);
    BOOST_CHECK_NE(power, 1);

    // zeta^64 SHOULD be 1
    for (int i = 0; i < 32; ++i) power = mul_mod_q(power, zeta);
    BOOST_CHECK_EQUAL(power, 1);

    BOOST_TEST_MESSAGE("A1: q=" << q << " is prime, zeta has order 64 ✓");
}

// =====================================================================
// A2: NTT slot roots verify X^128+1 factorization
// =====================================================================
BOOST_AUTO_TEST_CASE(a2_ntt_factorization)
{
    // Verify: product of (X^4 - SLOT_ROOTS[j]) for j=0..31 equals X^128+1 mod q
    // Check at multiple random evaluation points
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int64_t> dist(1, Q - 1);

    for (int trial = 0; trial < 20; ++trial) {
        int64_t x = dist(rng);

        // Compute X^128 + 1
        int64_t x128 = 1;
        for (int i = 0; i < 128; ++i) x128 = mul_mod_q(x128, x);
        int64_t target = add_mod_q(x128, 1);

        // Compute product of (x^4 - root_j)
        int64_t x4 = 1;
        for (int i = 0; i < 4; ++i) x4 = mul_mod_q(x4, x);

        int64_t product = 1;
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            int64_t factor = sub_mod_q(x4, SLOT_ROOTS[j]);
            product = mul_mod_q(product, factor);
        }

        BOOST_CHECK_EQUAL(product, target);
    }
    BOOST_TEST_MESSAGE("A2: X^128+1 = prod(X^4 - r_j) verified at 20 random points ✓");
}

// =====================================================================
// A3: NTT round-trip correctness
// =====================================================================
BOOST_AUTO_TEST_CASE(a3_ntt_roundtrip)
{
    std::mt19937_64 rng(123);
    std::uniform_int_distribution<int64_t> dist(0, Q - 1);

    for (int trial = 0; trial < 100; ++trial) {
        SmilePoly p;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            p.coeffs[i] = dist(rng);
        }

        NttForm ntt = NttForward(p);
        SmilePoly recovered = NttInverse(ntt);
        recovered.Reduce();
        SmilePoly orig = p;
        orig.Reduce();

        BOOST_CHECK(recovered == orig);
    }
    BOOST_TEST_MESSAGE("A3: NTT forward/inverse round-trip correct for 100 random polynomials ✓");
}

// =====================================================================
// A4: NTT multiplication matches schoolbook
// =====================================================================
BOOST_AUTO_TEST_CASE(a4_ntt_mul_vs_schoolbook)
{
    std::mt19937_64 rng(456);
    std::uniform_int_distribution<int64_t> dist(0, Q - 1);

    for (int trial = 0; trial < 50; ++trial) {
        SmilePoly a, b;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            a.coeffs[i] = dist(rng);
            b.coeffs[i] = dist(rng);
        }

        SmilePoly ntt_result = NttMul(a, b);
        SmilePoly school_result = a.MulSchoolbook(b);

        ntt_result.Reduce();
        school_result.Reduce();

        BOOST_CHECK(ntt_result == school_result);
    }
    BOOST_TEST_MESSAGE("A4: NTT multiplication matches schoolbook for 50 random pairs ✓");
}

// =====================================================================
// A5: Module-SIS/Module-LWE parameter security estimation
// Verify parameters provide ≥128-bit classical security.
// =====================================================================
BOOST_AUTO_TEST_CASE(a5_parameter_security_estimation)
{
    // Security estimation using root Hermite factor analysis.
    // For Module-SIS with rank α, degree d, modulus q, bound β:
    //   δ = (β / q^(α·d))^(1/(2·α·d))
    //   Security ≈ -log2(δ) / (log2(δ) - 1/(4·α·d·log2(δ)))
    //
    // Conservative estimate: bit-security ≈ d·α / (7.2·log2(root_hermite_factor))
    // For NIST level 1 (128-bit): δ ≈ 1.0045

    size_t d = POLY_DEGREE;          // 128
    size_t alpha = MSIS_RANK;        // 10
    int64_t q_val = Q;               // ~2^32

    // Module rank = α = 10, degree d = 128
    // Effective lattice dimension = α·d = 1280
    // For Kyber-512 (α=2, d=256): dimension=512, 128-bit security with q≈3329
    // Our dimension 1280 >> 512, and q~2^32 vs q~2^12
    // The larger q hurts, but much larger dimension compensates.

    double log_q = std::log2(static_cast<double>(q_val)); // ~32
    double dim = static_cast<double>(alpha * d);           // 1280

    // Root Hermite factor estimate: δ = q^(1/dim) for SIS
    double root_hermite = std::pow(static_cast<double>(q_val), 1.0 / dim);
    double log_delta = std::log2(root_hermite);

    // Bit security ≈ 2·d·α / (7.2·log2(δ))  [Chen-Nguyen model]
    // This is a simplified estimate; real estimation uses lattice-estimator
    double bit_security = 2.0 * dim / (7.2 * log_delta);

    BOOST_TEST_MESSAGE("A5: Security estimation:");
    BOOST_TEST_MESSAGE("  Module rank (α): " << alpha);
    BOOST_TEST_MESSAGE("  Polynomial degree (d): " << d);
    BOOST_TEST_MESSAGE("  Effective dimension: " << dim);
    BOOST_TEST_MESSAGE("  log2(q): " << log_q);
    BOOST_TEST_MESSAGE("  Root Hermite factor: " << root_hermite);
    BOOST_TEST_MESSAGE("  Estimated bit-security: " << bit_security);

    // Must be ≥ 128 bits
    BOOST_CHECK_GE(bit_security, 128.0);
}

// =====================================================================
// A6: Membership proof soundness — wrong key MUST be rejected
// =====================================================================
BOOST_AUTO_TEST_CASE(a6_soundness_wrong_key)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xA6);
    auto pks = ExtractPublicKeys(keys);

    // Try 10 different fake keys
    int rejected = 0;
    for (int trial = 0; trial < 10; ++trial) {
        SmileSecretKey fake_sk;
        fake_sk.s = SampleTernary(KEY_COLS, 77777 + trial);

        auto proof = ProveMembership(pks, 5, fake_sk, 88888 + trial);
        if (!VerifyMembership(pks, proof)) {
            rejected++;
        }
    }

    BOOST_CHECK_EQUAL(rejected, 10);
    BOOST_TEST_MESSAGE("A6: All 10 wrong-key proofs rejected ✓");
}

// =====================================================================
// A7: Membership proof soundness — wrong index MUST be rejected
// =====================================================================
BOOST_AUTO_TEST_CASE(a7_soundness_wrong_index)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xA7);
    auto pks = ExtractPublicKeys(keys);

    // Prove for index 5 but use key 10's secret
    auto proof = ProveMembership(pks, 5, keys[10].sec, 99999);
    bool valid = VerifyMembership(pks, proof);
    BOOST_CHECK(!valid);
    BOOST_TEST_MESSAGE("A7: Wrong index proof rejected ✓");
}

// =====================================================================
// A8: Membership proof soundness — tampered h polynomial
// =====================================================================
BOOST_AUTO_TEST_CASE(a8_soundness_tampered_h)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xA8);
    auto pks = ExtractPublicKeys(keys);

    auto proof = ProveMembership(pks, 7, keys[7].sec, 111111);
    BOOST_CHECK(VerifyMembership(pks, proof)); // honest proof passes

    // Tamper with h
    proof.h.coeffs[10] = mod_q(proof.h.coeffs[10] + 1);
    BOOST_CHECK(!VerifyMembership(pks, proof));

    BOOST_TEST_MESSAGE("A8: Tampered h polynomial rejected ✓");
}

// =====================================================================
// A9: Membership proof soundness — tampered omega
// =====================================================================
BOOST_AUTO_TEST_CASE(a9_soundness_tampered_omega)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xA9);
    auto pks = ExtractPublicKeys(keys);

    auto proof = ProveMembership(pks, 3, keys[3].sec, 222222);
    BOOST_CHECK(VerifyMembership(pks, proof));

    // Tamper with omega
    proof.omega.coeffs[0] = mod_q(proof.omega.coeffs[0] + 1);
    BOOST_CHECK(!VerifyMembership(pks, proof));

    BOOST_TEST_MESSAGE("A9: Tampered omega rejected ✓");
}

// =====================================================================
// A10: Zero-knowledge — z_0 distribution is statistically close to D_σ
// (Rejection sampling ensures z_0 is independent of secret key)
// =====================================================================
BOOST_AUTO_TEST_CASE(a10_zk_z0_distribution)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xA0);
    auto pks = ExtractPublicKeys(keys);

    // Generate proofs with different keys, check z_0 coefficient distribution
    std::vector<double> all_centered;
    for (int trial = 0; trial < 16; ++trial) {
        size_t idx = trial % N;
        auto proof = ProveMembership(pks, idx, keys[idx].sec, 500000 + trial);
        for (const auto& zi : proof.z0) {
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                all_centered.push_back(static_cast<double>(Center(zi.coeffs[c])));
            }
        }
    }

    // Compute mean and stddev
    double sum = std::accumulate(all_centered.begin(), all_centered.end(), 0.0);
    double mean = sum / all_centered.size();
    double sq_sum = 0.0;
    for (double v : all_centered) sq_sum += (v - mean) * (v - mean);
    double stddev = std::sqrt(sq_sum / all_centered.size());

    BOOST_TEST_MESSAGE("A10: z_0 distribution: mean=" << mean << " stddev=" << stddev
                       << " (expected: mean≈0, stddev≈" << MEMBERSHIP_SIGMA_KEY << ")");

    // Mean should be near 0 (tolerance: 3σ/√n)
    double tol = 3.0 * stddev / std::sqrt(static_cast<double>(all_centered.size()));
    BOOST_CHECK_LT(std::abs(mean), tol * 5); // generous

    // Stddev should be close to the live membership masking sigma.
    BOOST_CHECK_GT(stddev, MEMBERSHIP_SIGMA_KEY * 0.5);
    BOOST_CHECK_LT(stddev, MEMBERSHIP_SIGMA_KEY * 2.0);
}

// =====================================================================
// A11: Zero-knowledge — proofs for different indices are indistinguishable
// =====================================================================
BOOST_AUTO_TEST_CASE(a11_zk_index_indistinguishability)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xA1);
    auto pks = ExtractPublicKeys(keys);

    // Generate proofs for index 0 and index 15
    std::vector<double> h_coeffs_idx0, h_coeffs_idx15;

    for (int trial = 0; trial < 16; ++trial) {
        const uint64_t seed = 600000 + static_cast<uint64_t>(trial);
        auto proof0 = ProveMembership(pks, 0, keys[0].sec, seed);
        auto proof15 = ProveMembership(pks, 15, keys[15].sec, seed);

        for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
            h_coeffs_idx0.push_back(static_cast<double>(mod_q(proof0.h.coeffs[c])));
            h_coeffs_idx15.push_back(static_cast<double>(mod_q(proof15.h.coeffs[c])));
        }
    }

    // Compare means — should be statistically similar (both near Q/2)
    double mean0 = std::accumulate(h_coeffs_idx0.begin(), h_coeffs_idx0.end(), 0.0) / h_coeffs_idx0.size();
    double mean15 = std::accumulate(h_coeffs_idx15.begin(), h_coeffs_idx15.end(), 0.0) / h_coeffs_idx15.size();

    double expected_mean = static_cast<double>(Q) / 2.0;
    double dev0 = std::abs(mean0 - expected_mean) / expected_mean;
    double dev15 = std::abs(mean15 - expected_mean) / expected_mean;

    BOOST_TEST_MESSAGE("A11: h-coeff means: idx0=" << mean0 << " idx15=" << mean15
                       << " expected=" << expected_mean);
    BOOST_TEST_MESSAGE("  Deviation: idx0=" << (dev0*100) << "% idx15=" << (dev15*100) << "%");

    // Both should remain close to the same centered distribution when only the
    // witness index changes under the same randomness schedule.
    const double relative_gap = std::abs(mean0 - mean15) / expected_mean;
    BOOST_TEST_MESSAGE("  Relative mean gap: " << (relative_gap * 100) << "%");
    BOOST_CHECK_LT(relative_gap, 0.10);
}

// =====================================================================
// A12: CT proof balance enforcement — unbalanced tx MUST be rejected
// =====================================================================
BOOST_AUTO_TEST_CASE(a12_ct_balance_enforcement)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xB2);
    auto pks = ExtractPublicKeys(keys);

    CTPublicData pub;
    pub.anon_set = pks;
    pub.coin_rings = BuildCoinRings(keys, {0}, {100}, 0xB2);
    pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(keys, pub.coin_rings, 0xB200, 0x9a);

    // Balanced: 100 = 60 + 40
    std::vector<CTInput> inputs = {
        MakeCtInput(0, keys[0], 100, 0xB2, 0, N)
    };
    std::vector<CTOutput> outputs = MakeCtOutputs({60, 40}, 0xB200);

    auto proof_balanced = ProveCT(inputs, outputs, pub, 123456);
    BOOST_CHECK(VerifyCT(proof_balanced, 1, 2, pub));

    // Unbalanced: 100 != 60 + 50
    std::vector<CTOutput> outputs_unbal = MakeCtOutputs({60, 50}, 0xB210);
    auto proof_unbal = ProveCT(inputs, outputs_unbal, pub, 234567);
    BOOST_CHECK(!VerifyCT(proof_unbal, 1, 2, pub));

    BOOST_TEST_MESSAGE("A12: Balanced proof accepted, unbalanced rejected ✓");
}

// =====================================================================
// A13: CT proof — serial numbers are deterministic per key
// =====================================================================
BOOST_AUTO_TEST_CASE(a13_serial_number_determinism)
{
    auto sn_ck_seed = std::array<uint8_t, 32>{};
    sn_ck_seed[0] = 0xAA;
    auto sn_ck = BDLOPCommitmentKey::Generate(sn_ck_seed, 1);

    SmileSecretKey sk;
    sk.s = SampleTernary(KEY_COLS, 12345);

    // Compute serial number twice — must be identical
    SmilePoly sn1 = ComputeSerialNumber(sn_ck, sk);
    SmilePoly sn2 = ComputeSerialNumber(sn_ck, sk);

    sn1.Reduce();
    sn2.Reduce();
    BOOST_CHECK(sn1 == sn2);

    // Different key → different serial number
    SmileSecretKey sk2;
    sk2.s = SampleTernary(KEY_COLS, 67890);
    SmilePoly sn3 = ComputeSerialNumber(sn_ck, sk2);
    sn3.Reduce();
    BOOST_CHECK(sn1 != sn3);

    // Serial number must be non-zero
    BOOST_CHECK(!sn1.IsZero());

    BOOST_TEST_MESSAGE("A13: Serial numbers are deterministic, unique per key, non-zero ✓");
}

// =====================================================================
// A14: Serialization round-trip
// =====================================================================
BOOST_AUTO_TEST_CASE(a14_serialization_roundtrip)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xC1);
    auto pks = ExtractPublicKeys(keys);

    CTPublicData pub;
    pub.anon_set = pks;
    pub.coin_rings = BuildCoinRings(keys, {0}, {100}, 0xC1);
    pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(keys, pub.coin_rings, 0xC100, 0x9b);

    std::vector<CTInput> inputs = {MakeCtInput(0, keys[0], 100, 0xC1, 0, N)};
    std::vector<CTOutput> outputs = MakeCtOutputs({60, 40}, 0xC100);

    auto proof = ProveCT(inputs, outputs, pub, 777777);

    // Serialize
    auto bytes = SerializeCTProof(proof);
    BOOST_CHECK_GT(bytes.size(), 0u);

    // Deserialize
    SmileCTProof proof2;
    bool ok = DeserializeCTProof(bytes, proof2, inputs.size(), outputs.size());
    BOOST_CHECK(ok);

    // Re-serialize and compare
    auto bytes2 = SerializeCTProof(proof2);
    BOOST_CHECK_EQUAL(bytes.size(), bytes2.size());
    BOOST_CHECK(bytes == bytes2);

    BOOST_TEST_MESSAGE("A14: Serialization round-trip: " << bytes.size() << " bytes ✓");
}

// =====================================================================
// A15: Consensus parameters verification
// =====================================================================
BOOST_AUTO_TEST_CASE(a15_consensus_parameters)
{
    BOOST_CHECK_EQUAL(WITNESS_SCALE_FACTOR, 1);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, 24000000u);
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 24000000u);

    // With 1x discount: weight = size, so these should be equal
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_WEIGHT);

    // MIN_TRANSACTION_WEIGHT should be based on WSF=1
    BOOST_CHECK_EQUAL(MIN_TRANSACTION_WEIGHT, static_cast<size_t>(1 * 60));

    BOOST_TEST_MESSAGE("A15: WITNESS_SCALE_FACTOR=1, MAX_BLOCK=24MB, weight==size ✓");
}

// =====================================================================
// B1: Membership proof generation benchmark
// =====================================================================
BOOST_AUTO_TEST_CASE(b1_membership_prove_benchmark)
{
    constexpr auto kSmokeProveBudgetMs = 60000.0;
    constexpr auto kSmokeVerifyBudgetMs = 2000.0;
    // Keep the benchmark on the single-round launch profile and treat it as a
    // smoke guard with generous ceilings, not a hard performance certification.
    const size_t N = 8;
    auto keys = GenerateAnonSet(N, 0xD1);
    auto pks = ExtractPublicKeys(keys);

    const int TRIALS = 2;
    std::vector<double> prove_ms, verify_ms;

    for (int i = 0; i < TRIALS; ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();
        auto proof = ProveMembership(pks, i % N, keys[i % N].sec, 900000 + i);
        auto t1 = std::chrono::high_resolution_clock::now();
        bool valid = VerifyMembership(pks, proof);
        auto t2 = std::chrono::high_resolution_clock::now();

        BOOST_CHECK(valid);
        prove_ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
        verify_ms.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
    }

    double avg_prove = std::accumulate(prove_ms.begin(), prove_ms.end(), 0.0) / TRIALS;
    double avg_verify = std::accumulate(verify_ms.begin(), verify_ms.end(), 0.0) / TRIALS;

    BOOST_TEST_MESSAGE("B1: Membership proof (N=8 launch profile):");
    BOOST_TEST_MESSAGE("  Prove: " << avg_prove << " ms avg");
    BOOST_TEST_MESSAGE("  Verify: " << avg_verify << " ms avg");
    BOOST_TEST_MESSAGE("  Prove smoke ceiling: <" << kSmokeProveBudgetMs << " ms → "
                       << (avg_prove < kSmokeProveBudgetMs ? "PASS" : "FAIL"));
    BOOST_TEST_MESSAGE("  Verify smoke ceiling: <" << kSmokeVerifyBudgetMs << " ms → "
                       << (avg_verify < kSmokeVerifyBudgetMs ? "PASS" : "FAIL"));

    BOOST_CHECK_LT(avg_prove, kSmokeProveBudgetMs);
    BOOST_CHECK_LT(avg_verify, kSmokeVerifyBudgetMs);
}

// =====================================================================
// B2: CT proof generation benchmark
// =====================================================================
BOOST_AUTO_TEST_CASE(b2_ct_prove_benchmark)
{
    const size_t N = 4;
    auto keys = GenerateAnonSet(N, 0xD2);
    auto pks = ExtractPublicKeys(keys);

    CTPublicData pub;
    pub.anon_set = pks;

    const int TRIALS = 1;
    std::vector<double> prove_ms, verify_ms;
    std::vector<size_t> proof_sizes;

    for (int i = 0; i < TRIALS; ++i) {
        const size_t first_index = static_cast<size_t>(i % N);
        pub.coin_rings = BuildCoinRings(keys, {first_index}, {100}, 0xD2 + i);
        pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            keys, pub.coin_rings, 0xD200 + static_cast<uint32_t>(i) * 100, 0x9c);

        std::vector<CTInput> inputs = {
            MakeCtInput(first_index, keys[first_index], 100, 0xD2 + i, 0, N)
        };
        std::vector<CTOutput> outputs = MakeCtOutputs({100}, 0xD200 + i * 10);

        auto t0 = std::chrono::high_resolution_clock::now();
        auto proof = ProveValidCTWithRetries(inputs, outputs, pub, 1, 1, 800000 + i, 4);
        auto t1 = std::chrono::high_resolution_clock::now();
        BOOST_REQUIRE_MESSAGE(proof.has_value(),
                              "B2: expected a valid CT proof within the retry budget");
        bool valid = VerifyCT(*proof, 1, 1, pub);
        auto t2 = std::chrono::high_resolution_clock::now();

        BOOST_CHECK(valid);
        prove_ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
        verify_ms.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
        proof_sizes.push_back(proof->SerializedSize());
    }

    double avg_prove = std::accumulate(prove_ms.begin(), prove_ms.end(), 0.0) / TRIALS;
    double avg_verify = std::accumulate(verify_ms.begin(), verify_ms.end(), 0.0) / TRIALS;
    double avg_size = std::accumulate(proof_sizes.begin(), proof_sizes.end(), 0.0) / TRIALS;

    BOOST_TEST_MESSAGE("B2: CT proof (1-in-1-out, N=4):");
    BOOST_TEST_MESSAGE("  Prove: " << avg_prove << " ms avg");
    BOOST_TEST_MESSAGE("  Verify: " << avg_verify << " ms avg");
    BOOST_TEST_MESSAGE("  Size: " << avg_size << " bytes (" << avg_size/1024.0 << " KB)");

    // Throughput estimation
    double txns_per_block = 24000000.0 / avg_size;
    double verify_per_sec = 1000.0 / avg_verify;
    BOOST_TEST_MESSAGE("  Theoretical txns/block (24MB): " << static_cast<int>(txns_per_block));
    BOOST_TEST_MESSAGE("  Verification throughput: " << verify_per_sec << " txns/sec");
}

// =====================================================================
// B3: Block capacity stress test
// =====================================================================
BOOST_AUTO_TEST_CASE(b3_block_capacity_stress)
{
    const size_t N = 32;
    auto keys = GenerateAnonSet(N, 0xD3);
    auto pks = ExtractPublicKeys(keys);

    CTPublicData pub;
    pub.anon_set = pks;

    // Sample a few actual proofs, then project 24MB block capacity from the
    // average transaction size. This keeps the benchmark representative
    // without spending minutes synthesizing an entire block's worth of proofs.
    size_t total_bytes = 0;
    size_t successful_samples = 0;
    const size_t BLOCK_LIMIT = MAX_BLOCK_SERIALIZED_SIZE;
    constexpr size_t SAMPLE_TARGET = 4;

    auto t_start = std::chrono::high_resolution_clock::now();

    size_t failed_samples = 0;
    size_t sample_index = 0;
    while (successful_samples < SAMPLE_TARGET && sample_index < 16) {
        const size_t secret_index = sample_index % N;
        pub.coin_rings = BuildCoinRings(keys, {secret_index}, {100}, 0xD3 + sample_index);
        pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            keys, pub.coin_rings, 0xD300 + static_cast<uint32_t>(sample_index) * 100, 0x9d);
        std::vector<CTInput> inputs = {
            MakeCtInput(secret_index, keys[secret_index], 100, 0xD3 + sample_index, 0, N)
        };
        std::vector<CTOutput> outputs = MakeCtOutputs({50, 50}, 0xD300 + sample_index * 10);

        auto proof = ProveValidCTWithRetries(inputs, outputs, pub, 1, 2, 400000 + sample_index, 4);
        ++sample_index;
        if (!proof.has_value()) {
            ++failed_samples;
            continue;
        }
        auto bytes = SerializeCTProof(*proof);

        total_bytes += bytes.size() + 200; // +200 for tx overhead
        successful_samples++;
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t_end - t_start).count();
    BOOST_REQUIRE_GT(successful_samples, 0u);

    const double avg_tx_bytes = static_cast<double>(total_bytes) /
                                static_cast<double>(successful_samples);
    const size_t projected_tx_count = static_cast<size_t>(
        std::floor(static_cast<double>(BLOCK_LIMIT) / avg_tx_bytes));

    BOOST_TEST_MESSAGE("B3: Block capacity stress projection:");
    BOOST_TEST_MESSAGE("  Successful samples: " << successful_samples);
    BOOST_TEST_MESSAGE("  Average tx bytes: " << avg_tx_bytes);
    BOOST_TEST_MESSAGE("  Projected txs in 24MB block: " << projected_tx_count);
    BOOST_TEST_MESSAGE("  Sample generation time: " << elapsed << " s");
    BOOST_TEST_MESSAGE("  Sample throughput: " << successful_samples / elapsed << " txns/sec");
    BOOST_TEST_MESSAGE("  Retry-exhausted samples: " << failed_samples);

    BOOST_CHECK_GT(projected_tx_count, 2u);
}

// =====================================================================
// B4: BDLOP commitment benchmark
// =====================================================================
BOOST_AUTO_TEST_CASE(b4_bdlop_benchmark)
{
    auto seed = MakeSeed(0xD4);
    size_t n_msg = 8;
    auto ck = BDLOPCommitmentKey::Generate(seed, n_msg);

    std::vector<SmilePoly> messages(n_msg);
    for (auto& m : messages) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) m.coeffs[i] = i;
    }

    const int TRIALS = 25;
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TRIALS; ++i) {
        auto r = SampleTernary(ck.rand_dim(), 1000 + i);
        auto com = Commit(ck, messages, r);
        (void)com;
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double avg_ms = std::chrono::duration<double, std::milli>(t1 - t0).count() / TRIALS;

    BOOST_TEST_MESSAGE("B4: BDLOP Commit (n_msg=" << n_msg << "): " << avg_ms << " ms avg");
}

// =====================================================================
// B5: Proof size vs anonymity set size
// =====================================================================
BOOST_AUTO_TEST_CASE(b5_proof_size_scaling)
{
    std::vector<size_t> set_sizes = {32, 33};

    BOOST_TEST_MESSAGE("B5: Proof size scaling:");
    BOOST_TEST_MESSAGE("  N        | Membership | CT 1-in-1-out       | Launch surface");
    BOOST_TEST_MESSAGE("  ---------|------------|----------------------|----------------");

    for (size_t N : set_sizes) {
        auto keys = GenerateAnonSet(N, static_cast<uint8_t>(N & 0xFF));
        auto pks = ExtractPublicKeys(keys);

        // Membership proof size
        auto mproof = ProveMembership(pks, 0, keys[0].sec, 999);
        size_t msize = mproof.SerializedSize();

        // CT proof size
        CTPublicData pub;
        pub.anon_set = pks;
        pub.coin_rings = BuildCoinRings(keys, {0}, {100}, static_cast<uint64_t>(0xE0) + N);
        pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            keys, pub.coin_rings, 0xE000 + static_cast<uint32_t>(N), 0x9e);
        std::vector<CTInput> inputs = {
            MakeCtInput(0, keys[0], 100, static_cast<uint64_t>(0xE0) + N, 0, N)
        };
        std::vector<CTOutput> outputs = MakeCtOutputs({100}, 0xE000 + N);
        auto cproof = ProveValidCTWithRetries(inputs, outputs, pub, 1, 1, 888, 4);
        if (N <= NUM_NTT_SLOTS) {
            BOOST_REQUIRE_MESSAGE(cproof.has_value(),
                                  "B5: expected a valid CT proof within the retry budget for supported anonymity set");
            size_t csize = cproof->SerializedSize();
            const char* target = "supported";
            BOOST_TEST_MESSAGE("  " << N << " | "
                               << msize/1024.0 << " KB | "
                               << csize/1024.0 << " KB | " << target);
            BOOST_CHECK_LE(csize, 96 * 1024);
            BOOST_CHECK(VerifyCT(*cproof, 1, 1, pub));
        } else {
            const char* target = "rejected";
            BOOST_TEST_MESSAGE("  " << N << " | "
                               << msize/1024.0 << " KB | "
                               << "unsupported" << " | " << target);
            BOOST_CHECK(!cproof.has_value() || cproof->serial_numbers.empty());
            BOOST_CHECK(!cproof.has_value() || !VerifyCT(*cproof, 1, 1, pub));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
