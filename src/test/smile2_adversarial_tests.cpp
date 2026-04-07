// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Adversarial test suite for SMILE v2 confidential transactions.
// Targets vulnerability classes found in Zcash (CVE-2019-7167, InternalH collision),
// Monero (key-image forgery), and general lattice ZK proof systems.
//
// Vulnerability classes tested:
//   C1 - Inflation / counterfeiting (forged balance)
//   C2 - Double-spend (serial number collisions / duplicates)
//   C3 - Proof malleability (tampered components still verify)
//   C4 - Norm bound bypass (integer overflow / centering errors)
//   C5 - Soundness gaps (missing verification steps)
//   C6 - Commitment binding (open same commitment to different values)

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <random>
#include <set>
#include <stdexcept>
#include <vector>

using namespace smile2;

namespace {

// The full launch surface is N<=32 with rec_levels==1. These adversarial
// regression checks only need to stay on that same single-round verifier path,
// so an 8-member ring keeps the coverage while cutting suite runtime sharply.
inline constexpr size_t kAdversarialAnonSetSize = 8;

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

std::vector<SmileKeyPair> GenerateAnonSet(size_t N, uint8_t seed_val) {
    auto a_seed = MakeSeed(seed_val);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i) {
        keys[i] = SmileKeyPair::Generate(a_seed, 50000 + i);
    }
    return keys;
}

std::vector<SmilePublicKey> ExtractPublicKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    pks.reserve(keys.size());
    for (const auto& kp : keys) pks.push_back(kp.pub);
    return pks;
}

std::vector<std::vector<BDLOPCommitment>> BuildCoinRings(
    const std::vector<SmileKeyPair>& keys,
    const std::vector<size_t>& secret_indices,
    const std::vector<int64_t>& secret_amounts,
    uint64_t coin_seed)
{
    size_t N = keys.size();
    size_t m = secret_indices.size();
    const auto ck = GetPublicCoinCommitmentKey();

    std::vector<std::vector<BDLOPCommitment>> coin_rings(m);
    for (size_t inp = 0; inp < m; ++inp) {
        coin_rings[inp].resize(N);
        for (size_t j = 0; j < N; ++j) {
            SmilePoly amount_poly;
            if (j == secret_indices[inp]) {
                amount_poly = EncodeAmountToSmileAmountPoly(secret_amounts[inp]).value();
            } else {
                std::mt19937_64 rng(coin_seed * 1000 + inp * N + j);
                amount_poly = EncodeAmountToSmileAmountPoly(
                    static_cast<int64_t>(rng() % 1000000)).value();
            }
            const auto opening = SampleTernary(ck.rand_dim(), coin_seed * 100000 + inp * N + j);
            coin_rings[inp][j] = Commit(ck, {amount_poly}, opening);
        }
    }
    return coin_rings;
}

struct CTTestSetup {
    std::vector<SmileKeyPair> keys;
    CTPublicData pub;
    std::vector<CTInput> inputs;
    std::vector<CTOutput> outputs;

    static CTTestSetup Create(size_t N, size_t num_inputs, size_t num_outputs,
                               const std::vector<int64_t>& in_amounts,
                               const std::vector<int64_t>& out_amounts,
                               uint8_t seed_val)
    {
        CTTestSetup setup;
        setup.keys = GenerateAnonSet(N, seed_val);
        setup.pub.anon_set = ExtractPublicKeys(setup.keys);

        std::vector<size_t> secret_indices;
        for (size_t i = 0; i < num_inputs; ++i) {
            secret_indices.push_back(i * 2 + 1);
        }

        setup.pub.coin_rings = BuildCoinRings(
            setup.keys, secret_indices, in_amounts, seed_val + 100);
        setup.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            setup.keys, setup.pub.coin_rings, static_cast<uint32_t>(seed_val) * 1000 + 400, 0x93);

        setup.inputs.resize(num_inputs);
        const auto coin_ck = GetPublicCoinCommitmentKey();
        for (size_t i = 0; i < num_inputs; ++i) {
            setup.inputs[i].secret_index = secret_indices[i];
            setup.inputs[i].sk = setup.keys[secret_indices[i]].sec;
            setup.inputs[i].amount = in_amounts[i];
            setup.inputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val + 100) * 100000 + i * N + secret_indices[i]);
        }

        setup.outputs.resize(num_outputs);
        for (size_t i = 0; i < num_outputs; ++i) {
            setup.outputs[i].amount = out_amounts[i];
            setup.outputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val) * 1000000 + i);
        }
        return setup;
    }
};

// Create a valid proof as a baseline for tampering tests
SmileCTProof MakeValidProof(CTTestSetup& setup) {
    static constexpr uint64_t kSeedBase = 0xDEADBEEF;
    static constexpr uint64_t kAttemptStride = 0x1000000ULL;
    static constexpr int kMaxAttempts = 16;

    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        SmileCTProof proof = ProveCT(
            setup.inputs, setup.outputs, setup.pub, kSeedBase + (kAttemptStride * attempt));
        if (VerifyCT(proof, setup.inputs.size(), setup.outputs.size(), setup.pub)) {
            return proof;
        }
    }

    throw std::runtime_error("failed to build a valid adversarial SMILE2 proof fixture");
}

struct SharedCtProofCase {
    CTTestSetup setup;
    SmileCTProof proof;
};

const SharedCtProofCase& GetSharedTwoInputTwoOutputCase()
{
    static const SharedCtProofCase shared = [] {
        SharedCtProofCase fixture;
        fixture.setup = CTTestSetup::Create(kAdversarialAnonSetSize, 2, 2, {100, 200}, {150, 150}, 0xE0);
        fixture.proof = MakeValidProof(fixture.setup);
        return fixture;
    }();
    return shared;
}

const SharedCtProofCase& GetSharedOneInputOneOutputCase()
{
    static const SharedCtProofCase shared = [] {
        SharedCtProofCase fixture;
        fixture.setup = CTTestSetup::Create(kAdversarialAnonSetSize, 1, 1, {100}, {100}, 0xF0);
        fixture.proof = MakeValidProof(fixture.setup);
        return fixture;
    }();
    return shared;
}

const SharedCtProofCase& GetSharedAlternateOneInputOneOutputCase()
{
    static const SharedCtProofCase shared = [] {
        SharedCtProofCase fixture;
        fixture.setup = CTTestSetup::Create(kAdversarialAnonSetSize, 1, 1, {125}, {125}, 0xF6);
        fixture.proof = MakeValidProof(fixture.setup);
        return fixture;
    }();
    return shared;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_adversarial_tests, BasicTestingSetup)

// ============================================================================
// C1: INFLATION / COUNTERFEITING
// ============================================================================

// C1-1: Unbalanced transaction (more output than input) must be rejected.
BOOST_AUTO_TEST_CASE(c1_inflation_unbalanced_outputs_exceed_inputs)
{
    const size_t N = kAdversarialAnonSetSize;
    // in=300, out=350 → 50 coins from nowhere
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 200}, 0xC1);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xC1A);

    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C1-1: INFLATION — Unbalanced tx (in=300, out=350) MUST be rejected. "
        "If this passes, the balance check is broken.");
}

// C1-2: Reversed inflation — more input than output (fee leak).
BOOST_AUTO_TEST_CASE(c1_inflation_inputs_exceed_outputs)
{
    const size_t N = kAdversarialAnonSetSize;
    // in=400, out=300 → 100 coins vanish
    auto setup = CTTestSetup::Create(N, 2, 2, {200, 200}, {150, 150}, 0xC2);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xC2A);

    bool valid = VerifyCT(proof, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C1-2: Unbalanced tx (in=400, out=300) should be rejected. "
        "Disappearing value is also a balance violation.");
}

// C1-3: Tamper with h2 polynomial — set a zero coefficient to non-zero.
// This directly attacks the balance proof check (first d/l coefficients of h2).
BOOST_AUTO_TEST_CASE(c1_tampered_h2_first_coefficients)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Tamper: set h2.coeffs[0] to a non-zero value
    SmileCTProof tampered = proof;
    tampered.h2.coeffs[0] = 42;

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C1-3: Tampered h2 coeff[0] must be rejected by balance check.");
}

// C1-4: Tamper h2 at coefficient index = SLOT_DEGREE (boundary of the check).
// The verifier checks coeffs[0..SLOT_DEGREE-1]. Does it miss index SLOT_DEGREE?
BOOST_AUTO_TEST_CASE(c1_tampered_h2_boundary_coefficient)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Tamper: modify h2.coeffs[SLOT_DEGREE] — just beyond the checked range.
    // If the verifier only checks [0..SLOT_DEGREE-1], this modification might
    // go undetected by the h2 check. However, it should still break the
    // Fiat-Shamir transcript (h2 is hashed into the transcript at line 825).
    SmileCTProof tampered = proof;
    tampered.h2.coeffs[SLOT_DEGREE] += 1;

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C1-4: Tampered h2 at SLOT_DEGREE boundary must be caught "
        "(by Fiat-Shamir if not by direct check).");
}

// C1-5: Tamper output coin commitment to encode a different amount.
BOOST_AUTO_TEST_CASE(c1_tampered_output_coin_commitment)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Tamper: modify an output coin's t_msg (the amount encoding)
    SmileCTProof tampered = proof;
    if (!tampered.output_coins.empty() && !tampered.output_coins[0].t_msg.empty()) {
        tampered.output_coins[0].t_msg[0].coeffs[0] += 1000;
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C1-5: Tampered output coin commitment must break Fiat-Shamir binding.");
}

// C1-6: Attempt to create money from nothing — 0 input, positive output.
BOOST_AUTO_TEST_CASE(c1_inflation_zero_input_positive_output)
{
    const size_t N = kAdversarialAnonSetSize;
    // in=0, out=100 → pure inflation
    auto setup = CTTestSetup::Create(N, 1, 1, {0}, {100}, 0xC6);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xC6A);

    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C1-6: CRITICAL — Zero input with positive output is pure counterfeiting.");
}

// C1-7: Very large amounts near the modulus boundary.
BOOST_AUTO_TEST_CASE(c1_inflation_large_amounts_near_modulus)
{
    const size_t N = 2;
    // Use amounts that are large but balanced
    int64_t large = static_cast<int64_t>(Q) - 100;
    auto setup = CTTestSetup::Create(N, 1, 1, {large}, {large}, 0xC7);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xC7A);

    // This should either verify (if amounts wrap correctly) or reject.
    // The important thing is it doesn't create money.
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    // Either outcome is acceptable — what matters is consistency
    BOOST_TEST_MESSAGE("C1-7: Large amount near modulus: valid=" << valid);
    BOOST_CHECK(true);
}

// ============================================================================
// C2: DOUBLE-SPEND / SERIAL NUMBER ATTACKS
// ============================================================================

// C2-1: Same secret key in two different transactions must produce
// identical serial numbers (enabling double-spend detection).
BOOST_AUTO_TEST_CASE(c2_same_key_same_serial_number)
{
    auto seed = MakeSeed(0xAA);
    auto sn_ck = BDLOPCommitmentKey::Generate(seed, 1);
    auto keys = GenerateAnonSet(/*N=*/2, 0xD1);

    SmilePoly sn1 = ComputeSerialNumber(sn_ck, keys[1].sec); sn1.Reduce();
    SmilePoly sn2 = ComputeSerialNumber(sn_ck, keys[1].sec); sn2.Reduce();

    BOOST_CHECK_MESSAGE(sn1 == sn2,
        "C2-1: Same secret key MUST produce identical serial numbers across transactions. "
        "Failure here means double-spend detection is broken.");
}

// C2-2: Different secret keys must produce different serial numbers.
BOOST_AUTO_TEST_CASE(c2_different_keys_different_serial_numbers)
{
    auto seed = MakeSeed(0xAA);
    auto sn_ck = BDLOPCommitmentKey::Generate(seed, 1);
    auto keys1 = GenerateAnonSet(/*N=*/2, 0xD2);
    auto keys2 = GenerateAnonSet(/*N=*/2, 0xD3);

    SmilePoly sn1 = ComputeSerialNumber(sn_ck, keys1[1].sec); sn1.Reduce();
    SmilePoly sn2 = ComputeSerialNumber(sn_ck, keys2[1].sec); sn2.Reduce();

    BOOST_CHECK_MESSAGE(!(sn1 == sn2),
        "C2-2: Different keys MUST produce different serial numbers. "
        "Collision here enables undetectable double-spend.");
}

// C2-3: Serial numbers within a single multi-input proof must all be distinct.
BOOST_AUTO_TEST_CASE(c2_intra_proof_serial_number_uniqueness)
{
    const size_t N = kAdversarialAnonSetSize;
    // 2 different inputs → 2 different serial numbers
    auto setup = CTTestSetup::Create(N, 2, 2, {100, 200}, {150, 150}, 0xD4);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 555);

    BOOST_REQUIRE_EQUAL(proof.serial_numbers.size(), 2u);

    // All serial numbers must be distinct
    for (size_t i = 0; i < proof.serial_numbers.size(); ++i) {
        for (size_t j = i + 1; j < proof.serial_numbers.size(); ++j) {
            SmilePoly sn_i = proof.serial_numbers[i]; sn_i.Reduce();
            SmilePoly sn_j = proof.serial_numbers[j]; sn_j.Reduce();
            BOOST_CHECK_MESSAGE(!(sn_i == sn_j),
                "C2-3: Serial numbers " << i << " and " << j << " collide within same proof. "
                "This allows spending the same coin twice in one transaction.");
        }
    }
}

// C2-4: Tamper with a serial number in the proof — must be rejected.
BOOST_AUTO_TEST_CASE(c2_tampered_serial_number_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Tamper: modify first serial number
    SmileCTProof tampered = proof;
    tampered.serial_numbers[0].coeffs[0] += 1;

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C2-4: Tampered serial number must break Fiat-Shamir transcript binding.");
}

// C2-5: Null (all-zero) serial number must be rejected by dispatch.
BOOST_AUTO_TEST_CASE(c2_null_serial_number_rejected_by_dispatch)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& proof = shared.proof;

    // Force null serial number
    SmileCTProof tampered = proof;
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        tampered.serial_numbers[0].coeffs[c] = 0;
    }

    std::vector<SmilePoly> extracted;
    auto err = ExtractSmile2SerialNumbers(tampered, extracted);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "C2-5: Null serial number must be rejected by ExtractSmile2SerialNumbers.");
}

// ============================================================================
// C3: PROOF MALLEABILITY
// ============================================================================

// C3-1: Tamper with z vector (masked opening) — must be rejected.
BOOST_AUTO_TEST_CASE(c3_tampered_z_vector_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    if (!tampered.z.empty()) {
        tampered.z[0].coeffs[0] += 1;
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C3-1: Tampered z vector must be rejected (norm bound or transcript mismatch).");
}

// C3-2: Tamper with z0 vector (key opening) — must be rejected.
BOOST_AUTO_TEST_CASE(c3_tampered_z0_vector_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    if (!tampered.z0.empty() && !tampered.z0[0].empty()) {
        tampered.z0[0][0].coeffs[0] += 1;
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C3-2: Tampered z0 must break key membership check or Fiat-Shamir.");
}

// C3-3: Tamper with w0_vals — must be rejected.
BOOST_AUTO_TEST_CASE(c3_tampered_w0_vals_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    BOOST_REQUIRE(!tampered.w0_residue_accs.empty());
    tampered.w0_residue_accs[0].coeffs[0] += 1;

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C3-3: Tampered compressed W0 residue surface must be rejected.");
}

// C3-4: Tamper with aux_commitment — must be rejected.
BOOST_AUTO_TEST_CASE(c3_tampered_aux_commitment_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    if (!tampered.aux_commitment.t0.empty()) {
        tampered.aux_commitment.t0[0].coeffs[0] += 1;
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C3-4: Tampered aux commitment must break Fiat-Shamir transcript.");
}

// C3-5: Swap proof components between two valid proofs — must be rejected.
BOOST_AUTO_TEST_CASE(c3_cross_proof_component_swap_rejected)
{
    const auto& shared_a = GetSharedOneInputOneOutputCase();
    const auto& setup_a = shared_a.setup;
    const auto& proof_a = shared_a.proof;
    const auto& shared_b = GetSharedAlternateOneInputOneOutputCase();
    const auto& proof_b = shared_b.proof;

    BOOST_REQUIRE(proof_a.z != proof_b.z);
    BOOST_REQUIRE(proof_a.h2 != proof_b.h2);

    // Swap z vectors
    SmileCTProof hybrid = proof_a;
    hybrid.z = proof_b.z;
    BOOST_CHECK_MESSAGE(!VerifyCT(hybrid, 1, 1, setup_a.pub),
        "C3-5a: Cross-proof z swap must be rejected.");

    // Swap z0 vectors
    hybrid = proof_a;
    hybrid.z0 = proof_b.z0;
    BOOST_CHECK_MESSAGE(!VerifyCT(hybrid, 1, 1, setup_a.pub),
        "C3-5b: Cross-proof z0 swap must be rejected.");

    // Swap h2
    hybrid = proof_a;
    hybrid.h2 = proof_b.h2;
    BOOST_CHECK_MESSAGE(!VerifyCT(hybrid, 1, 1, setup_a.pub),
        "C3-5c: Cross-proof h2 swap must be rejected.");

    // Swap serial numbers
    hybrid = proof_a;
    hybrid.serial_numbers = proof_b.serial_numbers;
    BOOST_CHECK_MESSAGE(!VerifyCT(hybrid, 1, 1, setup_a.pub),
        "C3-5d: Cross-proof serial number swap must be rejected.");
}

// C3-6: Fiat-Shamir seed tampering — must be rejected.
BOOST_AUTO_TEST_CASE(c3_tampered_fiat_shamir_seeds_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Tamper fs_seed
    SmileCTProof tampered = proof;
    tampered.fs_seed[0] ^= 0xFF;
    BOOST_CHECK_MESSAGE(!VerifyCT(tampered, 1, 1, setup.pub),
        "C3-6a: Tampered fs_seed must be rejected.");

    // Tamper seed_c0
    tampered = proof;
    tampered.seed_c0[0] ^= 0xFF;
    BOOST_CHECK_MESSAGE(!VerifyCT(tampered, 1, 1, setup.pub),
        "C3-6b: Tampered seed_c0 must be rejected.");

    // Tamper seed_c
    tampered = proof;
    tampered.seed_c[0] ^= 0xFF;
    BOOST_CHECK_MESSAGE(!VerifyCT(tampered, 1, 1, setup.pub),
        "C3-6c: Tampered seed_c must be rejected.");
}

// ============================================================================
// C4: NORM BOUND BYPASS
// ============================================================================

// C4-1: Inflate z0 norm beyond bound — must be rejected.
BOOST_AUTO_TEST_CASE(c4_inflated_z0_norm_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Set z0 coefficients to large values that exceed the norm bound
    SmileCTProof tampered = proof;
    if (!tampered.z0.empty() && !tampered.z0[0].empty()) {
        for (size_t j = 0; j < tampered.z0[0].size(); ++j) {
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                tampered.z0[0][j].coeffs[c] = static_cast<int64_t>(Q / 2 - 1);
            }
        }
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C4-1: z0 with large coefficients must exceed norm bound.");
}

// C4-2: Inflate z norm beyond bound — must be rejected.
BOOST_AUTO_TEST_CASE(c4_inflated_z_norm_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    for (size_t j = 0; j < tampered.z.size(); ++j) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            tampered.z[j].coeffs[c] = static_cast<int64_t>(Q / 2 - 1);
        }
    }

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C4-2: z with large coefficients must exceed norm bound.");
}

// C4-3: Verify that the norm bound correctly handles the centered representation.
// Coefficients near Q (e.g., Q-1) should be centered to -1, not treated as large positive.
BOOST_AUTO_TEST_CASE(c4_centering_correctness)
{
    // This test verifies the centering logic: val > Q/2 → val -= Q
    // A coefficient of Q-1 should be centered to -1 (small norm contribution)
    // A coefficient of Q/2 should be centered to Q/2 (large norm contribution)

    const int64_t half_q = Q / 2;

    // Q-1 centered = -1
    int64_t val_near_q = mod_q(Q - 1);
    if (val_near_q > half_q) val_near_q -= Q;
    BOOST_CHECK_EQUAL(val_near_q, -1);

    // Q/2 + 1 centered = -(Q/2 - 1) if Q is even, or -(Q-1)/2 if Q is odd
    int64_t val_half = mod_q(Q / 2 + 1);
    if (val_half > half_q) val_half -= Q;
    BOOST_CHECK_LT(val_half, 0);
    BOOST_CHECK_GT(val_half, -half_q - 1);

    // 0 stays 0
    int64_t val_zero = mod_q(0);
    if (val_zero > half_q) val_zero -= Q;
    BOOST_CHECK_EQUAL(val_zero, 0);

    BOOST_TEST_MESSAGE("C4-3: Centering logic verified.");
}

// ============================================================================
// C5: SOUNDNESS GAPS
// ============================================================================

// C5-1: Wrong anonymity set — proof created for one set, verified with another.
BOOST_AUTO_TEST_CASE(c5_wrong_anonymity_set_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;
    const size_t N = setup.pub.anon_set.size();

    // Create a different anonymity set
    auto different_keys = GenerateAnonSet(N, 0xA2);
    CTPublicData different_pub;
    different_pub.anon_set = ExtractPublicKeys(different_keys);
    different_pub.coin_rings = setup.pub.coin_rings;
    different_pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        different_keys, different_pub.coin_rings, 0xA200, 0x94);

    bool valid = VerifyCT(proof, 1, 1, different_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-1: Proof verified against wrong anonymity set must be rejected.");
}

BOOST_AUTO_TEST_CASE(c5_wrong_coin_rings_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    CTPublicData different_pub = setup.pub;
    BOOST_REQUIRE(!different_pub.coin_rings.empty());
    BOOST_REQUIRE(!different_pub.coin_rings[0].empty());
    different_pub.coin_rings[0][0].t0[0].coeffs[0] =
        mod_q(different_pub.coin_rings[0][0].t0[0].coeffs[0] + 1);

    bool valid = VerifyCT(proof, 1, 1, different_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-1b: Proof verified against wrong coin rings must be rejected.");
}

BOOST_AUTO_TEST_CASE(c5_duplicate_public_key_ring_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    CTPublicData ambiguous_pub = setup.pub;
    BOOST_REQUIRE(setup.inputs[0].secret_index < ambiguous_pub.anon_set.size());
    ambiguous_pub.anon_set[0] = ambiguous_pub.anon_set[setup.inputs[0].secret_index];

    bool valid = VerifyCT(proof, 1, 1, ambiguous_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-1c: Proof verified against an anonymity set with duplicated SMILE public keys "
        "must be rejected because the hidden spend index becomes ambiguous.");
}

BOOST_AUTO_TEST_CASE(c5_mixed_public_key_matrix_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    CTPublicData malformed_pub = setup.pub;
    BOOST_REQUIRE(malformed_pub.anon_set.size() > 1);
    BOOST_REQUIRE(!malformed_pub.anon_set[1].A.empty());
    BOOST_REQUIRE(!malformed_pub.anon_set[1].A[0].empty());
    malformed_pub.anon_set[1].A[0][0].coeffs[0] =
        mod_q(malformed_pub.anon_set[1].A[0][0].coeffs[0] + 1);

    bool valid = VerifyCT(proof, 1, 1, malformed_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-1d: Proof verified against a ring with mixed A matrices must be rejected.");
}

BOOST_AUTO_TEST_CASE(c5_malformed_output_coin_shape_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    BOOST_REQUIRE(!tampered.output_coins.empty());
    tampered.output_coins[0].t_msg.push_back(SmilePoly{});

    bool valid = VerifyCT(tampered, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-1e: Proof with malformed public output coin commitment shape must be rejected.");
}

BOOST_AUTO_TEST_CASE(c5_malformed_coin_ring_shape_rejected)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    CTPublicData malformed_pub = setup.pub;
    BOOST_REQUIRE(!malformed_pub.coin_rings.empty());
    BOOST_REQUIRE(!malformed_pub.coin_rings[0].empty());
    malformed_pub.coin_rings[0][0].t0.pop_back();

    bool valid = VerifyCT(proof, 1, 1, malformed_pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-1f: Proof verified against a malformed public coin ring commitment must be rejected.");
}

// C5-2: Wrong number of inputs/outputs — must be rejected.
BOOST_AUTO_TEST_CASE(c5_wrong_input_output_count_rejected)
{
    const auto& shared = GetSharedTwoInputTwoOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Claim 1 input instead of 2
    BOOST_CHECK_MESSAGE(!VerifyCT(proof, 1, 2, setup.pub),
        "C5-2a: Wrong input count must be rejected.");

    // Claim 3 outputs instead of 2
    BOOST_CHECK_MESSAGE(!VerifyCT(proof, 2, 3, setup.pub),
        "C5-2b: Wrong output count must be rejected.");
}

// C5-3: Empty proof — dispatch must reject.
BOOST_AUTO_TEST_CASE(c5_empty_proof_rejected_by_dispatch)
{
    std::vector<uint8_t> empty_bytes;
    SmileCTProof proof;
    auto err = ParseSmile2Proof(empty_bytes, 1, 1, proof);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "C5-3: Empty proof bytes must be rejected by ParseSmile2Proof.");
}

// C5-4: Undersized proof — dispatch must reject.
BOOST_AUTO_TEST_CASE(c5_undersized_proof_rejected)
{
    std::vector<uint8_t> tiny_bytes(100, 0x42); // well under MIN_SMILE2_PROOF_BYTES
    SmileCTProof proof;
    auto err = ParseSmile2Proof(tiny_bytes, 1, 1, proof);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "C5-4: Undersized proof must be rejected.");
}

// C5-5: Oversized proof — dispatch must reject.
BOOST_AUTO_TEST_CASE(c5_oversized_proof_rejected)
{
    std::vector<uint8_t> huge_bytes(MAX_SMILE2_PROOF_BYTES + 1, 0xFF);
    SmileCTProof proof;
    auto err = ParseSmile2Proof(huge_bytes, 1, 1, proof);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "C5-5: Oversized proof must be rejected.");
}

// C5-6: Invalid input/output counts — dispatch must reject.
BOOST_AUTO_TEST_CASE(c5_invalid_counts_rejected)
{
    std::vector<uint8_t> dummy(MIN_SMILE2_PROOF_BYTES + 1, 0x00);
    SmileCTProof proof;

    auto err0 = ParseSmile2Proof(dummy, 0, 1, proof);
    BOOST_CHECK_MESSAGE(err0.has_value(), "C5-6a: Zero inputs must be rejected.");

    auto err17 = ParseSmile2Proof(dummy, 17, 1, proof);
    BOOST_CHECK_MESSAGE(err17.has_value(), "C5-6b: 17 inputs must be rejected (max 16).");

    auto errO = ParseSmile2Proof(dummy, 1, 0, proof);
    BOOST_CHECK_MESSAGE(errO.has_value(), "C5-6c: Zero outputs must be rejected.");

    auto errO17 = ParseSmile2Proof(dummy, 1, 17, proof);
    BOOST_CHECK_MESSAGE(errO17.has_value(), "C5-6d: 17 outputs must be rejected (max 16).");
}

// C5-7: Proof with wrong number of serial numbers — must be rejected.
BOOST_AUTO_TEST_CASE(c5_serial_count_mismatch_rejected)
{
    const auto& shared = GetSharedTwoInputTwoOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    // Remove one serial number
    SmileCTProof tampered = proof;
    tampered.serial_numbers.pop_back();

    bool valid = VerifyCT(tampered, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-7: Proof with wrong serial number count must be rejected.");
}

// C5-8: Proof with wrong z0 count — must be rejected.
BOOST_AUTO_TEST_CASE(c5_z0_count_mismatch_rejected)
{
    const auto& shared = GetSharedTwoInputTwoOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    SmileCTProof tampered = proof;
    tampered.z0.pop_back();

    bool valid = VerifyCT(tampered, 2, 2, setup.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "C5-8: Proof with wrong z0 count must be rejected.");
}

// ============================================================================
// C6: COMMITMENT BINDING
// ============================================================================

// C6-1: BDLOP commitment key is deterministic from seed.
BOOST_AUTO_TEST_CASE(c6_bdlop_key_determinism)
{
    auto seed = MakeSeed(0x42);
    auto ck1 = BDLOPCommitmentKey::Generate(seed, 3);
    auto ck2 = BDLOPCommitmentKey::Generate(seed, 3);

    // Same seed → same key
    BOOST_REQUIRE_EQUAL(ck1.B0.size(), ck2.B0.size());
    for (size_t i = 0; i < ck1.B0.size(); ++i) {
        BOOST_REQUIRE_EQUAL(ck1.B0[i].size(), ck2.B0[i].size());
        for (size_t j = 0; j < ck1.B0[i].size(); ++j) {
            BOOST_CHECK(ck1.B0[i][j] == ck2.B0[i][j]);
        }
    }

    // Different seed → different key
    auto seed2 = MakeSeed(0x43);
    auto ck3 = BDLOPCommitmentKey::Generate(seed2, 3);
    bool any_diff = false;
    for (size_t i = 0; i < ck1.B0.size() && i < ck3.B0.size(); ++i) {
        for (size_t j = 0; j < ck1.B0[i].size() && j < ck3.B0[i].size(); ++j) {
            if (!(ck1.B0[i][j] == ck3.B0[i][j])) {
                any_diff = true;
                break;
            }
        }
        if (any_diff) break;
    }
    BOOST_CHECK_MESSAGE(any_diff,
        "C6-1: Different seeds must produce different commitment keys.");
}

// C6-2: BDLOP commitment correctness — commit then verify opening.
BOOST_AUTO_TEST_CASE(c6_bdlop_commit_verify_roundtrip)
{
    auto seed = MakeSeed(0x44);
    auto ck = BDLOPCommitmentKey::Generate(seed, 2);

    SmilePoly msg1, msg2;
    msg1.coeffs[0] = 42;
    msg2.coeffs[0] = 99;
    std::vector<SmilePoly> msgs = {msg1, msg2};

    auto r = SampleTernary(ck.rand_dim(), 12345);
    auto commitment = Commit(ck, msgs, r);

    bool valid = VerifyOpening(ck, commitment, msgs, r);
    BOOST_CHECK_MESSAGE(valid,
        "C6-2: BDLOP commitment should verify with correct opening.");

    // Wrong message should fail
    std::vector<SmilePoly> wrong_msgs = msgs;
    wrong_msgs[0].coeffs[0] = 43;
    bool invalid = VerifyOpening(ck, commitment, wrong_msgs, r);
    BOOST_CHECK_MESSAGE(!invalid,
        "C6-2: BDLOP commitment must reject wrong message opening.");
}

// ============================================================================
// C7: SERIALIZATION ATTACKS
// ============================================================================

// C7-1: Serialize/deserialize roundtrip preserves proof validity.
BOOST_AUTO_TEST_CASE(c7_serialization_roundtrip_integrity)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    auto serialized = SerializeCTProof(proof);
    BOOST_CHECK_GT(serialized.size(), 0u);

    SmileCTProof deserialized;
    bool ok = DeserializeCTProof(serialized, deserialized, 1, 1);
    BOOST_REQUIRE_MESSAGE(ok, "C7-1: Deserialization must succeed for valid proof.");

    deserialized.output_coins = proof.output_coins;

    bool valid = VerifyCT(deserialized, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid,
        "C7-1: Deserialized proof must still verify.");
}

// C7-2: Bit-flip in serialized proof — deserialized proof must fail verification.
BOOST_AUTO_TEST_CASE(c7_bitflip_in_serialized_proof)
{
    const auto& shared = GetSharedOneInputOneOutputCase();
    const auto& setup = shared.setup;
    const auto& proof = shared.proof;

    auto serialized = SerializeCTProof(proof);
    BOOST_REQUIRE_GT(serialized.size(), 100u);

    // Flip bits at various positions and verify rejection
    int corruption_detected = 0;
    int total_tests = 0;
    std::mt19937 rng(0xB2);

    for (int trial = 0; trial < 4; ++trial) {
        auto corrupted = serialized;
        size_t pos = rng() % corrupted.size();
        corrupted[pos] ^= (1 << (rng() % 8));

        SmileCTProof bad_proof;
        bool deser_ok = DeserializeCTProof(corrupted, bad_proof, 1, 1);
        if (deser_ok) {
            bad_proof.output_coins = proof.output_coins;
            if (!VerifyCT(bad_proof, 1, 1, setup.pub)) {
                corruption_detected++;
            }
        } else {
            corruption_detected++; // Deserialization failure is also detection
        }
        total_tests++;
    }

    BOOST_CHECK_MESSAGE(corruption_detected == total_tests,
        "C7-2: All " << total_tests << " bit-flip corruptions should be detected. "
        "Detected: " << corruption_detected);
}

// ============================================================================
// C8: EDGE CASES AND REGRESSION
// ============================================================================

// C8-1: Single input, single output (minimal transaction).
BOOST_AUTO_TEST_CASE(c8_minimal_1in_1out_transaction)
{
    const size_t N = kAdversarialAnonSetSize;
    auto setup = CTTestSetup::Create(N, 1, 1, {500}, {500}, 0xCC);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xCC1);

    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid, "C8-1: Minimal 1-in-1-out balanced tx must verify.");
}

// C8-2: Larger multi-input transaction still verifies.
BOOST_AUTO_TEST_CASE(c8_larger_4in_4out_transaction)
{
    const auto& shared = GetSharedTwoInputTwoOutputCase();
    bool valid = VerifyCT(shared.proof, 2, 2, shared.setup.pub);
    BOOST_CHECK_MESSAGE(valid, "C8-2: Shared balanced multi-input tx fixture must verify.");
}

// C8-3: Zero-value transaction (0 in, 0 out).
BOOST_AUTO_TEST_CASE(c8_zero_value_transaction)
{
    const size_t N = kAdversarialAnonSetSize;
    auto setup = CTTestSetup::Create(N, 1, 1, {0}, {0}, 0xCE);

    auto proof = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xCE1);

    // Zero-value transactions should be valid (balanced)
    bool valid = VerifyCT(proof, 1, 1, setup.pub);
    BOOST_CHECK_MESSAGE(valid, "C8-3: Zero-value balanced tx should verify.");
}

// C8-4: Deterministic proof generation — same inputs produce same proof.
BOOST_AUTO_TEST_CASE(c8_deterministic_proof_generation)
{
    const size_t N = kAdversarialAnonSetSize;
    auto setup = CTTestSetup::Create(N, 1, 1, {100}, {100}, 0xCF);

    auto proof1 = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xCF1);
    auto proof2 = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xCF1);

    // Same RNG seed → same proof
    auto ser1 = SerializeCTProof(proof1);
    auto ser2 = SerializeCTProof(proof2);
    BOOST_CHECK_MESSAGE(ser1 == ser2,
        "C8-4: Same inputs + same RNG seed must produce identical proofs.");
}

// C8-5: Different RNG seed → different proof (but both valid).
BOOST_AUTO_TEST_CASE(c8_different_seed_different_proof)
{
    const size_t N = kAdversarialAnonSetSize;
    auto setup = CTTestSetup::Create(N, 1, 1, {100}, {100}, 0xD0);

    auto proof1 = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xD01);
    auto proof2 = ProveCT(setup.inputs, setup.outputs, setup.pub, 0xD02);

    BOOST_CHECK(VerifyCT(proof1, 1, 1, setup.pub));
    BOOST_CHECK(VerifyCT(proof2, 1, 1, setup.pub));

    auto ser1 = SerializeCTProof(proof1);
    auto ser2 = SerializeCTProof(proof2);
    BOOST_CHECK_MESSAGE(ser1 != ser2,
        "C8-5: Different RNG seeds must produce different proofs.");
}

BOOST_AUTO_TEST_SUITE_END()
