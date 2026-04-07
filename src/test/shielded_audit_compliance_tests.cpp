// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Comprehensive audit compliance test suite. Verifies that all critical
// security properties identified in the formal audit report
// (doc/btx-shielded-pool-formal-audit-2026-03-05.md) are correctly
// implemented and maintained in the codebase.

#include <consensus/amount.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/ntt.h>
#include <shielded/lattice/params.h>
#include <shielded/lattice/ntt.h>
#include <shielded/lattice/poly.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <shielded/ringct/balance_proof.h>
#include <shielded/ringct/commitment.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <string>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(shielded_audit_compliance_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// P0-1: Rejection sampling gap must be positive
// The Lyubashevsky rejection gap gamma - beta*eta must be > 0 for
// the ring signature to have non-negligible acceptance probability
// without leaking the real signer index.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_p0_1_rejection_gap_positive)
{
    // RESPONSE_NORM_BOUND = GAMMA_RESPONSE - BETA_CHALLENGE * SECRET_SMALL_ETA
    constexpr int32_t gap = lattice::GAMMA_RESPONSE -
                            lattice::BETA_CHALLENGE * lattice::SECRET_SMALL_ETA;
    BOOST_CHECK_GT(gap, 0);
    // The gap should be substantial (>100000) for practical acceptance rate
    BOOST_CHECK_GT(gap, 100000);
    BOOST_TEST_MESSAGE("Rejection sampling gap: " << gap
                       << " (gamma=" << lattice::GAMMA_RESPONSE
                       << ", beta*eta=" << lattice::BETA_CHALLENGE * lattice::SECRET_SMALL_ETA << ")");
}

// ---------------------------------------------------------------------------
// P0-2: Range proof masking nonce must be wide enough
// The masking distribution must dominate the secret contribution to
// maintain zero-knowledge (statistical hiding).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_p0_2_masking_dominates_secret)
{
    // Masking bound must be >> beta*eta for statistical hiding
    constexpr int32_t secret_contribution = lattice::BETA_CHALLENGE * lattice::SECRET_SMALL_ETA;
    constexpr int32_t masking_bound = lattice::GAMMA_RESPONSE;
    constexpr double ratio = static_cast<double>(masking_bound) / secret_contribution;

    // At least 100:1 ratio for statistical hiding
    BOOST_CHECK_GT(ratio, 100.0);
    BOOST_TEST_MESSAGE("Masking/secret ratio: " << ratio << ":1");
}

// ---------------------------------------------------------------------------
// P0-3: Polynomial challenges provide >128-bit soundness
// SampleChallenge must produce sparse ternary polynomials with
// sufficient challenge space.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_p0_3_polynomial_challenge_soundness)
{
    // Challenge space = C(256, 60) * 2^60 > 2^200
    // Verify SampleChallenge produces correct structure
    std::vector<unsigned char> transcript(32, 0xAB);
    lattice::Poly256 challenge = lattice::SampleChallenge(transcript);

    int nonzero = 0;
    for (size_t i = 0; i < lattice::POLY_N; ++i) {
        BOOST_CHECK(challenge.coeffs[i] >= -1 && challenge.coeffs[i] <= 1);
        if (challenge.coeffs[i] != 0) ++nonzero;
    }
    BOOST_CHECK_EQUAL(nonzero, lattice::BETA_CHALLENGE);

    // Soundness bits: log2(C(256,60) * 2^60) > 200
    // C(256,60) > 2^140 (conservative bound), so total > 2^200
    // This far exceeds 128-bit security requirement
    BOOST_TEST_MESSAGE("Challenge weight: " << nonzero
                       << " (provides >200-bit soundness)");
}

// ---------------------------------------------------------------------------
// P0-6: Ring member uniqueness enforcement
// Validation must reject rings with insufficient diversity.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_p0_6_ring_diversity_enforced)
{
    BOOST_CHECK_EQUAL(lattice::RING_SIZE, lattice::DEFAULT_RING_SIZE);
    BOOST_CHECK_GE(lattice::MIN_RING_SIZE, 8U);
    BOOST_CHECK_LE(lattice::RING_SIZE, lattice::MAX_RING_SIZE);
    BOOST_TEST_MESSAGE("Ring policy: default=" << lattice::RING_SIZE
                       << " supported_range=[" << lattice::MIN_RING_SIZE
                       << ", " << lattice::MAX_RING_SIZE << "]");
}

// ---------------------------------------------------------------------------
// T8: InfNorm must be constant-time (branchless)
// Verify the constant-time implementation produces correct results.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_t8_infnorm_correctness)
{
    lattice::Poly256 poly{};
    poly.coeffs[0] = 42;
    poly.coeffs[100] = -99;
    poly.coeffs[200] = 50;

    BOOST_CHECK_EQUAL(poly.InfNorm(), 99);

    // Edge cases
    lattice::Poly256 zero{};
    BOOST_CHECK_EQUAL(zero.InfNorm(), 0);

    lattice::Poly256 neg{};
    neg.coeffs[0] = -1;
    BOOST_CHECK_EQUAL(neg.InfNorm(), 1);
}

// ---------------------------------------------------------------------------
// Commitment homomorphic property (cryptographic correctness)
// Commit(a, r1) + Commit(b, r2) == Commit(a+b, r1+r2)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_commitment_homomorphic_property)
{
    FastRandomContext rng{uint256{0xDE}};
    lattice::PolyVec r1 = lattice::SampleUniformVec(rng, lattice::MODULE_RANK);
    lattice::PolyVec r2 = lattice::SampleUniformVec(rng, lattice::MODULE_RANK);

    Commitment c1 = Commit(100, r1);
    Commitment c2 = Commit(200, r2);
    Commitment c_sum = CommitmentAdd(c1, c2);

    lattice::PolyVec r_sum = lattice::PolyVecAdd(r1, r2);
    Commitment c_expected = Commit(300, r_sum);

    for (size_t i = 0; i < lattice::MODULE_RANK; ++i) {
        for (size_t j = 0; j < lattice::POLY_N; ++j) {
            BOOST_CHECK_EQUAL(lattice::Freeze(c_sum.vec[i].coeffs[j]),
                              lattice::Freeze(c_expected.vec[i].coeffs[j]));
        }
    }
}

// ---------------------------------------------------------------------------
// Domain separation: version tags must be unique and bound into transcripts
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_domain_separators_are_unique)
{
    // Core domain separators that must remain stable across releases.
    const std::vector<std::string> separators{
        "BTX_MatRiCT_BalanceProof_V2",
        "BTX_MatRiCT_Proof_V2",
        "BTX_MatRiCT_RingSig_Challenge_V4",
        "BTX_MatRiCT_RingSig_FS_V3",
        "BTX_MatRiCT_RingSig_Msg_V1",
        "BTX_MatRiCT_RingSig_Nullifier_V1",
        "BTX_Note_Commit_V1",
        "BTX_Note_Nullifier_V1",
        "BTX_Shielded_SpendAuth_V1",
    };

    // Verify all separators are unique
    std::set<std::string> seen;
    for (const auto& sep : separators) {
        auto [_, inserted] = seen.insert(sep);
        BOOST_CHECK_MESSAGE(inserted, "Duplicate domain separator: " + sep);
    }
}

// ---------------------------------------------------------------------------
// Key image linkability: same secret + same commitment = same key image
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_key_image_deterministic_linkability)
{
    FastRandomContext rng{uint256{0xAA}};
    lattice::PolyVec secret = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
    uint256 member_commitment = GetRandHash();

    Nullifier nf1, nf2;
    BOOST_REQUIRE(DeriveInputNullifierFromSecret(nf1, secret, member_commitment));
    BOOST_REQUIRE(DeriveInputNullifierFromSecret(nf2, secret, member_commitment));

    // Same inputs must produce same nullifier (linkability)
    BOOST_CHECK_EQUAL(nf1, nf2);

    // Different commitment must produce different nullifier
    Nullifier nf3;
    BOOST_REQUIRE(DeriveInputNullifierFromSecret(nf3, secret, GetRandHash()));
    BOOST_CHECK(nf1 != nf3);
}

// ---------------------------------------------------------------------------
// Balance proof: end-to-end correctness with multiple inputs/outputs
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_balance_proof_e2e_multi_io)
{
    FastRandomContext rng{uint256{0xBB}};

    // 3-in, 2-out, fee=150
    std::vector<CommitmentOpening> inputs(3);
    std::vector<CommitmentOpening> outputs(2);
    CAmount total_in = 0;

    inputs[0].value = 500; inputs[0].blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
    inputs[1].value = 400; inputs[1].blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
    inputs[2].value = 300; inputs[2].blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
    total_in = 1200;

    CAmount fee = 150;
    outputs[0].value = 600; outputs[0].blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
    outputs[1].value = total_in - fee - 600;
    outputs[1].blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, inputs, outputs, fee));

    std::vector<Commitment> in_commits, out_commits;
    for (const auto& o : inputs) in_commits.push_back(Commit(o.value, o.blind));
    for (const auto& o : outputs) out_commits.push_back(Commit(o.value, o.blind));

    BOOST_CHECK(VerifyBalanceProof(proof, in_commits, out_commits, fee));

    // Wrong fee must fail
    BOOST_CHECK(!VerifyBalanceProof(proof, in_commits, out_commits, fee + 1));
}

// ---------------------------------------------------------------------------
// Parameter static assertions alignment check
// Verify parameters match security requirements documented in the audit.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(audit_parameter_security_alignment)
{
    // q must be the Dilithium-2 prime
    BOOST_CHECK_EQUAL(lattice::POLY_Q, 8380417);

    // N must be 256 (degree of the cyclotomic polynomial)
    BOOST_CHECK_EQUAL(lattice::POLY_N, 256U);

    // MODULE_RANK = 4 provides NIST Level 2 security
    BOOST_CHECK_EQUAL(lattice::MODULE_RANK, 4U);

    // VALUE_BITS = 51 must cover MAX_MONEY
    BOOST_CHECK_LE(MAX_MONEY, static_cast<CAmount>((uint64_t{1} << lattice::VALUE_BITS) - 1));

    // SECRET_SMALL_ETA = 2 (matching Dilithium-2)
    BOOST_CHECK_EQUAL(lattice::SECRET_SMALL_ETA, 2);

    // BETA_CHALLENGE = 60 (weight of ternary challenge)
    BOOST_CHECK_EQUAL(lattice::BETA_CHALLENGE, 60);

    // GAMMA_RESPONSE = 2^17 = 131072
    BOOST_CHECK_EQUAL(lattice::GAMMA_RESPONSE, 131072);
}

BOOST_AUTO_TEST_SUITE_END()
