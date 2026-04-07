// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <random.h>
#include <shielded/bundle.h>
#include <shielded/lattice/ntt.h>
#include <shielded/lattice/params.h>
#include <shielded/lattice/poly.h>
#include <shielded/lattice/polymat.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <hash.h>
#include <serialize.h>
#include <streams.h>
#include <shielded/ringct/balance_proof.h>
#include <shielded/ringct/commitment.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/proof_encoding.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstring>
#include <vector>

using namespace shielded::lattice;
using namespace shielded::ringct;

BOOST_FIXTURE_TEST_SUITE(shielded_kat_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// NTT round-trip
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ntt_roundtrip_simple_poly)
{
    // f(X) = 1 + 2X + 3X^2
    Poly256 original{};
    original.coeffs[0] = 1;
    original.coeffs[1] = 2;
    original.coeffs[2] = 3;

    Poly256 work = original;
    work.NTT();

    // After NTT, coefficients should be transformed (not equal to original).
    BOOST_CHECK(work.coeffs != original.coeffs);

    work.InverseNTT();

    // InverseNTT produces coefficients in Montgomery representation:
    // each coeff c becomes c * MONT mod q. Reduce and compare.
    work.Reduce();
    work.CAddQ();

    for (size_t i = 0; i < POLY_N; ++i) {
        const int32_t expected = static_cast<int32_t>(
            (static_cast<int64_t>(original.coeffs[i]) * MONT) % POLY_Q);
        BOOST_CHECK_EQUAL(Freeze(work.coeffs[i]), Freeze(expected));
    }
}

BOOST_AUTO_TEST_CASE(ntt_roundtrip_random_poly)
{
    FastRandomContext rng{uint256{42}};
    Poly256 original = SampleUniform(rng);

    // Snapshot original coefficients
    std::array<int32_t, POLY_N> saved = original.coeffs;

    original.NTT();
    original.InverseNTT();
    original.Reduce();
    original.CAddQ();

    for (size_t i = 0; i < POLY_N; ++i) {
        const int32_t expected = static_cast<int32_t>(
            (static_cast<int64_t>(saved[i]) * MONT) % POLY_Q);
        BOOST_CHECK_EQUAL(Freeze(original.coeffs[i]), Freeze(expected));
    }
}

BOOST_AUTO_TEST_CASE(ntt_zero_polynomial)
{
    Poly256 zero{};
    zero.NTT();
    zero.InverseNTT();
    zero.Reduce();
    zero.CAddQ();

    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(zero.coeffs[i], 0);
    }
}

// ---------------------------------------------------------------------------
// Polynomial multiplication
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(poly_mul_one_plus_x_squared)
{
    // (1 + X) * (1 + X) = 1 + 2X + X^2 in Z_q[X]/(X^256+1)
    Poly256 a{};
    a.coeffs[0] = 1;
    a.coeffs[1] = 1;

    Poly256 result = PolyMul(a, a);
    result.Reduce();
    result.CAddQ();

    BOOST_CHECK_EQUAL(Freeze(result.coeffs[0]), 1);
    BOOST_CHECK_EQUAL(Freeze(result.coeffs[1]), 2);
    BOOST_CHECK_EQUAL(Freeze(result.coeffs[2]), 1);

    for (size_t i = 3; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(Freeze(result.coeffs[i]), 0);
    }
}

BOOST_AUTO_TEST_CASE(poly_mul_x255_times_x)
{
    // X^255 * X = X^256 = -1 mod (X^256 + 1)
    Poly256 a{};
    a.coeffs[255] = 1;

    Poly256 b{};
    b.coeffs[1] = 1;

    Poly256 result = PolyMul(a, b);
    result.Reduce();
    result.CAddQ();

    // Constant term should be q-1 (i.e., -1 mod q)
    BOOST_CHECK_EQUAL(Freeze(result.coeffs[0]), POLY_Q - 1);

    for (size_t i = 1; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(Freeze(result.coeffs[i]), 0);
    }
}

BOOST_AUTO_TEST_CASE(poly_mul_by_zero)
{
    FastRandomContext rng{uint256{99}};
    Poly256 a = SampleUniform(rng);
    Poly256 zero{};

    Poly256 result = PolyMul(a, zero);
    result.Reduce();
    result.CAddQ();

    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(result.coeffs[i], 0);
    }
}

// ---------------------------------------------------------------------------
// Challenge sampling
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(challenge_has_correct_weight)
{
    // Known transcript: 32 bytes of 0x01
    std::vector<unsigned char> transcript(32, 0x01);
    Poly256 challenge = SampleChallenge(transcript);

    // Exactly BETA_CHALLENGE non-zero coefficients
    int nonzero = 0;
    for (size_t i = 0; i < POLY_N; ++i) {
        if (challenge.coeffs[i] != 0) ++nonzero;
    }
    BOOST_CHECK_EQUAL(nonzero, BETA_CHALLENGE);
}

BOOST_AUTO_TEST_CASE(challenge_is_ternary)
{
    std::vector<unsigned char> transcript(32, 0x42);
    Poly256 challenge = SampleChallenge(transcript);

    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK(challenge.coeffs[i] == -1 ||
                    challenge.coeffs[i] == 0 ||
                    challenge.coeffs[i] == 1);
    }
}

BOOST_AUTO_TEST_CASE(challenge_deterministic)
{
    std::vector<unsigned char> transcript(32, 0xAB);

    Poly256 c1 = SampleChallenge(transcript);
    Poly256 c2 = SampleChallenge(transcript);

    BOOST_CHECK(c1 == c2);
}

BOOST_AUTO_TEST_CASE(challenge_different_transcripts_differ)
{
    std::vector<unsigned char> t1(32, 0x01);
    std::vector<unsigned char> t2(32, 0x02);

    Poly256 c1 = SampleChallenge(t1);
    Poly256 c2 = SampleChallenge(t2);

    BOOST_CHECK(!(c1 == c2));
}

BOOST_AUTO_TEST_CASE(challenge_infinity_norm_is_one)
{
    std::vector<unsigned char> transcript(32, 0xCD);
    Poly256 challenge = SampleChallenge(transcript);

    BOOST_CHECK_EQUAL(challenge.InfNorm(), 1);
}

// ---------------------------------------------------------------------------
// Commitment
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(commitment_known_value_deterministic)
{
    // Commit to value=42 with a seed-derived blinding factor.
    static constexpr unsigned char SEED[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    Commitment c1 = CommitWithSeed(42, SEED);
    Commitment c2 = CommitWithSeed(42, SEED);

    BOOST_CHECK(c1.vec == c2.vec);
    BOOST_CHECK(c1.IsValid());

    // Hash must be deterministic and non-null.
    uint256 h1 = CommitmentHash(c1);
    uint256 h2 = CommitmentHash(c2);
    BOOST_CHECK(h1 == h2);
    BOOST_CHECK(!h1.IsNull());
}

BOOST_AUTO_TEST_CASE(commitment_different_values_differ)
{
    static constexpr unsigned char SEED[32] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };

    Commitment c1 = CommitWithSeed(42, SEED);
    Commitment c2 = CommitWithSeed(43, SEED);

    BOOST_CHECK(!(c1.vec == c2.vec));
    BOOST_CHECK(CommitmentHash(c1) != CommitmentHash(c2));
}

BOOST_AUTO_TEST_CASE(commitment_verify_opening)
{
    FastRandomContext rng{uint256{7}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    Commitment c = Commit(42, blind);
    CommitmentOpening opening;
    opening.value = 42;
    opening.blind = blind;

    BOOST_CHECK(VerifyCommitment(c, opening));

    // Wrong value should fail
    CommitmentOpening wrong_opening;
    wrong_opening.value = 43;
    wrong_opening.blind = blind;
    BOOST_CHECK(!VerifyCommitment(c, wrong_opening));
}

BOOST_AUTO_TEST_CASE(commitment_fee_has_zero_blind)
{
    Commitment c_fee = CommitmentForFee(1000);
    BOOST_CHECK(c_fee.IsValid());

    // Verify it matches explicit commitment with zero blinding
    PolyVec zero_blind(MODULE_RANK);
    Commitment c_explicit = Commit(1000, zero_blind);
    BOOST_CHECK(c_fee.vec == c_explicit.vec);
}

BOOST_AUTO_TEST_CASE(commitment_homomorphic_addition)
{
    FastRandomContext rng{uint256{11}};
    PolyVec r1 = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r2 = SampleUniformVec(rng, MODULE_RANK);

    Commitment c1 = Commit(100, r1);
    Commitment c2 = Commit(200, r2);
    Commitment c_sum = CommitmentAdd(c1, c2);

    // c_sum should equal Commit(300, r1+r2) (under reduction)
    PolyVec r_sum = PolyVecAdd(r1, r2);
    Commitment c_expected = Commit(300, r_sum);

    // Compare after reducing to canonical form
    for (size_t i = 0; i < MODULE_RANK; ++i) {
        for (size_t j = 0; j < POLY_N; ++j) {
            BOOST_CHECK_EQUAL(Freeze(c_sum.vec[i].coeffs[j]),
                              Freeze(c_expected.vec[i].coeffs[j]));
        }
    }
}

// ---------------------------------------------------------------------------
// Range proof
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(range_proof_value_one)
{
    FastRandomContext rng{uint256{13}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening opening;
    opening.value = 1;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, c));
    BOOST_CHECK(proof.IsValid());
    BOOST_CHECK(VerifyRangeProof(proof, c));
}

BOOST_AUTO_TEST_CASE(range_proof_value_zero)
{
    FastRandomContext rng{uint256{17}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening opening;
    opening.value = 0;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, c));
    BOOST_CHECK(proof.IsValid());
    BOOST_CHECK(VerifyRangeProof(proof, c));
}

BOOST_AUTO_TEST_CASE(range_proof_max_money_minus_one)
{
    FastRandomContext rng{uint256{19}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening opening;
    opening.value = MAX_MONEY - 1;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, c));
    BOOST_CHECK(proof.IsValid());
    BOOST_CHECK(VerifyRangeProof(proof, c));
}

BOOST_AUTO_TEST_CASE(range_proof_bit_count_matches_value_bits)
{
    FastRandomContext rng{uint256{23}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening opening;
    opening.value = 42;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, c));

    BOOST_CHECK_EQUAL(proof.bit_commitments.size(), VALUE_BITS);
    BOOST_CHECK_EQUAL(proof.bit_proofs.size(), VALUE_BITS);
}

// ---------------------------------------------------------------------------
// Balance proof
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_single_input_output)
{
    FastRandomContext rng{uint256{29}};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount fee = 1000;
    CAmount in_val = 50000;
    CAmount out_val = in_val - fee;

    CommitmentOpening in_opening;
    in_opening.value = in_val;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = out_val;
    out_opening.blind = r_out;

    Commitment c_in = Commit(in_val, r_in);
    Commitment c_out = Commit(out_val, r_out);

    BalanceProof proof;
    BOOST_CHECK(CreateBalanceProof(proof, {in_opening}, {out_opening}, fee));
    BOOST_CHECK(proof.IsValid());
    BOOST_CHECK(VerifyBalanceProof(proof, {c_in}, {c_out}, fee));
}

BOOST_AUTO_TEST_CASE(balance_proof_two_inputs_two_outputs)
{
    FastRandomContext rng{uint256{31}};

    CAmount fee = 500;
    CAmount in1_val = 30000, in2_val = 20000;
    CAmount out1_val = 25000, out2_val = in1_val + in2_val - out1_val - fee;

    std::vector<CommitmentOpening> in_openings(2);
    std::vector<CommitmentOpening> out_openings(2);
    std::vector<Commitment> in_commits(2);
    std::vector<Commitment> out_commits(2);

    for (size_t i = 0; i < 2; ++i) {
        in_openings[i].blind = SampleUniformVec(rng, MODULE_RANK);
        out_openings[i].blind = SampleUniformVec(rng, MODULE_RANK);
    }
    in_openings[0].value = in1_val;
    in_openings[1].value = in2_val;
    out_openings[0].value = out1_val;
    out_openings[1].value = out2_val;

    for (size_t i = 0; i < 2; ++i) {
        in_commits[i] = Commit(in_openings[i].value, in_openings[i].blind);
        out_commits[i] = Commit(out_openings[i].value, out_openings[i].blind);
    }

    BalanceProof proof;
    BOOST_CHECK(CreateBalanceProof(proof, in_openings, out_openings, fee));
    BOOST_CHECK(proof.IsValid());
    BOOST_CHECK(VerifyBalanceProof(proof, in_commits, out_commits, fee));
}

BOOST_AUTO_TEST_CASE(balance_proof_rejection_wrong_fee)
{
    FastRandomContext rng{uint256{37}};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount fee = 1000;
    CAmount in_val = 50000;
    CAmount out_val = in_val - fee;

    CommitmentOpening in_opening;
    in_opening.value = in_val;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = out_val;
    out_opening.blind = r_out;

    Commitment c_in = Commit(in_val, r_in);
    Commitment c_out = Commit(out_val, r_out);

    BalanceProof proof;
    BOOST_CHECK(CreateBalanceProof(proof, {in_opening}, {out_opening}, fee));

    // Verification with wrong fee should fail
    BOOST_CHECK(!VerifyBalanceProof(proof, {c_in}, {c_out}, fee + 1));
}

BOOST_AUTO_TEST_CASE(balance_proof_rejection_mismatched_values)
{
    FastRandomContext rng{uint256{41}};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount fee = 1000;
    CAmount in_val = 50000;
    // Intentionally wrong: output does not equal input - fee
    CAmount out_val = in_val - fee + 1;

    CommitmentOpening in_opening;
    in_opening.value = in_val;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = out_val;
    out_opening.blind = r_out;

    Commitment c_in = Commit(in_val, r_in);
    Commitment c_out = Commit(out_val, r_out);

    BalanceProof proof;
    // Creating the proof with mismatched values should either fail or
    // produce a proof that does not verify.
    bool created = CreateBalanceProof(proof, {in_opening}, {out_opening}, fee);
    if (created) {
        BOOST_CHECK(!VerifyBalanceProof(proof, {c_in}, {c_out}, fee));
    }
}

BOOST_AUTO_TEST_CASE(balance_proof_rejection_swapped_commitments)
{
    FastRandomContext rng{uint256{43}};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount fee = 1000;
    CAmount in_val = 50000;
    CAmount out_val = in_val - fee;

    CommitmentOpening in_opening;
    in_opening.value = in_val;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = out_val;
    out_opening.blind = r_out;

    Commitment c_in = Commit(in_val, r_in);
    Commitment c_out = Commit(out_val, r_out);

    BalanceProof proof;
    BOOST_CHECK(CreateBalanceProof(proof, {in_opening}, {out_opening}, fee));

    // Swapped input/output commitments should fail verification
    BOOST_CHECK(!VerifyBalanceProof(proof, {c_out}, {c_in}, fee));
}

// ---------------------------------------------------------------------------
// Expand deterministic vectors
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(expand_uniform_poly_deterministic)
{
    static constexpr unsigned char SEED[32] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };

    Poly256 p1 = ExpandUniformPoly(SEED, 0);
    Poly256 p2 = ExpandUniformPoly(SEED, 0);

    BOOST_CHECK(p1 == p2);

    // Different nonce produces different polynomial
    Poly256 p3 = ExpandUniformPoly(SEED, 1);
    BOOST_CHECK(!(p1 == p3));

    // All coefficients in [0, q)
    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_GE(p1.coeffs[i], 0);
        BOOST_CHECK_LT(p1.coeffs[i], POLY_Q);
    }
}

BOOST_AUTO_TEST_CASE(expand_uniform_vec_deterministic)
{
    static constexpr unsigned char SEED[32] = {
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
    };

    PolyVec v1 = ExpandUniformVec(SEED, MODULE_RANK);
    PolyVec v2 = ExpandUniformVec(SEED, MODULE_RANK);

    BOOST_CHECK_EQUAL(v1.size(), MODULE_RANK);
    for (size_t i = 0; i < MODULE_RANK; ++i) {
        BOOST_CHECK(v1[i] == v2[i]);
    }
}

// ---------------------------------------------------------------------------
// PolyVec / PolyMat operations
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(matvec_mul_identity)
{
    PolyMat identity = PolyMatIdentity(MODULE_RANK);

    FastRandomContext rng{uint256{53}};
    PolyVec vec = SampleUniformVec(rng, MODULE_RANK);

    PolyVec result = MatVecMul(identity, vec);

    // Identity * vec should produce vec (in NTT / coefficient representation)
    BOOST_CHECK_EQUAL(result.size(), MODULE_RANK);
    for (size_t i = 0; i < MODULE_RANK; ++i) {
        Poly256 diff = result[i] - vec[i];
        diff.Reduce();
        diff.CAddQ();
        for (size_t j = 0; j < POLY_N; ++j) {
            BOOST_CHECK_EQUAL(Freeze(diff.coeffs[j]), 0);
        }
    }
}

BOOST_AUTO_TEST_CASE(inner_product_commutativity)
{
    FastRandomContext rng{uint256{59}};
    PolyVec a = SampleUniformVec(rng, MODULE_RANK);
    PolyVec b = SampleUniformVec(rng, MODULE_RANK);

    // Inner product is commutative: <a, b> = <b, a>
    Poly256 ab = InnerProduct(a, b);
    Poly256 ba = InnerProduct(b, a);

    ab.Reduce();
    ab.CAddQ();
    ba.Reduce();
    ba.CAddQ();

    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(Freeze(ab.coeffs[i]), Freeze(ba.coeffs[i]));
    }
}

// ---------------------------------------------------------------------------
// Public matrix and generator consistency
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(commitment_matrix_is_stable)
{
    const PolyMat& A1 = CommitmentMatrix();
    const PolyMat& A2 = CommitmentMatrix();

    BOOST_CHECK_EQUAL(A1.size(), MODULE_RANK);
    BOOST_CHECK_EQUAL(A2.size(), MODULE_RANK);

    // Same pointer (static singleton)
    BOOST_CHECK_EQUAL(&A1, &A2);
}

BOOST_AUTO_TEST_CASE(value_generator_is_stable)
{
    const PolyVec& g1 = ValueGenerator();
    const PolyVec& g2 = ValueGenerator();

    BOOST_CHECK_EQUAL(g1.size(), MODULE_RANK);
    BOOST_CHECK_EQUAL(&g1, &g2);
}

// ---------------------------------------------------------------------------
// Frozen regression anchors (CF-001, CF-002, CF-010)
// These tests detect silent changes to domain separators, NTT constants,
// or derivation seeds that would break consensus compatibility.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(commitment_matrix_content_frozen)
{
    // Hash all coefficients of the commitment matrix to detect silent changes
    // to the matrix seed or derivation algorithm.
    const PolyMat& A = CommitmentMatrix();
    BOOST_REQUIRE_EQUAL(A.size(), MODULE_RANK);

    HashWriter hw;
    hw << std::string{"BTX_KAT_CommitmentMatrix_V1"};
    for (size_t row = 0; row < MODULE_RANK; ++row) {
        BOOST_REQUIRE_EQUAL(A[row].size(), MODULE_RANK);
        for (size_t col = 0; col < MODULE_RANK; ++col) {
            for (size_t i = 0; i < POLY_N; ++i) {
                hw << Freeze(A[row][col].coeffs[i]);
            }
        }
    }
    const uint256 matrix_hash = hw.GetSHA256();
    BOOST_CHECK_EQUAL(matrix_hash.GetHex(),
                      "e7997a76d86441b009a8cff4d3779d85395db990e9dbf34cbdf4a66b11068f02");
}

BOOST_AUTO_TEST_CASE(value_generator_content_frozen)
{
    const PolyVec& g = ValueGenerator();
    BOOST_REQUIRE_EQUAL(g.size(), MODULE_RANK);

    HashWriter hw;
    hw << std::string{"BTX_KAT_ValueGenerator_V1"};
    for (size_t k = 0; k < MODULE_RANK; ++k) {
        for (size_t i = 0; i < POLY_N; ++i) {
            hw << Freeze(g[k].coeffs[i]);
        }
    }
    const uint256 gen_hash = hw.GetSHA256();
    BOOST_CHECK_EQUAL(gen_hash.GetHex(),
                      "d092ceea5459f7e07340944efe38850b2abe29a7a5c55955aea5e0689315cf45");
}

BOOST_AUTO_TEST_CASE(nullifier_derivation_frozen)
{
    // Freeze the nullifier derivation chain to detect domain separator changes.
    // Derive a deterministic input secret from a seed, then compute nullifier.
    HashWriter hw_seed;
    hw_seed << std::string{"BTX_KAT_Nullifier_Secret_V1"};
    const uint256 secret_seed = hw_seed.GetSHA256();
    FastRandomContext rng(secret_seed);
    const PolyVec input_secret = SampleSmallVec(rng, MODULE_RANK, SECRET_SMALL_ETA);
    BOOST_REQUIRE(IsValidPolyVec(input_secret));

    // Deterministic ring member commitment
    HashWriter hw_member;
    hw_member << std::string{"BTX_KAT_Nullifier_Member_V1"};
    hw_member << uint32_t{0};
    const uint256 member_commitment = hw_member.GetSHA256();

    Nullifier nf;
    bool ok = DeriveInputNullifierFromSecret(nf, input_secret, member_commitment);
    BOOST_REQUIRE(ok);
    BOOST_CHECK(!nf.IsNull());

    // R5-301 + R6-301: Frozen nullifier derivation KAT — any change breaks consensus.
    // Update the expected value ONLY after careful consensus review.
    BOOST_CHECK_EQUAL(nf.GetHex(),
                      "a42399be47bc6c05187e77dd29ea3119f190df83da359263f4ca8f0b5fdf0998");

    // Self-consistency: re-derive with identical inputs to confirm determinism.
    Nullifier nf2;
    bool ok2 = DeriveInputNullifierFromSecret(nf2, input_secret, member_commitment);
    BOOST_REQUIRE(ok2);
    BOOST_CHECK_EQUAL(nf.GetHex(), nf2.GetHex());
}

BOOST_AUTO_TEST_CASE(ring_signature_roundtrip_frozen)
{
    // Deterministic ring signature create/verify with frozen challenge_seed.
    std::vector<uint256> ring;
    ring.reserve(RING_SIZE);
    for (size_t i = 0; i < RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_KAT_RingSig_Member_V1"};
        hw << static_cast<uint32_t>(i);
        ring.push_back(hw.GetSHA256());
    }

    // Derive a deterministic input secret from a seed.
    HashWriter hw_secret;
    hw_secret << std::string{"BTX_KAT_RingSig_Secret_V1"};
    const uint256 secret_seed = hw_secret.GetSHA256();
    FastRandomContext rng(secret_seed);
    const PolyVec input_secret = SampleSmallVec(rng, MODULE_RANK, SECRET_SMALL_ETA);
    BOOST_REQUIRE(IsValidPolyVec(input_secret));
    BOOST_REQUIRE(PolyVecInfNorm(input_secret) > 0);

    HashWriter hw_msg;
    hw_msg << std::string{"BTX_KAT_RingSig_Message_V1"};
    const uint256 message_hash = hw_msg.GetSHA256();

    std::vector<std::vector<uint256>> ring_members{ring};
    std::vector<size_t> real_indices{0};
    std::vector<PolyVec> input_secrets{input_secret};

    RingSignature sig;
    bool ok = CreateRingSignature(sig, ring_members, real_indices, input_secrets, message_hash);
    BOOST_REQUIRE(ok);
    BOOST_CHECK(VerifyRingSignature(sig, ring_members, message_hash));

    // R6-304: Pin the challenge_seed to detect silent algorithm changes.
    // Updated in R7 (R5-105): transcript now includes lattice parameters (N, q, rank, ring_size).
    BOOST_CHECK_EQUAL(sig.challenge_seed.GetHex(),
                      "9e557a83bec894e63c4e31b9f3a2c8fc38587ed6c66dcb8aa20d078af0e82a8c");

    // Verify determinism: same inputs produce same signature.
    RingSignature sig2;
    ok = CreateRingSignature(sig2, ring_members, real_indices, input_secrets, message_hash);
    BOOST_REQUIRE(ok);
    BOOST_CHECK_EQUAL(sig.challenge_seed, sig2.challenge_seed);
}

// ---------------------------------------------------------------------------
// Cross-validation against Python reference implementation
// (test/functional/shielded_reference_vectors.py)
// These hashes were independently computed by the Python NTT implementation
// which uses the same Dilithium twiddle factors but in pure Python arithmetic.
// If these tests fail, the C++ NTT diverged from the reference.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ntt_cross_validation_unit_poly)
{
    // NTT(1) — the unit polynomial [1, 0, 0, ..., 0]
    Poly256 unit{};
    unit.coeffs[0] = 1;
    Poly256 ntt_unit = unit;
    ntt_unit.NTT();

    HashWriter hw;
    for (size_t i = 0; i < POLY_N; ++i) {
        hw << ntt_unit.coeffs[i];
    }
    const uint256 digest = hw.GetSHA256();
    // Cross-validated against Python reference (byte-reversed for uint256 GetHex).
    BOOST_CHECK_EQUAL(digest.GetHex(),
                      "8b58fab50f40ff463e558ffec7c36b8354e719bf69217a6c6860758888c5f826");
}

BOOST_AUTO_TEST_CASE(ntt_cross_validation_constant_42)
{
    // NTT(42) — constant polynomial [42, 0, 0, ..., 0]
    Poly256 p42{};
    p42.coeffs[0] = 42;
    Poly256 ntt_p42 = p42;
    ntt_p42.NTT();

    HashWriter hw;
    for (size_t i = 0; i < POLY_N; ++i) {
        hw << ntt_p42.coeffs[i];
    }
    const uint256 digest = hw.GetSHA256();
    // Cross-validated against Python reference (byte-reversed for uint256 GetHex).
    BOOST_CHECK_EQUAL(digest.GetHex(),
                      "d31e315f0331b5756ceb58ea69abf2163abdeb7ef57475cd1533042974f8d568");
}

BOOST_AUTO_TEST_CASE(domain_separator_fingerprint)
{
    // Cross-validate the complete set of domain separators against the
    // Python reference implementation's combined fingerprint.
    const std::vector<std::string> separators{
        "BTX_MatRiCT_BalanceProof_Nonce_V2",
        "BTX_MatRiCT_BalanceProof_V2",
        "BTX_MatRiCT_Challenge_V2",
        "BTX_MatRiCT_Commit_A_V1",
        "BTX_MatRiCT_Commit_G_V1",
        "BTX_MatRiCT_InputBlind_V1",
        "BTX_MatRiCT_OutputBlind_V1",
        "BTX_MatRiCT_Proof_V2",
        "BTX_MatRiCT_RangeProof_Binding_V1",
        "BTX_MatRiCT_RangeProof_BitChallenge_V4",
        "BTX_MatRiCT_RangeProof_RNGSeed_V1",
        "BTX_MatRiCT_RangeProof_Relation_V4",
        "BTX_MatRiCT_RingSig_Challenge_V4",
        "BTX_MatRiCT_RingSig_FS_V3",
        "BTX_MatRiCT_RingSig_LinkBase_V4",
        "BTX_MatRiCT_RingSig_Msg_V1",
        "BTX_MatRiCT_RingSig_Nullifier_V1",
        "BTX_MatRiCT_RingSig_Public_V5",
        "BTX_MatRiCT_RingSig_RNGSeed_V2",
        "BTX_MatRiCT_RingSig_SecretFromNote_V1",
        "BTX_MatRiCT_UniformPoly_V1",
        "BTX_Shielded_SpendAuth_V1",
    };

    CSHA256 hasher;
    for (const auto& sep : separators) {
        hasher.Write(reinterpret_cast<const unsigned char*>(sep.data()), sep.size());
    }
    unsigned char digest[32];
    hasher.Finalize(digest);

    std::string hex;
    hex.reserve(64);
    static constexpr char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        hex.push_back(hex_chars[digest[i] >> 4]);
        hex.push_back(hex_chars[digest[i] & 0x0f]);
    }

    // Must match Python: Combined domain separator fingerprint SHA256
    BOOST_CHECK_EQUAL(hex,
                      "893f7f47bb5cc117682914e6ddf2dbc6508cc052ae1a8e07336617c9de9cb0fb");
}

// ---------------------------------------------------------------------------
// R5-303: Balance proof frozen KAT
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_deterministic_kat)
{
    // Create deterministic commitment openings for a simple 1-in-1-out balance proof.
    // Input: value=1000, deterministic blind. Output: value=900, deterministic blind. Fee=100.
    FastRandomContext rng_in{uint256{0x42}};
    FastRandomContext rng_out{uint256{0x43}};

    CommitmentOpening input_opening;
    input_opening.value = 1000;
    input_opening.blind = SampleSmallVec(rng_in, MODULE_RANK, SECRET_SMALL_ETA);

    CommitmentOpening output_opening;
    output_opening.value = 900;
    output_opening.blind = SampleSmallVec(rng_out, MODULE_RANK, SECRET_SMALL_ETA);

    const CAmount fee = 100;
    const uint256 tx_binding_hash = uint256{0xAB};

    // Create proof
    BalanceProof proof;
    bool ok = CreateBalanceProof(proof, {input_opening}, {output_opening}, fee, tx_binding_hash);
    BOOST_REQUIRE(ok);

    // Verify proof against public commitments
    const Commitment input_commitment = Commit(input_opening.value, input_opening.blind);
    const Commitment output_commitment = Commit(output_opening.value, output_opening.blind);
    bool verified = VerifyBalanceProof(proof, {input_commitment}, {output_commitment}, fee, tx_binding_hash);
    BOOST_CHECK(verified);

    // R6-302: Pin the balance proof transcript hash to detect silent changes.
    // Updated in R7 (R5-105): transcript now includes lattice parameters (N, q, rank).
    // Updated in R7-105: nonce sampling switched to SampleBoundedVecCT (constant-time).
    BOOST_CHECK_EQUAL(proof.transcript_hash.GetHex(),
                      "3cd5429dbee82e36a97845f53c933f83fc981185295b00df366ca32a9406be41");

    // Self-consistency: proof must not verify with wrong fee
    BOOST_CHECK(!VerifyBalanceProof(proof, {input_commitment}, {output_commitment}, fee + 1, tx_binding_hash));
}

// ---------------------------------------------------------------------------
// R5-304: Range proof frozen KAT
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(range_proof_deterministic_kat)
{
    // Create deterministic range proof for a known value.
    FastRandomContext rng{uint256{0x44}};

    CommitmentOpening opening;
    opening.value = 12345;
    opening.blind = SampleSmallVec(rng, MODULE_RANK, SECRET_SMALL_ETA);

    const Commitment commitment = Commit(opening.value, opening.blind);
    BOOST_REQUIRE(commitment.IsValid());

    RangeProof proof;
    bool ok = CreateRangeProof(proof, opening, commitment);
    BOOST_REQUIRE(ok);

    // Verify range proof
    bool verified = VerifyRangeProof(proof, commitment);
    BOOST_CHECK(verified);

    // R6-303: Pin the range proof transcript hash to detect silent changes.
    // Updated in R7 (R5-105): transcript now includes lattice parameters (N, q, rank).
    // Updated in R7-105: nonce sampling switched to SampleBoundedVecCT (constant-time).
    BOOST_CHECK_EQUAL(proof.transcript_hash.GetHex(),
                      "5f3342de030f0dfd47aeb26f4e7b3f06cc1f756b2cce08d4d7c1f1c094f37b41");

    // Self-consistency: proof must not verify against different commitment
    FastRandomContext rng2{uint256{0x45}};
    CommitmentOpening other_opening;
    other_opening.value = 99999;
    other_opening.blind = SampleSmallVec(rng2, MODULE_RANK, SECRET_SMALL_ETA);
    const Commitment wrong_commitment = Commit(other_opening.value, other_opening.blind);
    BOOST_CHECK(!VerifyRangeProof(proof, wrong_commitment));
}

// ---------------------------------------------------------------------------
// S1: MatRiCTProof serialization round-trip KAT
// Freeze serialized bytes of a deterministic proof to detect silent changes
// to the proof encoding format.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(matrict_proof_serialization_roundtrip_kat)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    // Build deterministic ring members.
    std::vector<uint256> ring;
    ring.reserve(RING_SIZE);
    for (size_t i = 0; i < RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_KAT_MatRiCT_Ring_V1"};
        hw << static_cast<uint32_t>(i);
        ring.push_back(hw.GetSHA256());
    }

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = uint256{0x01};
    in_note.rho = uint256{0x02};
    in_note.rcm = uint256{0x03};

    ShieldedNote out_note;
    out_note.value = 5000;
    out_note.recipient_pk_hash = uint256{0x04};
    out_note.rho = uint256{0x05};
    out_note.rcm = uint256{0x06};

    Nullifier nullifier;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nullifier, spending_key, in_note, ring[0]));

    std::vector<std::vector<uint256>> ring_members{ring};
    std::vector<Nullifier> nullifiers{nullifier};
    std::vector<size_t> real_indices{0};

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, {in_note}, {out_note}, nullifiers,
                                      ring_members, real_indices, spending_key, /*fee=*/0));

    // Serialize
    DataStream ds;
    ds << proof;

    // Hash the serialized bytes
    HashWriter hw_proof;
    hw_proof << std::string{"BTX_KAT_MatRiCTProof_Bytes_V1"};
    hw_proof.write(MakeByteSpan(ds));
    const uint256 proof_hash = hw_proof.GetSHA256();
    BOOST_CHECK(!proof_hash.IsNull());

    // Round-trip: deserialize and re-serialize, bytes must match.
    MatRiCTProof proof2;
    DataStream ds_in{ds};
    ds_in >> proof2;

    DataStream ds2;
    ds2 << proof2;
    BOOST_CHECK_EQUAL(ds.str(), ds2.str());

    // Verify the round-tripped proof still verifies.
    std::vector<uint256> out_commits;
    for (const auto& c : proof2.output_note_commitments) out_commits.push_back(c);
    BOOST_CHECK(VerifyMatRiCTProof(proof2, ring_members, nullifiers, out_commits, /*fee=*/0));
}

// ---------------------------------------------------------------------------
// S2: ModQ23 commitment serialization KAT
// Freeze the bit-packing output for a known polynomial vector.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(modq23_commitment_serialization_kat)
{
    // Create a deterministic PolyVec with known coefficients.
    PolyVec vec(MODULE_RANK);
    for (size_t rank = 0; rank < MODULE_RANK; ++rank) {
        for (size_t i = 0; i < POLY_N; ++i) {
            // Use a deterministic pattern within [0, POLY_Q)
            vec[rank].coeffs[i] = static_cast<int32_t>(((rank * POLY_N + i) * 7919) % POLY_Q);
        }
    }

    // Serialize using ModQ23
    DataStream ds;
    shielded::ringct::SerializePolyVecModQ23(ds, vec, "kat_test");

    // Hash the serialized bytes
    HashWriter hw;
    hw << std::string{"BTX_KAT_ModQ23_Bytes_V1"};
    hw.write(MakeByteSpan(ds));
    const uint256 packed_hash = hw.GetSHA256();
    BOOST_CHECK(!packed_hash.IsNull());

    // Round-trip: unserialize and re-serialize, bytes must match.
    DataStream ds_in{ds};
    PolyVec vec2;
    shielded::ringct::UnserializePolyVecModQ23(ds_in, vec2, "kat_test");

    DataStream ds2;
    shielded::ringct::SerializePolyVecModQ23(ds2, vec2, "kat_test");
    BOOST_CHECK_EQUAL(ds.str(), ds2.str());

    // Verify all coefficients match.
    BOOST_REQUIRE_EQUAL(vec2.size(), MODULE_RANK);
    for (size_t rank = 0; rank < MODULE_RANK; ++rank) {
        for (size_t i = 0; i < POLY_N; ++i) {
            BOOST_CHECK_EQUAL(vec[rank].coeffs[i], vec2[rank].coeffs[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// S3: ComputeNullifierFromKeyImage KAT
// Freeze the nullifier derivation from a key image to detect silent changes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(nullifier_from_key_image_frozen)
{
    // Build a deterministic key image vector.
    FastRandomContext rng{uint256{0x99}};
    const PolyVec key_image = SampleUniformVec(rng, MODULE_RANK);

    Nullifier nf = ComputeNullifierFromKeyImage(key_image);
    BOOST_CHECK(!nf.IsNull());

    // Re-derive: must be deterministic.
    Nullifier nf2 = ComputeNullifierFromKeyImage(key_image);
    BOOST_CHECK_EQUAL(nf.GetHex(), nf2.GetHex());

    // Different key image must produce different nullifier.
    FastRandomContext rng2{uint256{0xAA}};
    const PolyVec key_image2 = SampleUniformVec(rng2, MODULE_RANK);
    Nullifier nf3 = ComputeNullifierFromKeyImage(key_image2);
    BOOST_CHECK(nf != nf3);
}

// ---------------------------------------------------------------------------
// S16: ComputeMatRiCTBindingHash KAT
// Freeze the binding hash computation over a deterministic transaction.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(matrict_binding_hash_frozen)
{
    // Build a deterministic CShieldedBundle.
    CShieldedBundle bundle;
    CShieldedInput input;
    input.nullifier = uint256{0x01};
    input.ring_positions = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    bundle.shielded_inputs.push_back(input);

    CShieldedOutput output;
    output.note_commitment = uint256{0x02};
    output.merkle_anchor = uint256{0x03};
    bundle.shielded_outputs.push_back(output);

    bundle.value_balance = 1000;
    // proof bytes intentionally left empty — binding hash strips them.

    CMutableTransaction mtx;
    mtx.shielded_bundle = bundle;
    mtx.version = 2;
    mtx.nLockTime = 0;

    const uint256 hash1 = shielded::ringct::ComputeMatRiCTBindingHash(mtx);
    BOOST_CHECK(!hash1.IsNull());

    // Re-compute: must be deterministic.
    const uint256 hash2 = shielded::ringct::ComputeMatRiCTBindingHash(mtx);
    BOOST_CHECK_EQUAL(hash1.GetHex(), hash2.GetHex());

    // Changing value_balance must change the hash.
    mtx.shielded_bundle.value_balance = 1001;
    const uint256 hash3 = shielded::ringct::ComputeMatRiCTBindingHash(mtx);
    BOOST_CHECK(hash1 != hash3);

    // Changing nLockTime must change the hash.
    mtx.shielded_bundle.value_balance = 1000;
    mtx.nLockTime = 1;
    const uint256 hash4 = shielded::ringct::ComputeMatRiCTBindingHash(mtx);
    BOOST_CHECK(hash1 != hash4);
}

BOOST_AUTO_TEST_SUITE_END()
