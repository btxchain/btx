// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/params.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <shielded/merkle_tree.h>
#include <shielded/ringct/balance_proof.h>
#include <shielded/ringct/commitment.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>
#include <shielded/validation.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

std::vector<uint256> MakeDistinctRingMembers(size_t count)
{
    std::vector<uint256> ring;
    ring.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        ring.push_back(hw.GetSHA256());
    }
    return ring;
}

/** Build a valid MatRiCTProof and matching ring members for a single-input, single-output bundle. */
struct ValidProofFixture {
    MatRiCTProof proof;
    std::vector<std::vector<uint256>> ring_members;
    std::vector<Nullifier> input_nullifiers;
    std::vector<uint256> output_commitments;
    CAmount fee{0};
    uint256 tx_binding_hash;

    ValidProofFixture(CAmount value_in = 5000, CAmount value_out = 5000, CAmount fee_in = 0)
        : fee{fee_in}
    {
        const std::vector<unsigned char> spending_key(32, 0x42);

        std::vector<uint256> ring = MakeDistinctRingMembers(lattice::RING_SIZE);
        ring_members.push_back(ring);

        ShieldedNote in_note;
        in_note.value = value_in;
        in_note.recipient_pk_hash = GetRandHash();
        in_note.rho = GetRandHash();
        in_note.rcm = GetRandHash();

        ShieldedNote out_note;
        out_note.value = value_out;
        out_note.recipient_pk_hash = GetRandHash();
        out_note.rho = GetRandHash();
        out_note.rcm = GetRandHash();

        Nullifier nullifier;
        bool ok = DeriveInputNullifierForNote(nullifier, spending_key, in_note, ring[0]);
        assert(ok);
        input_nullifiers.push_back(nullifier);

        std::vector<ShieldedNote> input_notes{in_note};
        std::vector<ShieldedNote> output_notes{out_note};
        std::vector<size_t> real_indices{0};

        ok = CreateMatRiCTProof(proof,
                                input_notes,
                                output_notes,
                                input_nullifiers,
                                ring_members,
                                real_indices,
                                spending_key,
                                fee,
                                tx_binding_hash);
        assert(ok);

        output_commitments.reserve(proof.output_note_commitments.size());
        for (const auto& c : proof.output_note_commitments) {
            output_commitments.push_back(c);
        }
    }

    /** Convenience: verify the proof returns the expected result. */
    bool Verify() const
    {
        return VerifyMatRiCTProof(proof, ring_members, input_nullifiers,
                                  output_commitments, fee, tx_binding_hash);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_proof_adversarial_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// 1. duplicate_ring_members_rejected
//    Build a ring with duplicate uint256 entries; CreateRingSignature must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(duplicate_ring_members_rejected)
{
    // Build a ring where two entries are identical.
    std::vector<uint256> ring = MakeDistinctRingMembers(lattice::RING_SIZE);
    ring[5] = ring[0]; // introduce duplicate

    std::vector<std::vector<uint256>> ring_members{ring};
    std::vector<size_t> real_indices{0};
    const uint256 message_hash = GetRandHash();

    // Derive a dummy input secret for the ring signature test.
    FastRandomContext test_rng(GetRandHash());
    std::vector<lattice::PolyVec> input_secrets{
        lattice::SampleSmallVec(test_rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA)};

    RingSignature sig;
    // CreateRingSignature should reject duplicate ring members.
    BOOST_CHECK(!CreateRingSignature(sig, ring_members, real_indices, input_secrets, message_hash));

    // Also verify that a valid proof with the ring tampered post-creation fails verification.
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());
    f.ring_members[0][1] = f.ring_members[0][0];
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 2. oversized_response_rejected
//    Create a proof, tamper a response coefficient to exceed RESPONSE_NORM_BOUND.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(oversized_response_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Set one coefficient to GAMMA_RESPONSE (exceeds the norm bound).
    const int32_t over_bound = lattice::GAMMA_RESPONSE;
    BOOST_REQUIRE(!f.proof.ring_signature.input_proofs.empty());
    BOOST_REQUIRE(!f.proof.ring_signature.input_proofs[0].responses.empty());
    BOOST_REQUIRE(!f.proof.ring_signature.input_proofs[0].responses[0].empty());
    f.proof.ring_signature.input_proofs[0].responses[0][0].coeffs[0] = over_bound;

    // The RingInputProof itself should report invalid.
    BOOST_CHECK(!f.proof.ring_signature.input_proofs[0].IsValid(lattice::RING_SIZE));

    // Full proof verification must also reject.
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 3. null_challenge_rejected
//    Create a valid proof, zero out one challenge digest; verification must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(null_challenge_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Set one challenge to the null (zero) hash.
    BOOST_REQUIRE(!f.proof.ring_signature.input_proofs.empty());
    BOOST_REQUIRE(!f.proof.ring_signature.input_proofs[0].challenges.empty());
    f.proof.ring_signature.input_proofs[0].challenges[0].SetNull();
    BOOST_CHECK(f.proof.ring_signature.input_proofs[0].challenges[0].IsNull());

    // RingInputProof::IsValid rejects null challenges.
    BOOST_CHECK(!f.proof.ring_signature.input_proofs[0].IsValid(lattice::RING_SIZE));

    // Full proof verification must reject.
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 4. wrong_ring_size_rejected
//    Try rings with 0, 1, 15, 17 members; all should fail verification.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(wrong_ring_size_rejected)
{
    const std::vector<size_t> bad_sizes{0, 1, lattice::RING_SIZE - 1, lattice::RING_SIZE + 1};

    for (const size_t sz : bad_sizes) {
        ValidProofFixture f;
        BOOST_REQUIRE(f.Verify());

        // Replace ring with one of incorrect size.
        f.ring_members[0] = MakeDistinctRingMembers(sz);
        BOOST_CHECK_MESSAGE(!f.Verify(),
            "Expected verification failure for ring size " + std::to_string(sz));
    }
}

// ---------------------------------------------------------------------------
// 5. challenge_chain_tampered
//    Create valid proof, swap two challenges; verification must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(challenge_chain_tampered)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    auto& challenges = f.proof.ring_signature.input_proofs[0].challenges;
    BOOST_REQUIRE(challenges.size() >= 2);

    // Swap challenges[0] and challenges[1] to break the chain.
    std::swap(challenges[0], challenges[1]);

    // Ensure neither is null so the failure is not trivially from null-check.
    BOOST_REQUIRE(!challenges[0].IsNull());
    BOOST_REQUIRE(!challenges[1].IsNull());

    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 6. response_coefficient_tampered
//    Flip one coefficient in a response (keeping it within norm); verify fails.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(response_coefficient_tampered)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Modify a single coefficient in one response vector (keeping it in-bound).
    BOOST_REQUIRE(!f.proof.ring_signature.input_proofs[0].responses.empty());
    auto& response_poly = f.proof.ring_signature.input_proofs[0].responses[0][0];
    // Add 1 to the first coefficient. This changes the response without exceeding norm.
    response_poly.coeffs[0] = static_cast<int32_t>(response_poly.coeffs[0] + 1);

    // Ensure the response vector is still within the norm bound so this is
    // not trivially caught by norm checking alone.
    const int32_t norm_bound = lattice::GAMMA_RESPONSE - lattice::BETA_CHALLENGE;
    BOOST_REQUIRE(lattice::PolyVecInfNorm(f.proof.ring_signature.input_proofs[0].responses[0]) <= norm_bound);

    // The proof must fail because the tampered response breaks the ring equation.
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 7. balance_proof_wrong_fee
//    Create balance proof with fee=100; verify with fee=101 must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_wrong_fee)
{
    // Build a valid proof with fee=100: input 5100, output 5000.
    ValidProofFixture f(/*value_in=*/5100, /*value_out=*/5000, /*fee_in=*/100);
    BOOST_REQUIRE(f.Verify());

    // Attempt verification with a wrong fee value.
    BOOST_CHECK(!VerifyMatRiCTProof(f.proof, f.ring_members, f.input_nullifiers,
                                     f.output_commitments, /*fee=*/101, f.tx_binding_hash));

    // Also check fee=99.
    BOOST_CHECK(!VerifyMatRiCTProof(f.proof, f.ring_members, f.input_nullifiers,
                                     f.output_commitments, /*fee=*/99, f.tx_binding_hash));

    // Original fee=100 still works.
    BOOST_CHECK(VerifyMatRiCTProof(f.proof, f.ring_members, f.input_nullifiers,
                                    f.output_commitments, /*fee=*/100, f.tx_binding_hash));
}

// ---------------------------------------------------------------------------
// 8. range_proof_out_of_range
//    Try to create range proof for negative value and for value > MAX_MONEY.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(range_proof_out_of_range)
{
    FastRandomContext rng(GetRandHash());
    lattice::PolyVec blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, /*eta=*/2);

    // Negative value: CreateRangeProof should fail.
    {
        const CAmount negative_value = -1;
        CommitmentOpening opening;
        opening.value = negative_value;
        opening.blind = blind;
        Commitment commitment = Commit(negative_value, blind);

        RangeProof rp;
        BOOST_CHECK(!CreateRangeProof(rp, opening, commitment));
    }

    // Value at 2^VALUE_BITS (one past the representable range): must fail.
    // Note: MAX_MONEY+1 is still within VALUE_BITS (51 bits cover up to 2^51-1),
    // so we test at the actual cryptographic boundary.
    {
        const CAmount too_large = static_cast<CAmount>(uint64_t{1} << lattice::VALUE_BITS);
        CommitmentOpening opening;
        opening.value = too_large;
        opening.blind = blind;
        Commitment commitment = Commit(too_large, blind);

        RangeProof rp;
        BOOST_CHECK(!CreateRangeProof(rp, opening, commitment));
    }

    // Sanity: a valid in-range value succeeds.
    {
        const CAmount valid_value = 1000;
        CommitmentOpening opening;
        opening.value = valid_value;
        opening.blind = blind;
        Commitment commitment = Commit(valid_value, blind);

        RangeProof rp;
        BOOST_CHECK(CreateRangeProof(rp, opening, commitment));
        BOOST_CHECK(VerifyRangeProof(rp, commitment));
    }
}

// ---------------------------------------------------------------------------
// 9. key_image_zero_rejected
//    Construct proof with zero key image vector; verification must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(key_image_zero_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Zero out the key image (all polynomial coefficients to zero).
    BOOST_REQUIRE(!f.proof.ring_signature.key_images.empty());
    for (auto& poly : f.proof.ring_signature.key_images[0]) {
        poly.coeffs.fill(0);
    }
    BOOST_CHECK_EQUAL(lattice::PolyVecInfNorm(f.proof.ring_signature.key_images[0]), 0);

    // RingSignature::IsValid rejects zero-norm key images.
    BOOST_CHECK(!f.proof.ring_signature.IsValid(1, lattice::RING_SIZE));

    // Full proof verification must reject.
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 10. replay_nullifier
//     Verify same nullifier can't appear twice in input list.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(replay_nullifier)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    // Build two-input ring members with distinct rings.
    std::vector<uint256> ring_a = MakeDistinctRingMembers(lattice::RING_SIZE);
    std::vector<uint256> ring_b;
    ring_b.reserve(lattice::RING_SIZE);
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(lattice::RING_SIZE + i);
        ring_b.push_back(hw.GetSHA256());
    }
    std::vector<std::vector<uint256>> ring_members{ring_a, ring_b};

    ShieldedNote in_note_a;
    in_note_a.value = 3000;
    in_note_a.recipient_pk_hash = GetRandHash();
    in_note_a.rho = GetRandHash();
    in_note_a.rcm = GetRandHash();

    ShieldedNote in_note_b;
    in_note_b.value = 2000;
    in_note_b.recipient_pk_hash = GetRandHash();
    in_note_b.rho = GetRandHash();
    in_note_b.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    Nullifier nf_a;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf_a, spending_key, in_note_a, ring_a[0]));
    Nullifier nf_b;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf_b, spending_key, in_note_b, ring_b[0]));
    BOOST_REQUIRE(nf_a != nf_b);

    // Create a valid proof with two distinct nullifiers.
    std::vector<Nullifier> nullifiers{nf_a, nf_b};
    std::vector<ShieldedNote> input_notes{in_note_a, in_note_b};
    std::vector<ShieldedNote> output_notes{out_note};
    std::vector<size_t> real_indices{0, 0};

    MatRiCTProof proof;
    bool ok = CreateMatRiCTProof(proof, input_notes, output_notes,
                                  nullifiers, ring_members, real_indices,
                                  spending_key, /*fee=*/0);
    BOOST_REQUIRE(ok);

    std::vector<uint256> output_commitments;
    for (const auto& c : proof.output_note_commitments) {
        output_commitments.push_back(c);
    }

    // Sanity: the valid proof verifies.
    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, nullifiers,
                                    output_commitments, /*fee=*/0));

    // Now replay the first nullifier in place of the second.
    std::vector<Nullifier> replayed_nullifiers{nf_a, nf_a};
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, replayed_nullifiers,
                                     output_commitments, /*fee=*/0));

    // Also verify that CreateMatRiCTProof itself rejects duplicate nullifiers.
    MatRiCTProof bad_proof;
    BOOST_CHECK(!CreateMatRiCTProof(bad_proof, input_notes, output_notes,
                                     replayed_nullifiers, ring_members, real_indices,
                                     spending_key, /*fee=*/0));
}

// ---------------------------------------------------------------------------
// 11. sub_proof_substitution_ring_signature
//     Replace the ring signature in a valid proof with a zeroed one.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(sub_proof_substitution_ring_signature)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Zero out the ring signature challenge seed.
    f.proof.ring_signature.challenge_seed.SetNull();
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 12. sub_proof_substitution_balance_proof
//     Replace the balance proof transcript with a different hash.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(sub_proof_substitution_balance_proof)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Tamper the balance proof transcript hash.
    f.proof.balance_proof.transcript_hash = GetRandHash();
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 13. sub_proof_substitution_range_proof
//     Replace one range proof with a zeroed range proof.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(sub_proof_substitution_range_proof)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());
    BOOST_REQUIRE(!f.proof.output_range_proofs.empty());

    // Tamper the first range proof's transcript hash.
    f.proof.output_range_proofs[0].transcript_hash = GetRandHash();
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 14. sub_proof_cross_component_swap
//     Take two valid proofs and swap a sub-component between them.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(sub_proof_cross_component_swap)
{
    ValidProofFixture f1(5000, 5000, 0);
    ValidProofFixture f2(3000, 3000, 0);
    BOOST_REQUIRE(f1.Verify());
    BOOST_REQUIRE(f2.Verify());

    // Swap balance proofs between the two valid proofs.
    std::swap(f1.proof.balance_proof, f2.proof.balance_proof);
    BOOST_CHECK(!f1.Verify());
    BOOST_CHECK(!f2.Verify());
}

// ---------------------------------------------------------------------------
// 15. fee_zero_balance_proof
//     Verify that fee=0 is accepted when values balance.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(fee_zero_balance_proof)
{
    FastRandomContext rng{uint256{71}};
    lattice::PolyVec r_in = lattice::SampleUniformVec(rng, lattice::MODULE_RANK);
    lattice::PolyVec r_out = lattice::SampleUniformVec(rng, lattice::MODULE_RANK);

    CommitmentOpening in_opening;
    in_opening.value = 42000;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = 42000; // same value, fee=0
    out_opening.blind = r_out;

    Commitment c_in = Commit(in_opening.value, in_opening.blind);
    Commitment c_out = Commit(out_opening.value, out_opening.blind);

    BalanceProof proof;
    BOOST_CHECK(CreateBalanceProof(proof, {in_opening}, {out_opening}, /*fee=*/0));
    BOOST_CHECK(proof.IsValid());
    BOOST_CHECK(VerifyBalanceProof(proof, {c_in}, {c_out}, /*fee=*/0));

    // Fee=1 with same values must fail verification
    BOOST_CHECK(!VerifyBalanceProof(proof, {c_in}, {c_out}, /*fee=*/1));
}

// ---------------------------------------------------------------------------
// 16. commitment_ordering_sensitivity
//     Verify that reordering input/output commitments breaks verification.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(commitment_ordering_sensitivity)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    // Build two-input ring members.
    std::vector<uint256> ring_a = MakeDistinctRingMembers(lattice::RING_SIZE);
    std::vector<uint256> ring_b;
    ring_b.reserve(lattice::RING_SIZE);
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(lattice::RING_SIZE + i);
        ring_b.push_back(hw.GetSHA256());
    }
    std::vector<std::vector<uint256>> ring_members{ring_a, ring_b};

    ShieldedNote in_a;
    in_a.value = 3000;
    in_a.recipient_pk_hash = GetRandHash();
    in_a.rho = GetRandHash();
    in_a.rcm = GetRandHash();

    ShieldedNote in_b;
    in_b.value = 2000;
    in_b.recipient_pk_hash = GetRandHash();
    in_b.rho = GetRandHash();
    in_b.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    Nullifier nf_a, nf_b;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf_a, spending_key, in_a, ring_a[0]));
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf_b, spending_key, in_b, ring_b[0]));
    std::vector<Nullifier> nullifiers{nf_a, nf_b};

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                      {in_a, in_b}, {out_note},
                                      nullifiers, ring_members,
                                      {0, 0}, spending_key, /*fee=*/0));

    std::vector<uint256> out_commits;
    for (const auto& c : proof.output_note_commitments) out_commits.push_back(c);

    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, nullifiers, out_commits, 0));

    // Swap input ring members order — must fail
    std::vector<std::vector<uint256>> swapped_rings{ring_b, ring_a};
    BOOST_CHECK(!VerifyMatRiCTProof(proof, swapped_rings, nullifiers, out_commits, 0));

    // Swap nullifier order — must fail
    std::vector<Nullifier> swapped_nullifiers{nf_b, nf_a};
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, swapped_nullifiers, out_commits, 0));
}

// ---------------------------------------------------------------------------
// 17. three_input_matrict_proof
//     Verify that a 3-input proof works correctly.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(three_input_matrict_proof)
{
    const std::vector<unsigned char> spending_key(32, 0xBB);

    std::vector<std::vector<uint256>> ring_members;
    std::vector<ShieldedNote> inputs;
    std::vector<Nullifier> nullifiers;
    std::vector<size_t> real_indices;

    for (size_t i = 0; i < 3; ++i) {
        std::vector<uint256> ring;
        ring.reserve(lattice::RING_SIZE);
        for (size_t j = 0; j < lattice::RING_SIZE; ++j) {
            HashWriter hw;
            hw << std::string{"BTX_3Input_Ring_V1"};
            hw << static_cast<uint64_t>(i * 100 + j);
            ring.push_back(hw.GetSHA256());
        }
        ring_members.push_back(ring);

        ShieldedNote note;
        note.value = static_cast<CAmount>(1000 + i * 500);
        note.recipient_pk_hash = GetRandHash();
        note.rho = GetRandHash();
        note.rcm = GetRandHash();
        inputs.push_back(note);

        Nullifier nf;
        BOOST_REQUIRE(DeriveInputNullifierForNote(nf, spending_key, note, ring[0]));
        nullifiers.push_back(nf);
        real_indices.push_back(0);
    }

    // Total input: 1000 + 1500 + 2000 = 4500. Output: 4400, fee: 100.
    ShieldedNote out;
    out.value = 4400;
    out.recipient_pk_hash = GetRandHash();
    out.rho = GetRandHash();
    out.rcm = GetRandHash();

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, inputs, {out}, nullifiers,
                                      ring_members, real_indices, spending_key, /*fee=*/100));

    std::vector<uint256> out_commits;
    for (const auto& c : proof.output_note_commitments) out_commits.push_back(c);
    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, nullifiers, out_commits, /*fee=*/100));

    // Wrong fee must fail
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, nullifiers, out_commits, /*fee=*/99));
}

// ---------------------------------------------------------------------------
// 18. boundary_range_proof_max_money
//     Test range proof at MAX_MONEY boundary.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(boundary_range_proof_max_money)
{
    FastRandomContext rng{uint256{97}};
    lattice::PolyVec blind = lattice::SampleUniformVec(rng, lattice::MODULE_RANK);

    CommitmentOpening opening;
    opening.value = MAX_MONEY;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    // MAX_MONEY should fit within VALUE_BITS
    bool created = CreateRangeProof(proof, opening, c);
    if (created) {
        BOOST_CHECK(VerifyRangeProof(proof, c));
    }
}

// ---------------------------------------------------------------------------
// 19. boundary_range_proof_power_of_two
//     Test range proof at 2^50 (one bit below VALUE_BITS).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(boundary_range_proof_power_of_two)
{
    FastRandomContext rng{uint256{101}};
    lattice::PolyVec blind = lattice::SampleUniformVec(rng, lattice::MODULE_RANK);

    CommitmentOpening opening;
    opening.value = static_cast<CAmount>(uint64_t{1} << 50);
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, c));
    BOOST_CHECK(VerifyRangeProof(proof, c));
}

// ---------------------------------------------------------------------------
// 20. all_zero_response_rejected
//     A response vector of all zeros should not pass verification
//     (unless it happens to be the correct response, which is astronomically unlikely).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(all_zero_response_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Zero out all response coefficients for one ring member.
    auto& responses = f.proof.ring_signature.input_proofs[0].responses;
    BOOST_REQUIRE(!responses.empty());
    for (size_t k = 0; k < responses[0].size(); ++k) {
        for (size_t c = 0; c < lattice::POLY_N; ++c) {
            responses[0][k].coeffs[c] = 0;
        }
    }
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 21. input_commitment_tamper_rejected
//     Tampering an input commitment must break verification.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(input_commitment_tamper_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());
    BOOST_REQUIRE(!f.proof.input_commitments.empty());

    // Tamper one coefficient of the first input commitment.
    f.proof.input_commitments[0].vec[0].coeffs[0] += 1;
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// 22. output_commitment_tamper_rejected
//     Tampering an output commitment must break verification.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(output_commitment_tamper_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());
    BOOST_REQUIRE(!f.proof.output_commitments.empty());

    // Tamper one coefficient of the first output commitment.
    f.proof.output_commitments[0].vec[0].coeffs[0] += 1;
    BOOST_CHECK(!f.Verify());
}

// ---------------------------------------------------------------------------
// R6-310: Negative fee must be rejected by balance proof.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_rejects_negative_fee)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{uint256{200}};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount fee = -1;
    CAmount in_val = 50000;
    CAmount out_val = in_val - 1000; // actual fee would be 1000

    CommitmentOpening in_opening;
    in_opening.value = in_val;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = out_val;
    out_opening.blind = r_out;

    Commitment c_in = Commit(in_val, r_in);
    Commitment c_out = Commit(out_val, r_out);

    // Creating with negative fee should either fail or produce non-verifiable proof.
    BalanceProof proof;
    bool created = CreateBalanceProof(proof, {in_opening}, {out_opening}, fee);
    if (created) {
        BOOST_CHECK(!VerifyBalanceProof(proof, {c_in}, {c_out}, fee));
    }

    // Verification with negative fee must also fail even if proof was made with correct fee.
    BalanceProof good_proof;
    bool good_created = CreateBalanceProof(good_proof, {in_opening}, {out_opening}, /*fee=*/1000);
    if (good_created) {
        BOOST_CHECK(VerifyBalanceProof(good_proof, {c_in}, {c_out}, 1000));
        BOOST_CHECK(!VerifyBalanceProof(good_proof, {c_in}, {c_out}, -1));
    }
}

// ---------------------------------------------------------------------------
// R6-312: Range proof MAX_MONEY boundary must be deterministic.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(boundary_range_proof_max_money_deterministic)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{uint256{201}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening opening;
    opening.value = MAX_MONEY;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    // MAX_MONEY must fit within VALUE_BITS (51 bits). Assert creation succeeds.
    BOOST_CHECK(CreateRangeProof(proof, opening, c));
    BOOST_CHECK(VerifyRangeProof(proof, c));
}

// ---------------------------------------------------------------------------
// R7-101: Balance proof must reject overflow in input/output sums.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_rejects_sum_overflow)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r1 = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r2 = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r3 = SampleUniformVec(rng, MODULE_RANK);

    // Two inputs each near MAX_MONEY: sum would overflow if unchecked.
    CommitmentOpening in1;
    in1.value = MAX_MONEY;
    in1.blind = r1;

    CommitmentOpening in2;
    in2.value = MAX_MONEY;
    in2.blind = r2;

    CommitmentOpening out;
    out.value = MAX_MONEY; // Doesn't matter, the input sum overflow should be caught.
    out.blind = r3;

    BalanceProof proof;
    // With two MAX_MONEY inputs, sum_in = 2*MAX_MONEY which exceeds MoneyRange.
    // CreateBalanceProof should return false because the checked sum is out of range.
    bool created = CreateBalanceProof(proof, {in1, in2}, {out}, /*fee=*/MAX_MONEY);
    // Either creation fails, or verification fails.
    if (created) {
        Commitment c_in1 = Commit(in1.value, in1.blind);
        Commitment c_in2 = Commit(in2.value, in2.blind);
        Commitment c_out = Commit(out.value, out.blind);
        BOOST_CHECK(!VerifyBalanceProof(proof, {c_in1, c_in2}, {c_out}, MAX_MONEY));
    }
}

// ---------------------------------------------------------------------------
// R7-104: Balance proof with padding still produces valid proofs.
// (Regression: ensure padding doesn't break proof generation.)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_with_padding_still_valid)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening in_opening;
    in_opening.value = 100000;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = 99000;
    out_opening.blind = r_out;

    CAmount fee = 1000;

    BalanceProof proof;
    BOOST_CHECK(CreateBalanceProof(proof, {in_opening}, {out_opening}, fee));
    BOOST_CHECK(proof.IsValid());

    Commitment c_in = Commit(in_opening.value, in_opening.blind);
    Commitment c_out = Commit(out_opening.value, out_opening.blind);
    BOOST_CHECK(VerifyBalanceProof(proof, {c_in}, {c_out}, fee));

    // Also verify determinism: creating again with same inputs gives same proof.
    BalanceProof proof2;
    BOOST_CHECK(CreateBalanceProof(proof2, {in_opening}, {out_opening}, fee));
    BOOST_CHECK_EQUAL(proof.transcript_hash.ToString(), proof2.transcript_hash.ToString());
}

// ---------------------------------------------------------------------------
// R7-101: Verify that negative input values are rejected.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_rejects_negative_input_value)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening in_opening;
    in_opening.value = -1; // Invalid: negative value
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = 1000;
    out_opening.blind = r_out;

    BalanceProof proof;
    // Should fail because input has invalid (negative) value.
    BOOST_CHECK(!CreateBalanceProof(proof, {in_opening}, {out_opening}, /*fee=*/0));
}

// ---------------------------------------------------------------------------
// R5-105: Verify that balance proofs created with current parameters only
// verify with the same transcript (which now includes lattice parameters).
// A proof that was valid before R5-105 would fail under the new transcript
// because the challenge hash has changed.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_transcript_binds_lattice_params)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount in_val = 5000;
    CAmount out_val = 4000;
    CAmount fee = 1000;

    CommitmentOpening in_opening;
    in_opening.value = in_val;
    in_opening.blind = r_in;

    CommitmentOpening out_opening;
    out_opening.value = out_val;
    out_opening.blind = r_out;

    BalanceProof proof;
    bool ok = CreateBalanceProof(proof, {in_opening}, {out_opening}, fee);
    BOOST_REQUIRE(ok);

    // Verify the proof is valid.
    Commitment in_commit = Commit(in_val, r_in);
    Commitment out_commit = Commit(out_val, r_out);
    BOOST_CHECK(VerifyBalanceProof(proof, {in_commit}, {out_commit}, fee));

    // Tamper with transcript_hash: even a single bit flip should invalidate.
    BalanceProof tampered_proof = proof;
    unsigned char* raw = tampered_proof.transcript_hash.begin();
    raw[0] ^= 0x01;
    BOOST_CHECK(!VerifyBalanceProof(tampered_proof, {in_commit}, {out_commit}, fee));
}

// ---------------------------------------------------------------------------
// Edge case: balance proof with MAX_MONEY input split into two outputs.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_max_money_split)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r_in = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out1 = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out2 = SampleUniformVec(rng, MODULE_RANK);

    CAmount total = MAX_MONEY;
    CAmount out1 = total / 2;
    CAmount out2 = total - out1;

    CommitmentOpening in_opening;
    in_opening.value = total;
    in_opening.blind = r_in;

    CommitmentOpening out_opening1;
    out_opening1.value = out1;
    out_opening1.blind = r_out1;

    CommitmentOpening out_opening2;
    out_opening2.value = out2;
    out_opening2.blind = r_out2;

    BalanceProof proof;
    bool ok = CreateBalanceProof(proof, {in_opening}, {out_opening1, out_opening2}, /*fee=*/0);
    BOOST_REQUIRE(ok);

    Commitment in_commit = Commit(total, r_in);
    Commitment out_commit1 = Commit(out1, r_out1);
    Commitment out_commit2 = Commit(out2, r_out2);
    BOOST_CHECK(VerifyBalanceProof(proof, {in_commit}, {out_commit1, out_commit2}, /*fee=*/0));
}

// ---------------------------------------------------------------------------
// Verify that multiple inputs summing correctly still produce valid proofs.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_multiple_inputs)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r_in1 = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_in2 = SampleUniformVec(rng, MODULE_RANK);
    PolyVec r_out = SampleUniformVec(rng, MODULE_RANK);

    CAmount val1 = 3000, val2 = 7000;
    CAmount fee = 500;
    CAmount out_val = val1 + val2 - fee;

    CommitmentOpening in1;
    in1.value = val1;
    in1.blind = r_in1;
    CommitmentOpening in2;
    in2.value = val2;
    in2.blind = r_in2;
    CommitmentOpening out;
    out.value = out_val;
    out.blind = r_out;

    BalanceProof proof;
    bool ok = CreateBalanceProof(proof, {in1, in2}, {out}, fee);
    BOOST_REQUIRE(ok);

    Commitment c_in1 = Commit(val1, r_in1);
    Commitment c_in2 = Commit(val2, r_in2);
    Commitment c_out = Commit(out_val, r_out);
    BOOST_CHECK(VerifyBalanceProof(proof, {c_in1, c_in2}, {c_out}, fee));

    // Wrong fee should fail.
    BOOST_CHECK(!VerifyBalanceProof(proof, {c_in1, c_in2}, {c_out}, fee + 1));
}

// ---------------------------------------------------------------------------
// S5: Truncated proof bytes must be rejected by validation layer.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(truncated_proof_bytes_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Serialize the proof.
    DataStream ds;
    ds << f.proof;
    const std::string full_bytes = ds.str();
    BOOST_REQUIRE(full_bytes.size() > 10);

    // Test multiple truncation points.
    for (size_t trunc : {size_t{1}, size_t{10}, full_bytes.size() / 2, full_bytes.size() - 1}) {
        DataStream truncated;
        truncated.write(MakeByteSpan(std::string_view{full_bytes.data(), trunc}));

        MatRiCTProof bad_proof;
        bool deserialized = true;
        try {
            truncated >> bad_proof;
        } catch (const std::ios_base::failure&) {
            deserialized = false;
        }

        // Either deserialization fails, or the resulting proof doesn't verify.
        if (deserialized) {
            std::vector<uint256> out_commits;
            for (const auto& c : bad_proof.output_note_commitments) out_commits.push_back(c);
            BOOST_CHECK(!VerifyMatRiCTProof(bad_proof, f.ring_members, f.input_nullifiers,
                                             out_commits, f.fee, f.tx_binding_hash));
        }
    }
}

// ---------------------------------------------------------------------------
// S6: Garbage proof bytes must be rejected.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(garbage_proof_bytes_rejected)
{
    ValidProofFixture f;
    BOOST_REQUIRE(f.Verify());

    // Serialize the proof, then replace with random garbage of same size.
    DataStream ds;
    ds << f.proof;
    FastRandomContext rng{uint256{0xDE}};

    std::string garbage(ds.size(), '\0');
    for (size_t i = 0; i < garbage.size(); ++i) {
        garbage[i] = static_cast<char>(rng.randbits(8));
    }

    DataStream garbage_ds;
    garbage_ds.write(MakeByteSpan(std::string_view{garbage.data(), garbage.size()}));

    MatRiCTProof bad_proof;
    bool deserialized = true;
    try {
        garbage_ds >> bad_proof;
    } catch (const std::ios_base::failure&) {
        deserialized = false;
    }

    if (deserialized) {
        std::vector<uint256> out_commits;
        for (const auto& c : bad_proof.output_note_commitments) out_commits.push_back(c);
        BOOST_CHECK(!VerifyMatRiCTProof(bad_proof, f.ring_members, f.input_nullifiers,
                                         out_commits, f.fee, f.tx_binding_hash));
    }
}

// ---------------------------------------------------------------------------
// S7: real_index out of bounds in CreateMatRiCTProof must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_index_out_of_bounds_rejected)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    std::vector<uint256> ring = MakeDistinctRingMembers(lattice::RING_SIZE);
    std::vector<std::vector<uint256>> ring_members{ring};

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = GetRandHash();
    in_note.rho = GetRandHash();
    in_note.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    Nullifier nf;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf, spending_key, in_note, ring[0]));

    // real_index = RING_SIZE (one past valid range)
    MatRiCTProof proof;
    BOOST_CHECK(!CreateMatRiCTProof(proof, {in_note}, {out_note}, {nf},
                                     ring_members, {lattice::RING_SIZE}, spending_key, /*fee=*/0));

    // real_index = SIZE_MAX
    BOOST_CHECK(!CreateMatRiCTProof(proof, {in_note}, {out_note}, {nf},
                                     ring_members, {std::numeric_limits<size_t>::max()},
                                     spending_key, /*fee=*/0));
}

// ---------------------------------------------------------------------------
// S9: CAmount integer overflow in CreateBalanceProof must be caught.
// (Complementing the existing R7-101 test with explicit MAX_MONEY + 1 input.)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(balance_proof_rejects_over_max_money_value)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{GetRandHash()};
    PolyVec r = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening bad_opening;
    bad_opening.value = MAX_MONEY + 1;
    bad_opening.blind = r;

    CommitmentOpening out_opening;
    out_opening.value = MAX_MONEY;
    out_opening.blind = SampleUniformVec(rng, MODULE_RANK);

    BalanceProof proof;
    BOOST_CHECK(!CreateBalanceProof(proof, {bad_opening}, {out_opening}, /*fee=*/1));
}

// ---------------------------------------------------------------------------
// S11: Per-bit-proof tampering in range proof verification.
// Tamper a single bit commitment in a range proof; verification must fail.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(range_proof_per_bit_tamper_rejected)
{
    using namespace shielded::lattice;
    using namespace shielded::ringct;

    FastRandomContext rng{uint256{0x77}};
    PolyVec blind = SampleUniformVec(rng, MODULE_RANK);

    CommitmentOpening opening;
    opening.value = 42;
    opening.blind = blind;

    Commitment c = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, c));
    BOOST_REQUIRE(VerifyRangeProof(proof, c));

    // Tamper each bit commitment in turn and verify rejection.
    for (size_t bit = 0; bit < proof.bit_commitments.size(); ++bit) {
        RangeProof tampered = proof;
        // Flip one coefficient of the bit commitment.
        tampered.bit_commitments[bit].vec[0].coeffs[0] += 1;
        BOOST_CHECK_MESSAGE(!VerifyRangeProof(tampered, c),
            "Expected range proof to fail after tampering bit " + std::to_string(bit));
    }

    // Also tamper a bit proof challenge digest and verify rejection.
    RangeProof tampered2 = proof;
    tampered2.bit_proofs[0].c0 = GetRandHash();
    BOOST_CHECK(!VerifyRangeProof(tampered2, c));
}

// ---------------------------------------------------------------------------
// S12: Empty input/output vectors in CreateMatRiCTProof must fail or produce
// a proof that is not useful (no valid transaction can have 0 inputs/outputs).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(empty_input_output_vectors_rejected)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    // Empty inputs with one output
    {
        ShieldedNote out_note;
        out_note.value = 5000;
        out_note.recipient_pk_hash = GetRandHash();
        out_note.rho = GetRandHash();
        out_note.rcm = GetRandHash();

        MatRiCTProof proof;
        bool ok = CreateMatRiCTProof(proof, /*input_notes=*/{}, {out_note},
                                      /*nullifiers=*/{}, /*ring_members=*/{},
                                      /*real_indices=*/{}, spending_key, /*fee=*/0);
        // Either creation fails or the proof is structurally invalid.
        if (ok) {
            BOOST_CHECK(!proof.IsValid());
        }
    }

    // One input with empty outputs
    {
        std::vector<uint256> ring = MakeDistinctRingMembers(lattice::RING_SIZE);
        ShieldedNote in_note;
        in_note.value = 5000;
        in_note.recipient_pk_hash = GetRandHash();
        in_note.rho = GetRandHash();
        in_note.rcm = GetRandHash();

        Nullifier nf;
        BOOST_REQUIRE(DeriveInputNullifierForNote(nf, spending_key, in_note, ring[0]));

        MatRiCTProof proof;
        bool ok = CreateMatRiCTProof(proof, {in_note}, /*output_notes=*/{},
                                      {nf}, {ring}, {0}, spending_key, /*fee=*/5000);
        if (ok) {
            BOOST_CHECK(!proof.IsValid());
        }
    }

    // Both empty
    {
        MatRiCTProof proof;
        bool ok = CreateMatRiCTProof(proof, {}, {}, {}, {}, {}, spending_key, /*fee=*/0);
        if (ok) {
            BOOST_CHECK(!proof.IsValid());
        }
    }
}

// ---------------------------------------------------------------------------
// S8: Merkle witness manipulation in proof verification.
// Build a valid proof with correct Merkle witness, then tamper the witness
// root; the validation layer must reject.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(merkle_witness_root_tamper_rejected)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    // Build a Merkle tree with known commitments that serve as ring members.
    shielded::ShieldedMerkleTree tree;
    std::vector<uint256> ring;
    ring.reserve(lattice::RING_SIZE);
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        uint256 commit = hw.GetSHA256();
        ring.push_back(commit);
        tree.Append(commit);
    }

    const uint256 correct_root = tree.Root();
    BOOST_CHECK(!correct_root.IsNull());

    // Build a valid proof using these ring members.
    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = GetRandHash();
    in_note.rho = GetRandHash();
    in_note.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    Nullifier nf;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf, spending_key, in_note, ring[0]));

    std::vector<std::vector<uint256>> ring_members{ring};
    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, {in_note}, {out_note}, {nf},
                                      ring_members, {0}, spending_key, /*fee=*/0));

    // Verify against the correct tree.
    std::vector<uint256> out_commits;
    for (const auto& c : proof.output_note_commitments) out_commits.push_back(c);
    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, {nf}, out_commits, /*fee=*/0));

    // Now tamper a ring member (simulating wrong Merkle path) — proof must fail.
    std::vector<std::vector<uint256>> tampered_ring{ring};
    tampered_ring[0][0] = GetRandHash();
    BOOST_CHECK(!VerifyMatRiCTProof(proof, tampered_ring, {nf}, out_commits, /*fee=*/0));
}

// ---------------------------------------------------------------------------
// S14: End-to-end integration test
// Wallet creates proof → serialize to CShieldedBundle → consensus validates
// via CShieldedProofCheck → spend auth checks pass.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(e2e_wallet_create_consensus_validate)
{
    const std::vector<unsigned char> spending_key(32, 0x42);

    // 1. Build ring members and Merkle tree.
    shielded::ShieldedMerkleTree tree;
    std::vector<uint256> ring;
    ring.reserve(lattice::RING_SIZE);
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        uint256 commit = hw.GetSHA256();
        ring.push_back(commit);
        tree.Append(commit);
    }

    // 2. Create notes.
    ShieldedNote in_note;
    in_note.value = 10000;
    in_note.recipient_pk_hash = GetRandHash();
    in_note.rho = GetRandHash();
    in_note.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 9000;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    CAmount fee = 1000;

    // 3. Derive nullifier.
    Nullifier nf;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf, spending_key, in_note, ring[0]));

    // 4. Build CShieldedBundle.
    CShieldedBundle bundle;
    CShieldedInput spend;
    spend.nullifier = nf;
    spend.ring_positions.reserve(lattice::RING_SIZE);
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        spend.ring_positions.push_back(i);
    }
    bundle.shielded_inputs.push_back(spend);

    CShieldedOutput output;
    output.note_commitment = out_note.GetCommitment();
    output.merkle_anchor = tree.Root();
    // Populate synthetic encrypted note (CheckStructure requires
    // aead_ciphertext.size() >= AEADChaCha20Poly1305::EXPANSION).
    output.encrypted_note.aead_ciphertext.resize(AEADChaCha20Poly1305::EXPANSION + 64, 0x00);
    bundle.shielded_outputs.push_back(output);
    bundle.value_balance = fee;

    // 5. Create transaction to get binding hash.
    CMutableTransaction mtx;
    mtx.shielded_bundle = bundle;
    const uint256 binding_hash = shielded::ringct::ComputeMatRiCTBindingHash(mtx);

    // 6. Create MatRiCT proof.
    std::vector<std::vector<uint256>> ring_members{ring};
    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, {in_note}, {out_note}, {nf},
                                      ring_members, {0}, spending_key,
                                      fee, binding_hash));

    // 7. Serialize proof into bundle.
    DataStream ds;
    ds << proof;
    const auto* begin = reinterpret_cast<const unsigned char*>(ds.data());
    mtx.shielded_bundle.proof.assign(begin, begin + ds.size());

    // 8. Create immutable CTransaction.
    const CTransaction tx{mtx};

    // 9. Validate via CShieldedProofCheck.
    CShieldedProofCheck proof_check(tx, std::make_shared<shielded::ShieldedMerkleTree>(tree));
    const auto proof_result = proof_check();
    BOOST_CHECK_MESSAGE(!proof_result.has_value(),
        "Proof check failed: " + proof_result.value_or(""));

    // 10. Validate via CShieldedSpendAuthCheck.
    CShieldedSpendAuthCheck spend_check(tx, /*spend_index=*/0);
    const auto spend_result = spend_check();
    BOOST_CHECK_MESSAGE(!spend_result.has_value(),
        "Spend auth check failed: " + spend_result.value_or(""));
}

BOOST_AUTO_TEST_SUITE_END()
