// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Adversarial test suite for MatRiCT+ confidential transactions.
// Targets vulnerability classes: inflation, double-spend, ring forgery,
// proof malleability, and validation gaps.
//
// References:
//   - MatRiCT (ACM CCS 2019, Esgin et al.)
//   - MatRiCT+ (IEEE S&P 2022, Esgin et al.)
//   - Zcash CVE-2019-7167 (counterfeiting via BCTV14 soundness bug)
//   - Zcash InternalH collision (double-spend via hash truncation)

#include <random.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/ringct/matrict.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <set>
#include <vector>

using namespace shielded::ringct;
namespace matrictplus = shielded::matrictplus;
namespace lattice = shielded::lattice;

namespace {

ShieldedNote MakeNote(CAmount value)
{
    ShieldedNote n;
    n.value = value;
    n.recipient_pk_hash = GetRandHash();
    n.rho = GetRandHash();
    n.rcm = GetRandHash();
    return n;
}

std::vector<Nullifier> BuildInputNullifiers(const std::vector<ShieldedNote>& input_notes,
                                            const std::vector<std::vector<uint256>>& ring_members,
                                            const std::vector<size_t>& real_indices,
                                            Span<const unsigned char> spending_key)
{
    if (input_notes.size() != ring_members.size()) return {};
    std::vector<Nullifier> out;
    out.reserve(ring_members.size());
    for (size_t i = 0; i < ring_members.size(); ++i) {
        if (i >= real_indices.size()) return {};
        if (real_indices[i] >= ring_members[i].size()) return {};
        Nullifier nf;
        if (!DeriveInputNullifierForNote(nf,
                                         spending_key,
                                         input_notes[i],
                                         ring_members[i][real_indices[i]])) return {};
        out.push_back(nf);
    }
    return out;
}

struct MatRiCTTestSetup {
    std::vector<ShieldedNote> inputs;
    std::vector<ShieldedNote> outputs;
    std::vector<std::vector<uint256>> ring_members;
    std::vector<size_t> real_indices;
    std::vector<unsigned char> spending_key;
    std::vector<Nullifier> nullifiers;
    CAmount fee;

    static MatRiCTTestSetup Create(
        const std::vector<CAmount>& in_amounts,
        const std::vector<CAmount>& out_amounts,
        CAmount fee_val,
        uint8_t key_byte)
    {
        MatRiCTTestSetup s;
        s.fee = fee_val;
        s.spending_key.assign(32, key_byte);

        for (auto v : in_amounts) s.inputs.push_back(MakeNote(v));
        for (auto v : out_amounts) s.outputs.push_back(MakeNote(v));

        s.ring_members.resize(s.inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
        s.real_indices.resize(s.inputs.size());
        for (size_t i = 0; i < s.inputs.size(); ++i) {
            for (size_t j = 0; j < lattice::RING_SIZE; ++j) {
                s.ring_members[i][j] = GetRandHash();
            }
            s.real_indices[i] = (i + 2) % lattice::RING_SIZE;
            s.ring_members[i][s.real_indices[i]] = s.inputs[i].GetCommitment();
        }

        s.nullifiers = BuildInputNullifiers(s.inputs, s.ring_members, s.real_indices, s.spending_key);
        return s;
    }

    bool CreateAndVerify(MatRiCTProof& proof) const {
        if (!CreateMatRiCTProof(proof, inputs, outputs, nullifiers,
                                ring_members, real_indices, spending_key, fee)) {
            return false;
        }
        std::vector<uint256> out_commitments;
        for (const auto& n : outputs) out_commitments.push_back(n.GetCommitment());
        return VerifyMatRiCTProof(proof, ring_members, nullifiers, out_commitments, fee);
    }
};

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(matrict_adversarial_tests, BasicTestingSetup)

// ============================================================================
// M1: INFLATION / COUNTERFEITING
// ============================================================================

// M1-1: Outputs exceed inputs+fee — must fail creation or verification.
BOOST_AUTO_TEST_CASE(m1_inflation_outputs_exceed_inputs)
{
    // in=700+500=1200, out=600+800=1400, fee=0 → 200 coins from nowhere
    auto s = MatRiCTTestSetup::Create({700, 500}, {600, 800}, 0, 0x11);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 2u);

    MatRiCTProof proof;
    bool created = CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                      s.ring_members, s.real_indices, s.spending_key, s.fee);

    if (created) {
        std::vector<uint256> out_commitments;
        for (const auto& n : s.outputs) out_commitments.push_back(n.GetCommitment());
        bool valid = VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers,
                                        out_commitments, s.fee);
        BOOST_CHECK_MESSAGE(!valid,
            "M1-1: INFLATION — unbalanced tx (in=1200, out=1400) verified! "
            "This is a counterfeiting vulnerability.");
    } else {
        BOOST_TEST_MESSAGE("M1-1: CreateMatRiCTProof correctly refused unbalanced tx.");
    }
}

// M1-2: Fee mismatch — proof created with one fee, verified with another.
BOOST_AUTO_TEST_CASE(m1_fee_mismatch_rejected)
{
    auto s = MatRiCTTestSetup::Create({700, 500}, {600, 450}, 150, 0x12);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 2u);

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                     s.ring_members, s.real_indices, s.spending_key, 150));

    std::vector<uint256> out_commitments;
    for (const auto& n : s.outputs) out_commitments.push_back(n.GetCommitment());

    // Correct fee verifies
    BOOST_REQUIRE(VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers,
                                     out_commitments, 150));

    // Wrong fee must fail
    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers,
                                            out_commitments, 100),
        "M1-2: Fee mismatch (150 vs 100) must be rejected.");

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers,
                                            out_commitments, 200),
        "M1-2b: Fee mismatch (150 vs 200) must be rejected.");
}

// M1-3: Zero-value inputs with positive outputs — pure inflation.
BOOST_AUTO_TEST_CASE(m1_zero_input_positive_output)
{
    auto s = MatRiCTTestSetup::Create({0}, {100}, 0, 0x13);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 1u);

    MatRiCTProof proof;
    bool created = CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                      s.ring_members, s.real_indices, s.spending_key, s.fee);
    if (created) {
        std::vector<uint256> out{s.outputs[0].GetCommitment()};
        bool valid = VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers, out, s.fee);
        BOOST_CHECK_MESSAGE(!valid,
            "M1-3: CRITICAL — Zero input with positive output verified! Counterfeiting.");
    } else {
        BOOST_TEST_MESSAGE("M1-3: Correctly refused zero-input positive-output tx.");
    }
}

// ============================================================================
// M2: DOUBLE-SPEND / NULLIFIER ATTACKS
// ============================================================================

// M2-1: Same note spent twice (different transactions) must produce same nullifier.
BOOST_AUTO_TEST_CASE(m2_same_note_same_nullifier)
{
    auto note = MakeNote(500);
    std::vector<unsigned char> sk(32, 0x22);
    auto commitment = note.GetCommitment();

    Nullifier nf1, nf2;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf1, sk, note, commitment));
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf2, sk, note, commitment));

    BOOST_CHECK_MESSAGE(nf1 == nf2,
        "M2-1: Same note + same key must produce identical nullifiers.");
}

// M2-2: Different notes must produce different nullifiers.
BOOST_AUTO_TEST_CASE(m2_different_notes_different_nullifiers)
{
    auto note1 = MakeNote(500);
    auto note2 = MakeNote(500); // same amount but different rho/rcm
    std::vector<unsigned char> sk(32, 0x23);

    Nullifier nf1, nf2;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf1, sk, note1, note1.GetCommitment()));
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf2, sk, note2, note2.GetCommitment()));

    BOOST_CHECK_MESSAGE(nf1 != nf2,
        "M2-2: Different notes must produce different nullifiers. "
        "Collision enables undetectable double-spend.");
}

// M2-3: Different spending keys on same note must produce different nullifiers.
BOOST_AUTO_TEST_CASE(m2_different_keys_different_nullifiers)
{
    auto note = MakeNote(500);
    auto commitment = note.GetCommitment();

    std::vector<unsigned char> sk1(32, 0x24);
    std::vector<unsigned char> sk2(32, 0x25);

    Nullifier nf1, nf2;
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf1, sk1, note, commitment));
    BOOST_REQUIRE(DeriveInputNullifierForNote(nf2, sk2, note, commitment));

    BOOST_CHECK_MESSAGE(nf1 != nf2,
        "M2-3: Different spending keys must produce different nullifiers.");
}

// M2-4: Tampered nullifier must cause verification failure.
BOOST_AUTO_TEST_CASE(m2_tampered_nullifier_rejected)
{
    auto s = MatRiCTTestSetup::Create({700, 500}, {600, 450}, 150, 0x26);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 2u);

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                     s.ring_members, s.real_indices, s.spending_key, s.fee));

    std::vector<uint256> out_commitments;
    for (const auto& n : s.outputs) out_commitments.push_back(n.GetCommitment());

    // Tamper first nullifier
    std::vector<Nullifier> tampered_nf = s.nullifiers;
    tampered_nf[0] = GetRandHash();

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, s.ring_members, tampered_nf,
                                            out_commitments, s.fee),
        "M2-4: Tampered nullifier must cause verification failure.");
}

// ============================================================================
// M3: RING SIGNATURE FORGERY
// ============================================================================

// M3-1: Wrong spending key must cause proof creation or verification failure.
BOOST_AUTO_TEST_CASE(m3_wrong_spending_key_rejected)
{
    auto s = MatRiCTTestSetup::Create({500}, {450}, 50, 0x31);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 1u);

    // Try to create proof with wrong spending key
    std::vector<unsigned char> wrong_key(32, 0xFF);

    MatRiCTProof proof;
    bool created = CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                      s.ring_members, s.real_indices, wrong_key, s.fee);
    if (created) {
        std::vector<uint256> out{s.outputs[0].GetCommitment()};
        bool valid = VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers, out, s.fee);
        BOOST_CHECK_MESSAGE(!valid,
            "M3-1: Proof with wrong spending key must fail verification.");
    } else {
        BOOST_TEST_MESSAGE("M3-1: Correctly refused proof creation with wrong key.");
    }
}

// M3-2: Tampered ring members must cause verification failure.
BOOST_AUTO_TEST_CASE(m3_tampered_ring_members_rejected)
{
    auto s = MatRiCTTestSetup::Create({700, 500}, {600, 450}, 150, 0x32);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 2u);

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                     s.ring_members, s.real_indices, s.spending_key, s.fee));

    std::vector<uint256> out_commitments;
    for (const auto& n : s.outputs) out_commitments.push_back(n.GetCommitment());

    // Tamper a non-real ring member
    auto tampered_rings = s.ring_members;
    size_t tamper_idx = (s.real_indices[0] + 1) % lattice::RING_SIZE;
    tampered_rings[0][tamper_idx] = GetRandHash();

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, tampered_rings, s.nullifiers,
                                            out_commitments, s.fee),
        "M3-2: Tampered ring members must cause verification failure.");
}

// M3-3: Tampered real ring member (the actual spent coin) must fail.
BOOST_AUTO_TEST_CASE(m3_tampered_real_ring_member_rejected)
{
    auto s = MatRiCTTestSetup::Create({500}, {450}, 50, 0x33);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 1u);

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                     s.ring_members, s.real_indices, s.spending_key, s.fee));

    std::vector<uint256> out{s.outputs[0].GetCommitment()};

    // Tamper the real ring member
    auto tampered_rings = s.ring_members;
    tampered_rings[0][s.real_indices[0]] = GetRandHash();

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, tampered_rings, s.nullifiers, out, s.fee),
        "M3-3: Tampered real ring member must cause verification failure.");
}

// ============================================================================
// M4: PROOF MALLEABILITY / COMPONENT SUBSTITUTION
// ============================================================================

// M4-1: Substitute ring signature from a different valid proof.
BOOST_AUTO_TEST_CASE(m4_ring_signature_substitution_rejected)
{
    auto s_a = MatRiCTTestSetup::Create({700}, {650}, 50, 0x41);
    auto s_b = MatRiCTTestSetup::Create({500}, {450}, 50, 0x42);

    MatRiCTProof proof_a, proof_b;
    BOOST_REQUIRE(s_a.CreateAndVerify(proof_a));
    BOOST_REQUIRE(s_b.CreateAndVerify(proof_b));

    // Substitute ring signature
    MatRiCTProof tampered = proof_a;
    tampered.ring_signature = proof_b.ring_signature;

    std::vector<uint256> out_a;
    for (const auto& n : s_a.outputs) out_a.push_back(n.GetCommitment());

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(tampered, s_a.ring_members, s_a.nullifiers,
                                            out_a, s_a.fee),
        "M4-1: Substituted ring signature must be rejected.");
}

// M4-2: Substitute balance proof from a different valid proof.
BOOST_AUTO_TEST_CASE(m4_balance_proof_substitution_rejected)
{
    auto s_a = MatRiCTTestSetup::Create({700}, {650}, 50, 0x43);
    auto s_b = MatRiCTTestSetup::Create({500}, {450}, 50, 0x44);

    MatRiCTProof proof_a, proof_b;
    BOOST_REQUIRE(s_a.CreateAndVerify(proof_a));
    BOOST_REQUIRE(s_b.CreateAndVerify(proof_b));

    MatRiCTProof tampered = proof_a;
    tampered.balance_proof = proof_b.balance_proof;

    std::vector<uint256> out_a;
    for (const auto& n : s_a.outputs) out_a.push_back(n.GetCommitment());

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(tampered, s_a.ring_members, s_a.nullifiers,
                                            out_a, s_a.fee),
        "M4-2: Substituted balance proof must be rejected.");
}

// M4-3: Substitute range proofs from a different valid proof.
BOOST_AUTO_TEST_CASE(m4_range_proof_substitution_rejected)
{
    auto s_a = MatRiCTTestSetup::Create({700}, {650}, 50, 0x45);
    auto s_b = MatRiCTTestSetup::Create({500}, {450}, 50, 0x46);

    MatRiCTProof proof_a, proof_b;
    BOOST_REQUIRE(s_a.CreateAndVerify(proof_a));
    BOOST_REQUIRE(s_b.CreateAndVerify(proof_b));

    MatRiCTProof tampered = proof_a;
    tampered.output_range_proofs = proof_b.output_range_proofs;

    std::vector<uint256> out_a;
    for (const auto& n : s_a.outputs) out_a.push_back(n.GetCommitment());

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(tampered, s_a.ring_members, s_a.nullifiers,
                                            out_a, s_a.fee),
        "M4-3: Substituted range proofs must be rejected.");
}

// M4-4: Substitute challenge seed — must be rejected.
BOOST_AUTO_TEST_CASE(m4_challenge_seed_substitution_rejected)
{
    auto s_a = MatRiCTTestSetup::Create({700}, {650}, 50, 0x47);
    auto s_b = MatRiCTTestSetup::Create({500}, {450}, 50, 0x48);

    MatRiCTProof proof_a, proof_b;
    BOOST_REQUIRE(s_a.CreateAndVerify(proof_a));
    BOOST_REQUIRE(s_b.CreateAndVerify(proof_b));

    MatRiCTProof tampered = proof_a;
    tampered.challenge_seed = proof_b.challenge_seed;

    std::vector<uint256> out_a;
    for (const auto& n : s_a.outputs) out_a.push_back(n.GetCommitment());

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(tampered, s_a.ring_members, s_a.nullifiers,
                                            out_a, s_a.fee),
        "M4-4: Substituted challenge seed must be rejected.");
}

// ============================================================================
// M5: CROSS-TRANSACTION BINDING
// ============================================================================

// M5-1: Proof bound to one tx_binding_hash must not verify with another.
BOOST_AUTO_TEST_CASE(m5_cross_tx_replay_rejected)
{
    auto s = MatRiCTTestSetup::Create({800}, {750}, 50, 0x51);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 1u);

    const uint256 hash_a = GetRandHash();
    const uint256 hash_b = GetRandHash();

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, s.inputs, s.outputs, s.nullifiers,
                                     s.ring_members, s.real_indices, s.spending_key,
                                     s.fee, hash_a));

    std::vector<uint256> out{s.outputs[0].GetCommitment()};

    BOOST_REQUIRE(VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers, out, s.fee, hash_a));

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers, out, s.fee, hash_b),
        "M5-1: Proof must not verify with different tx binding hash.");

    BOOST_CHECK_MESSAGE(!VerifyMatRiCTProof(proof, s.ring_members, s.nullifiers, out, s.fee),
        "M5-1b: Proof bound to hash must not verify without any hash.");
}

// ============================================================================
// M6: EDGE CASES
// ============================================================================

// M6-1: Single input, single output (minimal).
BOOST_AUTO_TEST_CASE(m6_minimal_1in_1out)
{
    auto s = MatRiCTTestSetup::Create({500}, {450}, 50, 0x61);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 1u);

    MatRiCTProof proof;
    BOOST_CHECK(s.CreateAndVerify(proof));
    BOOST_TEST_MESSAGE("M6-1: Minimal 1-in-1-out proof size: " << proof.GetSerializedSize());
}

// M6-2: Three inputs, two outputs.
BOOST_AUTO_TEST_CASE(m6_three_in_two_out)
{
    auto s = MatRiCTTestSetup::Create({500, 400, 300}, {600, 450}, 150, 0x62);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 3u);

    MatRiCTProof proof;
    BOOST_CHECK(s.CreateAndVerify(proof));
    BOOST_TEST_MESSAGE("M6-2: 3-in-2-out proof size: " << proof.GetSerializedSize());
}

// M6-3: Large amounts (near CAmount bounds but balanced).
BOOST_AUTO_TEST_CASE(m6_large_amounts)
{
    CAmount large = 21000000LL * 100000000LL; // 21M BTC in satoshis
    auto s = MatRiCTTestSetup::Create({large}, {large - 1000}, 1000, 0x63);
    BOOST_REQUIRE_EQUAL(s.nullifiers.size(), 1u);

    MatRiCTProof proof;
    bool ok = s.CreateAndVerify(proof);
    BOOST_TEST_MESSAGE("M6-3: Large amount (" << large << " sats) proof: ok=" << ok);
    // Either succeeds or fails gracefully — no crash/overflow
}

// M6-4: Deterministic proof (same fixture → same hash).
BOOST_AUTO_TEST_CASE(m6_deterministic_proof)
{
    const auto fixture = matrictplus::BuildDeterministicFixture();
    BOOST_REQUIRE(fixture.IsValid());

    MatRiCTProof proof_a, proof_b;
    BOOST_REQUIRE(matrictplus::CreateProof(proof_a, fixture));
    BOOST_REQUIRE(matrictplus::CreateProof(proof_b, fixture));

    auto hash_a = matrictplus::SerializeProofHash(proof_a);
    auto hash_b = matrictplus::SerializeProofHash(proof_b);
    BOOST_CHECK_EQUAL(hash_a, hash_b);
}

// M6-5: Verify IsValid rejects empty/corrupt proof.
BOOST_AUTO_TEST_CASE(m6_empty_proof_invalid)
{
    MatRiCTProof empty_proof;
    BOOST_CHECK_MESSAGE(!empty_proof.IsValid(),
        "M6-5: Default-constructed (empty) proof must not be valid.");
}

BOOST_AUTO_TEST_SUITE_END()
