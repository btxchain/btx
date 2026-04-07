// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <random.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/ringct/matrict.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>

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

MatRiCTProof MakeValidProofForSerialization()
{
    const std::vector<ShieldedNote> inputs{MakeNote(640)};
    const std::vector<ShieldedNote> outputs{MakeNote(590)};

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();
    ring_members[0][3] = inputs[0].GetCommitment();

    std::vector<unsigned char> spending_key(32, 0x4d);
    const std::vector<size_t> real_indices{3};
    const std::vector<Nullifier> input_nullifiers =
        BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/50));
    return proof;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ringct_matrict_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(create_verify_matrict_roundtrip)
{
    const std::vector<ShieldedNote> inputs{
        MakeNote(700),
        MakeNote(500),
    };
    const std::vector<ShieldedNote> outputs{
        MakeNote(600),
        MakeNote(450),
    };

    std::vector<std::vector<uint256>> ring_members(inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < ring_members.size(); ++i) {
        for (size_t j = 0; j < ring_members[i].size(); ++j) {
            ring_members[i][j] = GetRandHash();
        }
        ring_members[i][2 + i] = inputs[i].GetCommitment();
    }

    std::vector<unsigned char> spending_key(32, 0x77);
    std::vector<size_t> real_indices{2, 3};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/150));

    std::vector<uint256> output_commitments;
    output_commitments.reserve(outputs.size());
    for (const auto& note : outputs) output_commitments.push_back(note.GetCommitment());

    BOOST_CHECK(VerifyMatRiCTProof(proof,
                                   ring_members,
                                   input_nullifiers,
                                   output_commitments,
                                   /*fee=*/150));
}

BOOST_AUTO_TEST_CASE(create_verify_matrict_with_explicit_output_note_commitments)
{
    const std::vector<ShieldedNote> inputs{
        MakeNote(700),
        MakeNote(500),
    };
    const std::vector<ShieldedNote> outputs{
        MakeNote(600),
        MakeNote(450),
    };

    std::vector<std::vector<uint256>> ring_members(inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < ring_members.size(); ++i) {
        for (size_t j = 0; j < ring_members[i].size(); ++j) {
            ring_members[i][j] = GetRandHash();
        }
        ring_members[i][2 + i] = inputs[i].GetCommitment();
    }

    const std::vector<uint256> explicit_output_note_commitments{
        uint256{0x91},
        uint256{0x92},
    };
    std::vector<unsigned char> spending_key(32, 0x57);
    const std::vector<size_t> real_indices{2, 3};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     Span<const uint256>{explicit_output_note_commitments.data(),
                                                         explicit_output_note_commitments.size()},
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/150));

    BOOST_CHECK(VerifyMatRiCTProof(proof,
                                   ring_members,
                                   input_nullifiers,
                                   explicit_output_note_commitments,
                                   /*fee=*/150));

    std::vector<uint256> legacy_note_commitments;
    legacy_note_commitments.reserve(outputs.size());
    for (const auto& note : outputs) {
        legacy_note_commitments.push_back(note.GetCommitment());
    }
    BOOST_CHECK(!VerifyMatRiCTProof(proof,
                                    ring_members,
                                    input_nullifiers,
                                    legacy_note_commitments,
                                    /*fee=*/150));
}

BOOST_AUTO_TEST_CASE(output_commitment_mismatch_rejected)
{
    const std::vector<ShieldedNote> inputs{MakeNote(400)};
    const std::vector<ShieldedNote> outputs{MakeNote(350)};

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();
    ring_members[0][4] = inputs[0].GetCommitment();

    MatRiCTProof proof;
    std::vector<unsigned char> spending_key(32, 0x88);
    const std::vector<size_t> real_indices{4};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/50));

    std::vector<uint256> wrong_commitments{GetRandHash()};
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, input_nullifiers, wrong_commitments, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(ring_member_mismatch_rejected)
{
    const std::vector<ShieldedNote> inputs{MakeNote(900)};
    const std::vector<ShieldedNote> outputs{MakeNote(800)};

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();
    ring_members[0][1] = inputs[0].GetCommitment();

    MatRiCTProof proof;
    std::vector<unsigned char> spending_key(32, 0x93);
    const std::vector<size_t> real_indices{1};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/100));

    std::vector<std::vector<uint256>> tampered = ring_members;
    tampered[0][0] = GetRandHash();

    std::vector<uint256> out{outputs[0].GetCommitment()};
    BOOST_CHECK(!VerifyMatRiCTProof(proof, tampered, input_nullifiers, out, /*fee=*/100));
}

BOOST_AUTO_TEST_CASE(matrict_verifier_rejects_empty_or_subminimum_ring_surface)
{
    const std::vector<ShieldedNote> inputs{MakeNote(640)};
    const std::vector<ShieldedNote> outputs{MakeNote(590)};

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();
    ring_members[0][3] = inputs[0].GetCommitment();

    std::vector<unsigned char> spending_key(32, 0x44);
    const std::vector<size_t> real_indices{3};
    const std::vector<Nullifier> input_nullifiers =
        BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/50));

    const std::vector<uint256> output_commitments{outputs[0].GetCommitment()};
    BOOST_REQUIRE(VerifyMatRiCTProof(proof,
                                     ring_members,
                                     input_nullifiers,
                                     output_commitments,
                                     /*fee=*/50));
    BOOST_CHECK(!VerifyMatRiCTProof(proof,
                                    {},
                                    input_nullifiers,
                                    output_commitments,
                                    /*fee=*/50));

    auto subminimum_ring = ring_members;
    subminimum_ring[0].resize(lattice::MIN_RING_SIZE - 1);
    BOOST_CHECK(!VerifyMatRiCTProof(proof,
                                    subminimum_ring,
                                    input_nullifiers,
                                    output_commitments,
                                    /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(matrict_verifier_rejects_jagged_ring_surface)
{
    const std::vector<ShieldedNote> inputs{
        MakeNote(900),
        MakeNote(700),
    };
    const std::vector<ShieldedNote> outputs{
        MakeNote(800),
        MakeNote(750),
    };

    std::vector<std::vector<uint256>> ring_members(inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < ring_members.size(); ++i) {
        for (auto& member : ring_members[i]) member = GetRandHash();
        ring_members[i][2 + i] = inputs[i].GetCommitment();
    }

    std::vector<unsigned char> spending_key(32, 0x45);
    const std::vector<size_t> real_indices{2, 3};
    const std::vector<Nullifier> input_nullifiers =
        BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/50));

    std::vector<uint256> output_commitments;
    output_commitments.reserve(outputs.size());
    for (const auto& note : outputs) output_commitments.push_back(note.GetCommitment());

    BOOST_REQUIRE(VerifyMatRiCTProof(proof,
                                     ring_members,
                                     input_nullifiers,
                                     output_commitments,
                                     /*fee=*/50));

    auto jagged_ring = ring_members;
    jagged_ring[1].resize(lattice::RING_SIZE - 1);
    BOOST_CHECK(!VerifyMatRiCTProof(proof,
                                    jagged_ring,
                                    input_nullifiers,
                                    output_commitments,
                                    /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(proof_size_target_for_2in_2out)
{
    const std::vector<ShieldedNote> inputs{
        MakeNote(900),
        MakeNote(700),
    };
    const std::vector<ShieldedNote> outputs{
        MakeNote(800),
        MakeNote(650),
    };

    std::vector<std::vector<uint256>> ring_members(inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < ring_members.size(); ++i) {
        for (size_t j = 0; j < ring_members[i].size(); ++j) {
            ring_members[i][j] = GetRandHash();
        }
        ring_members[i][i + 2] = inputs[i].GetCommitment();
    }

    std::vector<unsigned char> spending_key(32, 0x4A);
    const std::vector<size_t> real_indices{2, 3};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());
    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/150));

    const size_t proof_size = proof.GetSerializedSize();
    BOOST_TEST_MESSAGE("MatRiCT 2in2out serialized size: " << proof_size << " bytes");
    // Tight guardrail for current 2-in/2-out envelope with polynomial challenges.
    BOOST_CHECK_LT(proof_size, static_cast<size_t>(1280 * 1024));
}

BOOST_AUTO_TEST_CASE(nullifier_binding_mismatch_rejected)
{
    const std::vector<ShieldedNote> inputs{MakeNote(500)};
    const std::vector<ShieldedNote> outputs{MakeNote(450)};

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();
    ring_members[0][5] = inputs[0].GetCommitment();

    MatRiCTProof proof;
    std::vector<unsigned char> spending_key(32, 0x19);
    const std::vector<size_t> real_indices{5};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/50));

    std::vector<Nullifier> tampered_nullifiers{GetRandHash()};
    std::vector<uint256> out{outputs[0].GetCommitment()};
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, tampered_nullifiers, out, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(deterministic_matrict_proof_is_repeatable)
{
    const auto fixture = matrictplus::BuildDeterministicFixture();
    BOOST_REQUIRE(fixture.IsValid());

    MatRiCTProof proof_a;
    MatRiCTProof proof_b;
    BOOST_REQUIRE(matrictplus::CreateProof(proof_a, fixture));
    BOOST_REQUIRE(matrictplus::CreateProof(proof_b, fixture));
    BOOST_REQUIRE(matrictplus::VerifyProof(proof_a, fixture));
    BOOST_REQUIRE(matrictplus::VerifyProof(proof_b, fixture));

    const uint256 hash_a = matrictplus::SerializeProofHash(proof_a);
    const uint256 hash_b = matrictplus::SerializeProofHash(proof_b);
    BOOST_CHECK_EQUAL(hash_a, hash_b);
    BOOST_TEST_MESSAGE("MatRiCT+ deterministic proof size: " << proof_a.GetSerializedSize() << " bytes");
    BOOST_TEST_MESSAGE("deterministic MatRiCT proof vector hash: " << hash_a.GetHex());
    BOOST_CHECK(proof_a.GetSerializedSize() > 0);
}

BOOST_AUTO_TEST_CASE(hedged_entropy_changes_matrict_proof_but_verifies)
{
    const auto fixture = matrictplus::BuildDeterministicFixture();
    BOOST_REQUIRE(fixture.IsValid());

    std::array<unsigned char, 32> entropy_a{};
    std::array<unsigned char, 32> entropy_b{};
    for (size_t i = 0; i < entropy_a.size(); ++i) {
        entropy_a[i] = static_cast<unsigned char>(i + 9);
        entropy_b[i] = static_cast<unsigned char>(0xA0 + i);
    }

    MatRiCTProof proof_a;
    MatRiCTProof proof_a_repeat;
    MatRiCTProof proof_b;
    BOOST_REQUIRE(matrictplus::CreateProof(proof_a,
                                           fixture,
                                           Span<const unsigned char>{entropy_a.data(), entropy_a.size()}));
    BOOST_REQUIRE(matrictplus::CreateProof(proof_a_repeat,
                                           fixture,
                                           Span<const unsigned char>{entropy_a.data(), entropy_a.size()}));
    BOOST_REQUIRE(matrictplus::CreateProof(proof_b,
                                           fixture,
                                           Span<const unsigned char>{entropy_b.data(), entropy_b.size()}));

    BOOST_REQUIRE(matrictplus::VerifyProof(proof_a, fixture));
    BOOST_REQUIRE(matrictplus::VerifyProof(proof_a_repeat, fixture));
    BOOST_REQUIRE(matrictplus::VerifyProof(proof_b, fixture));

    const uint256 hash_a = matrictplus::SerializeProofHash(proof_a);
    const uint256 hash_a_repeat = matrictplus::SerializeProofHash(proof_a_repeat);
    const uint256 hash_b = matrictplus::SerializeProofHash(proof_b);
    BOOST_CHECK_EQUAL(hash_a, hash_a_repeat);
    BOOST_CHECK(hash_a != hash_b);
}

BOOST_AUTO_TEST_CASE(three_input_matrict_proof_roundtrip)
{
    const std::vector<ShieldedNote> inputs{
        MakeNote(500),
        MakeNote(400),
        MakeNote(300),
    };
    const std::vector<ShieldedNote> outputs{
        MakeNote(600),
        MakeNote(450),
    };

    std::vector<std::vector<uint256>> ring_members(inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < ring_members.size(); ++i) {
        for (size_t j = 0; j < ring_members[i].size(); ++j) {
            ring_members[i][j] = GetRandHash();
        }
        ring_members[i][i + 1] = inputs[i].GetCommitment();
    }

    std::vector<unsigned char> spending_key(32, 0x33);
    std::vector<size_t> real_indices{1, 2, 3};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/150));

    std::vector<uint256> output_commitments;
    for (const auto& note : outputs) output_commitments.push_back(note.GetCommitment());

    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, input_nullifiers, output_commitments, /*fee=*/150));
}

BOOST_AUTO_TEST_CASE(four_input_one_output_matrict_proof_roundtrip)
{
    const std::vector<ShieldedNote> inputs{
        MakeNote(100),
        MakeNote(200),
        MakeNote(300),
        MakeNote(400),
    };
    const std::vector<ShieldedNote> outputs{
        MakeNote(950),
    };

    std::vector<std::vector<uint256>> ring_members(inputs.size(), std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < ring_members.size(); ++i) {
        for (size_t j = 0; j < ring_members[i].size(); ++j) {
            ring_members[i][j] = GetRandHash();
        }
        ring_members[i][i] = inputs[i].GetCommitment();
    }

    std::vector<unsigned char> spending_key(32, 0x44);
    std::vector<size_t> real_indices{0, 1, 2, 3};
    std::vector<Nullifier> input_nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(input_nullifiers.size(), inputs.size());

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     inputs,
                                     outputs,
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     /*fee=*/50));

    std::vector<uint256> output_commitments{outputs[0].GetCommitment()};

    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, input_nullifiers, output_commitments, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(sub_proof_substitution_detected)
{
    // Create two independent valid proofs and try to substitute sub-proofs
    const std::vector<ShieldedNote> inputs_a{MakeNote(700)};
    const std::vector<ShieldedNote> outputs_a{MakeNote(650)};

    const std::vector<ShieldedNote> inputs_b{MakeNote(500)};
    const std::vector<ShieldedNote> outputs_b{MakeNote(450)};

    auto make_ring = [](const ShieldedNote& note, size_t real_idx) {
        std::vector<std::vector<uint256>> ring(1, std::vector<uint256>(lattice::RING_SIZE));
        for (auto& member : ring[0]) member = GetRandHash();
        ring[0][real_idx] = note.GetCommitment();
        return ring;
    };

    auto ring_a = make_ring(inputs_a[0], 3);
    auto ring_b = make_ring(inputs_b[0], 5);

    std::vector<unsigned char> sk_a(32, 0xAA);
    std::vector<unsigned char> sk_b(32, 0xBB);

    auto nullifiers_a = BuildInputNullifiers(inputs_a, ring_a, {3}, sk_a);
    auto nullifiers_b = BuildInputNullifiers(inputs_b, ring_b, {5}, sk_b);
    BOOST_REQUIRE_EQUAL(nullifiers_a.size(), 1U);
    BOOST_REQUIRE_EQUAL(nullifiers_b.size(), 1U);

    MatRiCTProof proof_a, proof_b;
    BOOST_REQUIRE(CreateMatRiCTProof(proof_a, inputs_a, outputs_a, nullifiers_a, ring_a, {3}, sk_a, /*fee=*/50));
    BOOST_REQUIRE(CreateMatRiCTProof(proof_b, inputs_b, outputs_b, nullifiers_b, ring_b, {5}, sk_b, /*fee=*/50));

    // Substitute ring signature from proof_b into proof_a
    MatRiCTProof tampered = proof_a;
    tampered.ring_signature = proof_b.ring_signature;

    std::vector<uint256> out_a{outputs_a[0].GetCommitment()};
    BOOST_CHECK(!VerifyMatRiCTProof(tampered, ring_a, nullifiers_a, out_a, /*fee=*/50));

    // Substitute balance proof from proof_b into proof_a
    tampered = proof_a;
    tampered.balance_proof = proof_b.balance_proof;
    BOOST_CHECK(!VerifyMatRiCTProof(tampered, ring_a, nullifiers_a, out_a, /*fee=*/50));

    // Substitute range proofs from proof_b into proof_a
    tampered = proof_a;
    tampered.output_range_proofs = proof_b.output_range_proofs;
    BOOST_CHECK(!VerifyMatRiCTProof(tampered, ring_a, nullifiers_a, out_a, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(matrict_serialize_rejects_oversized_vector_counts)
{
    MatRiCTProof proof = MakeValidProofForSerialization();

    proof.output_range_proofs.resize(MAX_MATRICT_OUTPUTS + 1);
    DataStream ss_range;
    BOOST_CHECK_EXCEPTION(ss_range << proof,
                          std::ios_base::failure,
                          HasReason("MatRiCTProof::Serialize oversized output_range_proofs"));

    proof = MakeValidProofForSerialization();
    proof.input_commitments.resize(MAX_MATRICT_INPUTS + 1);
    DataStream ss_inputs;
    BOOST_CHECK_EXCEPTION(ss_inputs << proof,
                          std::ios_base::failure,
                          HasReason("MatRiCTProof::Serialize oversized input_commitments"));

    proof = MakeValidProofForSerialization();
    proof.output_commitments.resize(MAX_MATRICT_OUTPUTS + 1);
    DataStream ss_outputs;
    BOOST_CHECK_EXCEPTION(ss_outputs << proof,
                          std::ios_base::failure,
                          HasReason("MatRiCTProof::Serialize oversized output_commitments"));

    proof = MakeValidProofForSerialization();
    proof.output_note_commitments.resize(MAX_MATRICT_OUTPUTS + 1);
    DataStream ss_notes;
    BOOST_CHECK_EXCEPTION(ss_notes << proof,
                          std::ios_base::failure,
                          HasReason("MatRiCTProof::Serialize oversized output_note_commitments"));
}

BOOST_AUTO_TEST_CASE(matrict_unserialize_rejects_oversized_vector_counts)
{
    const MatRiCTProof proof = MakeValidProofForSerialization();

    {
        DataStream ss;
        ss << proof.ring_signature << proof.balance_proof;
        const uint64_t oversized_output_ranges = MAX_MATRICT_OUTPUTS + 1;
        ::Serialize(ss, COMPACTSIZE(oversized_output_ranges));

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize oversized output_range_proofs"));
    }

    {
        DataStream ss;
        ss << proof.ring_signature << proof.balance_proof;
        const uint64_t zero = 0;
        const uint64_t oversized_inputs = MAX_MATRICT_INPUTS + 1;
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(oversized_inputs));

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize oversized input_commitments"));
    }

    {
        DataStream ss;
        ss << proof.ring_signature << proof.balance_proof;
        const uint64_t zero = 0;
        const uint64_t oversized_outputs = MAX_MATRICT_OUTPUTS + 1;
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(oversized_outputs));

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize oversized output_commitments"));
    }

    {
        DataStream ss;
        ss << proof.ring_signature << proof.balance_proof;
        const uint64_t zero = 0;
        const uint64_t oversized_note_commitments = MAX_MATRICT_OUTPUTS + 1;
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(oversized_note_commitments));

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize oversized output_note_commitments"));
    }
}

BOOST_AUTO_TEST_CASE(matrict_unserialize_rejects_vector_count_mismatches)
{
    const MatRiCTProof proof = MakeValidProofForSerialization();

    {
        DataStream ss;
        const uint64_t one = 1;
        const uint64_t zero = 0;
        ss << proof.ring_signature << proof.balance_proof;
        ::Serialize(ss, COMPACTSIZE(one));
        ::Serialize(ss, proof.output_range_proofs.front());
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ss << proof.challenge_seed;

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize output range/commitment size mismatch"));
    }

    {
        DataStream ss;
        const uint64_t one = 1;
        const uint64_t zero = 0;
        ss << proof.ring_signature << proof.balance_proof;
        ::Serialize(ss, COMPACTSIZE(one));
        ::Serialize(ss, proof.output_range_proofs.front());
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(one));
        ::Serialize(ss, proof.output_commitments.front());
        ::Serialize(ss, COMPACTSIZE(zero));
        ss << proof.challenge_seed;

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize output note commitment size mismatch"));
    }

    {
        DataStream ss;
        const uint64_t zero = 0;
        ss << proof.ring_signature << proof.balance_proof;
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ::Serialize(ss, COMPACTSIZE(zero));
        ss << proof.challenge_seed;

        MatRiCTProof decoded;
        BOOST_CHECK_EXCEPTION(ss >> decoded,
                              std::ios_base::failure,
                              HasReason("MatRiCTProof::Unserialize ring/input commitment size mismatch"));
    }
}

BOOST_AUTO_TEST_CASE(cross_transaction_proof_replay_detected)
{
    const std::vector<ShieldedNote> inputs{MakeNote(800)};
    const std::vector<ShieldedNote> outputs{MakeNote(750)};

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();
    ring_members[0][7] = inputs[0].GetCommitment();

    std::vector<unsigned char> spending_key(32, 0xCC);
    const std::vector<size_t> real_indices{7};
    auto nullifiers = BuildInputNullifiers(inputs, ring_members, real_indices, spending_key);
    BOOST_REQUIRE_EQUAL(nullifiers.size(), 1U);

    const uint256 binding_hash_a = GetRandHash();
    const uint256 binding_hash_b = GetRandHash();

    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof, inputs, outputs, nullifiers, ring_members, real_indices,
                                     spending_key, /*fee=*/50, binding_hash_a));

    std::vector<uint256> out{outputs[0].GetCommitment()};

    // Correct binding hash verifies
    BOOST_CHECK(VerifyMatRiCTProof(proof, ring_members, nullifiers, out, /*fee=*/50, binding_hash_a));

    // Different binding hash (different tx) fails — prevents cross-tx replay
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, nullifiers, out, /*fee=*/50, binding_hash_b));

    // No binding hash (empty) also fails
    BOOST_CHECK(!VerifyMatRiCTProof(proof, ring_members, nullifiers, out, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(binding_hash_binds_genesis_after_disable_height)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = 77;

    CShieldedInput spend;
    spend.nullifier = GetRandHash();
    spend.ring_positions.resize(lattice::RING_SIZE);
    for (size_t i = 0; i < spend.ring_positions.size(); ++i) {
        spend.ring_positions[i] = i;
    }
    mtx.shielded_bundle.shielded_inputs.push_back(spend);

    CShieldedOutput output;
    output.note_commitment = GetRandHash();
    output.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(output);

    const CTransaction tx{mtx};
    const auto& main_consensus = Params().GetConsensus();
    const auto alt_params = CreateChainParams(*m_node.args, ChainType::SHIELDEDV2DEV);
    BOOST_REQUIRE(alt_params != nullptr);

    const uint256 legacy_hash = ComputeMatRiCTBindingHash(tx);
    const uint256 pre_disable_hash = ComputeMatRiCTBindingHash(
        tx,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight - 1);
    const uint256 post_disable_hash = ComputeMatRiCTBindingHash(
        tx,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);
    const uint256 alt_chain_hash = ComputeMatRiCTBindingHash(
        tx,
        alt_params->GetConsensus(),
        alt_params->GetConsensus().nShieldedMatRiCTDisableHeight);

    BOOST_CHECK_EQUAL(legacy_hash, pre_disable_hash);
    BOOST_CHECK(post_disable_hash != legacy_hash);
    BOOST_CHECK(post_disable_hash != alt_chain_hash);
}

BOOST_AUTO_TEST_SUITE_END()
