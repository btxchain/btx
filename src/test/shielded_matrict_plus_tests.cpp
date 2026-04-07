// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <hash.h>
#include <random.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/ringct/matrict.h>
#include <shielded/v2_proof.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace matrictplus = shielded::matrictplus;
namespace v2proof = shielded::v2::proof;

std::string ReadReferenceVectorFile()
{
    std::ifstream input{BTX_REFERENCE_TEST_VECTORS_PATH};
    if (!input.is_open()) {
        throw std::runtime_error("unable to open shielded reference vectors");
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

const UniValue& GetMatRiCTPlusReferenceVector()
{
    static const UniValue vectors = read_json(ReadReferenceVectorFile());
    return vectors.find_value("matrict_plus");
}

uint256 ParseUint256Hex(const UniValue& value)
{
    const auto parsed = uint256::FromHex(value.get_str());
    if (!parsed.has_value()) {
        throw std::runtime_error("invalid uint256 hex in MatRiCT+ reference vector");
    }
    return *parsed;
}

ShieldedNote ParseNote(const UniValue& value)
{
    ShieldedNote note;
    note.value = value.find_value("value").getInt<int64_t>();
    note.recipient_pk_hash = ParseUint256Hex(value.find_value("recipient_pk_hash_hex"));
    note.rho = ParseUint256Hex(value.find_value("rho_hex"));
    note.rcm = ParseUint256Hex(value.find_value("rcm_hex"));
    note.memo = ParseHex(value.find_value("memo_hex").get_str());

    const uint256 expected_commitment = ParseUint256Hex(value.find_value("commitment_hex"));
    if (note.GetCommitment() != expected_commitment) {
        throw std::runtime_error("MatRiCT+ reference vector note commitment mismatch");
    }
    return note;
}

std::vector<ShieldedNote> ParseNotes(const UniValue& values)
{
    std::vector<ShieldedNote> out;
    out.reserve(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        out.push_back(ParseNote(values[i]));
    }
    return out;
}

std::vector<uint256> ParseUint256Array(const UniValue& values)
{
    std::vector<uint256> out;
    out.reserve(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        out.push_back(ParseUint256Hex(values[i]));
    }
    return out;
}

std::vector<std::vector<uint256>> ParseRingMembers(const UniValue& values)
{
    std::vector<std::vector<uint256>> out;
    out.reserve(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        out.push_back(ParseUint256Array(values[i]));
    }
    return out;
}

std::vector<size_t> ParseSizeArray(const UniValue& values)
{
    std::vector<size_t> out;
    out.reserve(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        out.push_back(static_cast<size_t>(values[i].getInt<int64_t>()));
    }
    return out;
}

matrictplus::PortableFixture ParseFixture(const UniValue& value)
{
    matrictplus::PortableFixture fixture;
    fixture.input_notes = ParseNotes(value.find_value("input_notes"));
    fixture.output_notes = ParseNotes(value.find_value("output_notes"));
    fixture.input_nullifiers = ParseUint256Array(value.find_value("input_nullifiers_hex"));
    fixture.ring_members = ParseRingMembers(value.find_value("ring_members_hex"));
    fixture.output_note_commitments = ParseUint256Array(value.find_value("output_note_commitments_hex"));
    fixture.real_indices = ParseSizeArray(value.find_value("real_indices"));
    fixture.spending_key = ParseHex(value.find_value("spending_key_hex").get_str());
    fixture.fee = value.find_value("fee_sat").getInt<int64_t>();
    fixture.tx_binding_hash = ParseUint256Hex(value.find_value("tx_binding_hash_hex"));
    return fixture;
}

shielded::ringct::MatRiCTProof ParseProof(const UniValue& value)
{
    const std::vector<unsigned char> serialized = ParseHex(value.find_value("serialized_proof_hex").get_str());
    DataStream stream{serialized};
    shielded::ringct::MatRiCTProof proof;
    stream >> proof;
    if (!stream.empty()) {
        throw std::runtime_error("MatRiCT+ reference vector proof had trailing bytes");
    }
    return proof;
}

std::vector<unsigned char> SerializeProof(const shielded::ringct::MatRiCTProof& proof)
{
    DataStream stream;
    stream << proof;
    std::vector<unsigned char> serialized;
    serialized.reserve(stream.size());
    for (const std::byte byte : stream) {
        serialized.push_back(std::to_integer<unsigned char>(byte));
    }
    return serialized;
}

shielded::BridgeBatchStatement MakeBatchStatement()
{
    shielded::BridgeBatchStatement statement;
    statement.direction = shielded::BridgeDirection::BRIDGE_OUT;
    statement.ids.bridge_id = uint256{0x91};
    statement.ids.operation_id = uint256{0x92};
    statement.entry_count = 8;
    statement.total_amount = 7 * COIN;
    statement.batch_root = uint256{0x94};
    statement.domain_id = uint256{0x95};
    statement.source_epoch = 3;
    statement.data_root = uint256{0x96};
    return statement;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_matrict_plus_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(portable_fixture_rejects_real_member_mismatch)
{
    auto fixture = matrictplus::BuildDeterministicFixture();
    BOOST_REQUIRE(fixture.IsValid());

    fixture.ring_members[0][fixture.real_indices[0]] = GetRandHash();
    BOOST_CHECK(!fixture.IsValid());

    shielded::ringct::MatRiCTProof proof;
    BOOST_CHECK(!matrictplus::CreateProof(proof, fixture));
}

BOOST_AUTO_TEST_CASE(seeded_fixture_produces_valid_proof_and_transcript_export)
{
    for (uint32_t i = 0; i < 3; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_MatRiCTPlus_SeededFixture_Test_V1"};
        hw << i;
        const uint256 seed = hw.GetSHA256();

        const auto fixture = matrictplus::BuildFixtureFromSeed(seed);
        BOOST_REQUIRE(fixture.IsValid());

        shielded::ringct::MatRiCTProof proof;
        BOOST_REQUIRE(matrictplus::CreateProof(proof, fixture));
        BOOST_REQUIRE(matrictplus::VerifyProof(proof, fixture));

        std::vector<std::vector<std::vector<unsigned char>>> transcript_chunks;
        const uint256 message_hash = shielded::ringct::RingSignatureMessageHash(
            proof.input_commitments,
            proof.output_commitments,
            fixture.fee,
            fixture.input_nullifiers,
            fixture.tx_binding_hash);
        BOOST_REQUIRE(shielded::ringct::ExportRingSignatureTranscriptChunks(
            transcript_chunks,
            proof.ring_signature,
            fixture.ring_members,
            message_hash));
        BOOST_CHECK_EQUAL(transcript_chunks.size(), fixture.input_notes.size());
        for (const auto& input_chunks : transcript_chunks) {
            BOOST_CHECK_EQUAL(input_chunks.size(), shielded::lattice::RING_SIZE);
            for (const auto& chunk : input_chunks) {
                BOOST_CHECK(!chunk.empty());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(native_batch_backend_descriptor_uses_portable_backend_id)
{
    const auto backend = v2proof::DescribeMatRiCTPlusNativeBatchBackend();
    BOOST_CHECK(backend.IsValid());
    BOOST_CHECK(backend.backend_id == matrictplus::GetBackendId());
    BOOST_CHECK(backend.membership_proof_kind == shielded::v2::ProofComponentKind::MATRICT);
    BOOST_CHECK(backend.amount_proof_kind == shielded::v2::ProofComponentKind::RANGE);
    BOOST_CHECK(backend.balance_proof_kind == shielded::v2::ProofComponentKind::BALANCE);

    const auto proof_statement = v2proof::DescribeNativeBatchSettlementStatement(MakeBatchStatement(), backend);
    BOOST_CHECK(proof_statement.IsValid());
    BOOST_CHECK(proof_statement.domain == v2proof::VerificationDomain::BATCH_SETTLEMENT);
    BOOST_CHECK(proof_statement.envelope.proof_kind == shielded::v2::ProofKind::BATCH_MATRICT);
}

BOOST_AUTO_TEST_CASE(portable_fixture_accepts_supported_nondefault_ring_size)
{
    auto fixture = matrictplus::BuildDeterministicFixture();
    BOOST_REQUIRE(fixture.IsValid());

    fixture.ring_members.assign(fixture.input_notes.size(), std::vector<uint256>(16));
    fixture.real_indices = {3, 5};
    for (size_t i = 0; i < fixture.ring_members.size(); ++i) {
        for (size_t j = 0; j < fixture.ring_members[i].size(); ++j) {
            HashWriter hw;
            hw << std::string{"BTX_MatRiCTPlus_TestRing_V1"};
            hw << static_cast<uint32_t>(i);
            hw << static_cast<uint32_t>(j);
            fixture.ring_members[i][j] = hw.GetSHA256();
        }
        fixture.ring_members[i][fixture.real_indices[i]] = fixture.input_notes[i].GetCommitment();
    }
    fixture.input_nullifiers.clear();
    for (size_t i = 0; i < fixture.input_notes.size(); ++i) {
        Nullifier nullifier;
        BOOST_REQUIRE(shielded::ringct::DeriveInputNullifierForNote(nullifier,
                                                                    fixture.spending_key,
                                                                    fixture.input_notes[i],
                                                                    fixture.ring_members[i][fixture.real_indices[i]]));
        fixture.input_nullifiers.push_back(nullifier);
    }

    BOOST_CHECK(fixture.IsValid());
}

BOOST_AUTO_TEST_CASE(reference_vector_matches_deterministic_proof_creation)
{
    const UniValue& kat = GetMatRiCTPlusReferenceVector();
    BOOST_REQUIRE(kat.isObject());

    const uint256 expected_backend_id = ParseUint256Hex(kat.find_value("backend_id_hex"));
    BOOST_CHECK_EQUAL(matrictplus::GetBackendId(), expected_backend_id);

    const auto fixture = ParseFixture(kat.find_value("fixture"));
    BOOST_REQUIRE(fixture.IsValid());

    shielded::ringct::MatRiCTProof proof;
    BOOST_REQUIRE(matrictplus::CreateProof(proof, fixture));
    BOOST_REQUIRE(matrictplus::VerifyProof(proof, fixture));

    const UniValue& proof_vector = kat.find_value("proof");
    const std::vector<unsigned char> serialized = SerializeProof(proof);
    BOOST_CHECK_EQUAL(serialized.size(), proof_vector.find_value("serialized_size").getInt<int64_t>());
    BOOST_CHECK_EQUAL(HexStr(serialized), proof_vector.find_value("serialized_proof_hex").get_str());
    BOOST_CHECK_EQUAL(matrictplus::SerializeProofHash(proof),
                      ParseUint256Hex(proof_vector.find_value("serialized_proof_hash_hex")));
}

BOOST_AUTO_TEST_CASE(reference_vector_packaged_proof_verifies_against_packaged_statement)
{
    const UniValue& kat = GetMatRiCTPlusReferenceVector();
    BOOST_REQUIRE(kat.isObject());

    const auto fixture = ParseFixture(kat.find_value("fixture"));
    const auto proof = ParseProof(kat.find_value("proof"));
    BOOST_REQUIRE(fixture.IsValid());
    BOOST_REQUIRE(proof.IsValid());
    BOOST_CHECK(kat.find_value("proof").find_value("verification_expected").get_bool());

    const std::vector<unsigned char> serialized = SerializeProof(proof);
    BOOST_CHECK_EQUAL(serialized.size(), kat.find_value("proof").find_value("serialized_size").getInt<int64_t>());
    BOOST_CHECK_EQUAL(matrictplus::SerializeProofHash(proof),
                      ParseUint256Hex(kat.find_value("proof").find_value("serialized_proof_hash_hex")));
    BOOST_CHECK(matrictplus::VerifyProof(proof, fixture));

    auto tampered_fixture = fixture;
    tampered_fixture.output_note_commitments[0] = GetRandHash();
    BOOST_CHECK(!matrictplus::VerifyProof(proof, tampered_fixture));
}

BOOST_AUTO_TEST_SUITE_END()
