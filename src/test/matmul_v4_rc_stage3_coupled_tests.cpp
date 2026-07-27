// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_coupled_tests, BasicTestingSetup)

namespace {

constexpr std::array<rc::RCStage3RelationRole, 8> COUPLED_ROLES{
    rc::RCStage3RelationRole::CoupledBank,
    rc::RCStage3RelationRole::CoupledGemm,
    rc::RCStage3RelationRole::CoupledExchange,
    rc::RCStage3RelationRole::CoupledPermutation,
    rc::RCStage3RelationRole::CoupledMix,
    rc::RCStage3RelationRole::CoupledExtract,
    rc::RCStage3RelationRole::CoupledBarrier,
    rc::RCStage3RelationRole::CoupledDigest,
};

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

rc::RCStage3SuccinctProof MakeCoupledProof()
{
    rc::RCStage3SuccinctProof proof;
    proof.statement = rc::RCStage3StatementKind::Coupled;
    auto& public_inputs = proof.public_inputs;
    public_inputs.height = 42;
    public_inputs.n_bits = 0x207fffff;
    public_inputs.coupled_profile = 4;
    public_inputs.transcript_version = rc::ENC_RC_V4;
    public_inputs.program_consensus_pin.recursive_alg_hash_root =
        Filled(0x08);
    public_inputs.program_consensus_pin.external_sha256d_audit_root =
        Filled(0x09);
    public_inputs.program_consensus_pin.registry_binding =
        Filled(0x0a);
    public_inputs.header_commitment = Filled(0x11);
    public_inputs.params_commitment = Filled(0x22);
    public_inputs.target = Filled(0x7f);
    public_inputs.sigma = Filled(0x33);
    public_inputs.coupled_digest = Filled(0x44);
    public_inputs.final_digest = Filled(0x55);
    public_inputs.transcript_commitment = Filled(0x66);

    const rc::RCStage3CoupledShape shape = rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(), rc::MakeMediumV4RCCoupOptions());
    const uint256 statement = rc::CommitRCStage3CoupledStatement(public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);
    uint256 input_root = public_inputs.header_commitment;

    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        rc::RCStage3CoupledRelationReceipt receipt;
        receipt.role = COUPLED_ROLES[i];
        receipt.shape = shape;
        receipt.statement_commitment = statement;
        receipt.params_commitment = public_inputs.params_commitment;
        receipt.coupled_shape_commitment = shape_commitment;
        receipt.sigma = public_inputs.sigma;
        receipt.input_root = input_root;
        receipt.output_root =
            i + 1 == COUPLED_ROLES.size()
                ? public_inputs.coupled_digest
                : Filled(static_cast<unsigned char>(0x80 + i));
        receipt.trace_root = Filled(static_cast<unsigned char>(0xa0 + i));
        const auto counts =
            rc::ExpectedRCStage3CoupledRelationCounts(receipt.role, shape);
        BOOST_REQUIRE(counts.has_value());
        receipt.primary_count = counts->primary;
        receipt.secondary_count = counts->secondary;
        receipt.engine_receipt = {
            static_cast<unsigned char>(i), 0xc3, 0x5a, 0xa5};
        receipt.aggregate_root =
            rc::CommitRCStage3CoupledRelationAggregate(receipt);

        std::vector<unsigned char> section;
        BOOST_REQUIRE(rc::SerializeRCStage3CoupledRelationReceipt(receipt, section));
        proof.commitments.push_back(
            {receipt.role, rc::CommitRCStage3CoupledSection(section)});
        proof.sections.push_back({receipt.role, std::move(section)});
        input_root = receipt.output_root;
    }
    return proof;
}

size_t RoleIndex(rc::RCStage3RelationRole role)
{
    const auto it = std::find(COUPLED_ROLES.begin(), COUPLED_ROLES.end(), role);
    BOOST_REQUIRE(it != COUPLED_ROLES.end());
    return static_cast<size_t>(std::distance(COUPLED_ROLES.begin(), it));
}

rc::RCStage3CoupledRelationReceipt DecodeAt(const rc::RCStage3SuccinctProof& proof,
                                            size_t index)
{
    const auto receipt =
        rc::DeserializeRCStage3CoupledRelationReceipt(proof.sections[index].proof);
    BOOST_REQUIRE(receipt.has_value());
    return *receipt;
}

void ReplaceAt(rc::RCStage3SuccinctProof& proof, size_t index,
               rc::RCStage3CoupledRelationReceipt receipt)
{
    receipt.aggregate_root = rc::CommitRCStage3CoupledRelationAggregate(receipt);
    std::vector<unsigned char> section;
    BOOST_REQUIRE(rc::SerializeRCStage3CoupledRelationReceipt(receipt, section));
    proof.sections[index].proof = section;
    proof.commitments[index].root = rc::CommitRCStage3CoupledSection(section);
}

} // namespace

BOOST_AUTO_TEST_CASE(coupled_exact_relation_coverage_counts)
{
    const auto shape = rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(), rc::MakeMediumV4RCCoupOptions());
    const std::array<rc::RCStage3CoupledRelationCounts, 8> expected{{
        {64, 64},       // every bank page and every scheduled selection
        {64, 16},       // every scheduled page GEMM, grouped by barrier/lobe
        {16, 32'768},   // every fixed lobe segment; no extra exchange rounds
        {4, 32'768},    // one public affine permutation per barrier
        {52, 32'768},   // 4 * log2(8192) butterfly stages
        {1'024, 32'768},// every 32-cell Extract tile
        {4, 32'768},    // every barrier and state byte
        {1, 5},         // bank root plus four barrier roots
    }};
    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        const auto actual =
            rc::ExpectedRCStage3CoupledRelationCounts(COUPLED_ROLES[i], shape);
        BOOST_REQUIRE(actual.has_value());
        BOOST_CHECK(*actual == expected[i]);
    }

    auto overflowing = shape;
    overflowing.lobes = std::numeric_limits<uint32_t>::max();
    std::string why;
    BOOST_CHECK(!rc::ExpectedRCStage3CoupledRelationCounts(
                     rc::RCStage3RelationRole::CoupledMix, overflowing, &why)
                     .has_value());
    BOOST_CHECK(why.find("state_bytes_overflow") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_receipt_codec_is_canonical_and_bounded)
{
    const auto proof = MakeCoupledProof();
    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        const auto decoded =
            rc::DeserializeRCStage3CoupledRelationReceipt(proof.sections[i].proof);
        BOOST_REQUIRE(decoded.has_value());
        std::vector<unsigned char> encoded;
        BOOST_REQUIRE(rc::SerializeRCStage3CoupledRelationReceipt(*decoded, encoded));
        BOOST_CHECK(encoded == proof.sections[i].proof);

        encoded.push_back(0);
        std::string why;
        BOOST_CHECK(
            !rc::DeserializeRCStage3CoupledRelationReceipt(encoded, &why).has_value());
        BOOST_CHECK(why.find("engine_length") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(coupled_statement_commitment_has_no_proof_hash_cycle)
{
    const auto proof = MakeCoupledProof();
    const uint256 commitment =
        rc::CommitRCStage3CoupledStatement(proof.public_inputs);

    auto post_proof = proof.public_inputs;
    post_proof.transcript_commitment = Filled(0xee);
    BOOST_CHECK(rc::CommitRCStage3CoupledStatement(post_proof) == commitment);

    auto changed_statement = proof.public_inputs;
    changed_statement.final_digest = Filled(0xef);
    BOOST_CHECK(rc::CommitRCStage3CoupledStatement(changed_statement) != commitment);
}

BOOST_AUTO_TEST_CASE(coupled_verifier_rejects_without_proof_only_engines)
{
    const auto proof = MakeCoupledProof();
    std::string why;
    BOOST_REQUIRE(rc::ValidateRCStage3ProofStructure(proof, &why));
    BOOST_CHECK(!rc::kRCStage3CoupledRelationEnginesReady);
    BOOST_CHECK(!rc::RCStage3CoupledRelationEnginesReady(&why));
    BOOST_CHECK(why.find("proof_engines_missing") != std::string::npos);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
    BOOST_CHECK(why.find("coupled:bank:recursive_decode") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_verifier_rejects_episode_only_and_legacy_permutation)
{
    auto episode = MakeCoupledProof();
    episode.statement = rc::RCStage3StatementKind::Episode;
    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(episode, &why));

    auto legacy = MakeCoupledProof();
    legacy.public_inputs.transcript_version = rc::ENC_RC_V3;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(legacy, &why));
    BOOST_CHECK(why.find("transcript_version") != std::string::npos);

    auto legacy_receipt = DecodeAt(MakeCoupledProof(), 0);
    legacy_receipt.shape.transcript_version = rc::ENC_RC_V3;
    legacy_receipt.coupled_shape_commitment =
        rc::CommitRCStage3CoupledShape(legacy_receipt.shape);
    std::vector<unsigned char> bytes;
    BOOST_CHECK(
        !rc::SerializeRCStage3CoupledRelationReceipt(legacy_receipt, bytes, &why));
    BOOST_CHECK(why.find("permutation_not_proof_friendly") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_every_role_rejects_undercoverage)
{
    for (rc::RCStage3RelationRole role : COUPLED_ROLES) {
        auto proof = MakeCoupledProof();
        const size_t index = RoleIndex(role);
        auto receipt = DecodeAt(proof, index);
        --receipt.primary_count;
        ReplaceAt(proof, index, receipt);

        std::string why;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
        BOOST_CHECK_MESSAGE(
            why.find(std::string(rc::RCStage3RelationRoleName(role)) + ":coverage") !=
                std::string::npos,
            why);
    }
}

BOOST_AUTO_TEST_CASE(coupled_every_role_rejects_broken_root_chain)
{
    for (rc::RCStage3RelationRole role : COUPLED_ROLES) {
        auto proof = MakeCoupledProof();
        const size_t index = RoleIndex(role);
        auto receipt = DecodeAt(proof, index);
        receipt.input_root = Filled(0xee);
        ReplaceAt(proof, index, receipt);

        std::string why;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
        BOOST_CHECK_MESSAGE(
            why.find(std::string(rc::RCStage3RelationRoleName(role)) + ":input_root") !=
                std::string::npos,
            why);
    }
}

BOOST_AUTO_TEST_CASE(coupled_rejects_commitment_aggregate_and_public_mutations)
{
    std::string why;
    auto section_mutation = MakeCoupledProof();
    section_mutation.sections[3].proof.back() ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(section_mutation, &why));
    BOOST_CHECK(why.find("section_commitment") != std::string::npos);

    auto aggregate_mutation = MakeCoupledProof();
    auto receipt = DecodeAt(aggregate_mutation, 4);
    receipt.aggregate_root = Filled(0xfe);
    std::vector<unsigned char> section;
    BOOST_REQUIRE(
        rc::SerializeRCStage3CoupledRelationReceipt(receipt, section));
    aggregate_mutation.sections[4].proof = section;
    aggregate_mutation.commitments[4].root =
        rc::CommitRCStage3CoupledSection(section);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(aggregate_mutation, &why));
    BOOST_CHECK(why.find("aggregate_root") != std::string::npos);

    auto public_mutation = MakeCoupledProof();
    public_mutation.public_inputs.sigma = Filled(0xef);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(public_mutation, &why));
    BOOST_CHECK(why.find("public_binding") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
