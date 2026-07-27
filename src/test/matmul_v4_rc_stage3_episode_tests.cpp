// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_episode_tests, BasicTestingSetup)

namespace {

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3SuccinctProof MakeEpisodeProof()
{
    rc::RCStage3SuccinctProof proof;
    proof.statement = rc::RCStage3StatementKind::Episode;
    auto& p = proof.public_inputs;
    p.height = 314;
    p.n_bits = 0x207fffff;
    p.episode_profile = 2;
    p.transcript_version = 1;
    p.program_consensus_pin.recursive_alg_hash_root = Filled(0x08);
    p.program_consensus_pin.external_sha256d_audit_root = Filled(0x09);
    p.program_consensus_pin.registry_binding = Filled(0x0a);
    p.header_commitment = Filled(0x11);
    p.params_commitment = Filled(0x22);
    p.target = Filled(0x7f);
    p.sigma = Filled(0x33);
    p.episode_digest = Filled(0x44);
    p.final_digest = Filled(0x55);
    p.transcript_commitment = Filled(0x66);

    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(proof);
    const auto roles =
        rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Episode);
    for (size_t i = 0; i < roles.size(); ++i) {
        rc::RCStage3EpisodeRelationProof relation;
        relation.role = roles[i];
        relation.engine =
            i == 1 || i == 2
                ? rc::RCStage3EpisodeEngine::EpisodeAirV1
                : (i == 4 ? rc::RCStage3EpisodeEngine::DirectNativeV1
                          : rc::RCStage3EpisodeEngine::WinnerGkrV7NativeV1);
        relation.covered_obligations =
            rc::RequiredRCStage3EpisodeCoverage(relation.role);
        relation.statement_commitment = statement_commitment;
        relation.payload = {static_cast<unsigned char>(i + 1), 0xa5, 0x5a};

        std::vector<unsigned char> encoded;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::EncodeRCStage3EpisodeRelationProof(relation, encoded, &why), why);
        proof.commitments.push_back(
            {roles[i], rc::RCStage3EpisodeSectionCommitment(encoded)});
        proof.sections.push_back({roles[i], std::move(encoded)});
    }
    return proof;
}

} // namespace

BOOST_AUTO_TEST_CASE(typed_episode_section_codec_is_canonical)
{
    const auto outer = MakeEpisodeProof();
    const auto& bytes = outer.sections[2].proof;
    rc::RCStage3EpisodeRelationProof decoded;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::DecodeRCStage3EpisodeRelationProof(bytes, decoded, &why), why);
    BOOST_CHECK(decoded.role == rc::RCStage3RelationRole::EpisodeExtract);
    BOOST_CHECK(decoded.engine == rc::RCStage3EpisodeEngine::EpisodeAirV1);
    BOOST_CHECK_EQUAL(
        decoded.covered_obligations,
        rc::RequiredRCStage3EpisodeCoverage(
            rc::RCStage3RelationRole::EpisodeExtract));

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_MESSAGE(
        rc::EncodeRCStage3EpisodeRelationProof(decoded, encoded, &why), why);
    BOOST_CHECK(encoded == bytes);
}

BOOST_AUTO_TEST_CASE(episode_statement_commitment_has_no_proof_hash_cycle)
{
    const auto proof = MakeEpisodeProof();
    const uint256 commitment = rc::RCStage3EpisodeStatementCommitment(proof);

    auto post_proof = proof;
    post_proof.public_inputs.transcript_commitment = Filled(0xee);
    BOOST_CHECK(rc::RCStage3EpisodeStatementCommitment(post_proof) == commitment);

    auto changed_statement = proof;
    changed_statement.public_inputs.final_digest = Filled(0xef);
    BOOST_CHECK(rc::RCStage3EpisodeStatementCommitment(changed_statement) != commitment);

    changed_statement = proof;
    changed_statement.public_inputs.program_consensus_pin
        .registry_binding.data()[0] ^= 1;
    BOOST_CHECK(
        rc::RCStage3EpisodeStatementCommitment(
            changed_statement) != commitment);
}

BOOST_AUTO_TEST_CASE(typed_episode_decoder_rejects_mutated_framing)
{
    const auto proof = MakeEpisodeProof();
    rc::RCStage3EpisodeRelationProof decoded;
    std::string why;

    auto reserved = proof.sections[0].proof;
    reserved[9] = 1;
    BOOST_CHECK(!rc::DecodeRCStage3EpisodeRelationProof(reserved, decoded, &why));
    BOOST_CHECK(why.find("nonzero_reserved") != std::string::npos);

    auto unknown_role = proof.sections[0].proof;
    unknown_role[6] = 0xff;
    unknown_role[7] = 0xff;
    BOOST_CHECK(!rc::DecodeRCStage3EpisodeRelationProof(unknown_role, decoded, &why));
    BOOST_CHECK(why.find("non_episode_inner_role") != std::string::npos);

    auto unknown_engine = proof.sections[0].proof;
    unknown_engine[8] = 0xff;
    BOOST_CHECK(!rc::DecodeRCStage3EpisodeRelationProof(unknown_engine, decoded, &why));
    BOOST_CHECK(why.find("unknown_inner_engine") != std::string::npos);

    auto unknown_obligation = proof.sections[0].proof;
    unknown_obligation[17] |= 0x80; // bit 63, never a registered obligation
    BOOST_CHECK(!rc::DecodeRCStage3EpisodeRelationProof(
        unknown_obligation, decoded, &why));
    BOOST_CHECK(why.find("noncanonical_obligation_mask") != std::string::npos);

    auto trailing = proof.sections[0].proof;
    trailing.push_back(0);
    BOOST_CHECK(!rc::DecodeRCStage3EpisodeRelationProof(trailing, decoded, &why));
    BOOST_CHECK(why.find("noncanonical_engine_proof_length") != std::string::npos);

    auto truncated = proof.sections[0].proof;
    truncated.pop_back();
    BOOST_CHECK(!rc::DecodeRCStage3EpisodeRelationProof(truncated, decoded, &why));
    BOOST_CHECK(why.find("noncanonical_engine_proof_length") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(all_six_episode_sections_are_bound_to_statement_and_roots)
{
    auto proof = MakeEpisodeProof();
    std::vector<rc::RCStage3EpisodeRelationProof> decoded;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3EpisodeRelationBindings(proof, &decoded, &why), why);
    BOOST_CHECK_EQUAL(decoded.size(), 6U);

    auto public_input_mutation = proof;
    public_input_mutation.public_inputs.height++;
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeRelationBindings(
        public_input_mutation, nullptr, &why));
    BOOST_CHECK(why.find("statement_binding") != std::string::npos);

    auto root_mutation = proof;
    root_mutation.commitments[1].root = Filled(0xee);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeRelationBindings(
        root_mutation, nullptr, &why));
    BOOST_CHECK(why.find("section_commitment") != std::string::npos);

    auto payload_mutation = proof;
    payload_mutation.sections[3].proof.back() ^= 1;
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeRelationBindings(
        payload_mutation, nullptr, &why));
    BOOST_CHECK(why.find("section_commitment") != std::string::npos);

    auto role_mutation = proof;
    rc::RCStage3EpisodeRelationProof wrong_role;
    BOOST_REQUIRE(rc::DecodeRCStage3EpisodeRelationProof(
        role_mutation.sections[0].proof, wrong_role, &why));
    wrong_role.role = rc::RCStage3RelationRole::EpisodeGemm;
    wrong_role.covered_obligations =
        rc::RequiredRCStage3EpisodeCoverage(wrong_role.role);
    BOOST_REQUIRE(rc::EncodeRCStage3EpisodeRelationProof(
        wrong_role, role_mutation.sections[0].proof, &why));
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeRelationBindings(
        role_mutation, nullptr, &why));
    BOOST_CHECK(why.find("inner_outer_role_mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(incomplete_coverage_and_native_engines_never_authorize)
{
    auto proof = MakeEpisodeProof();
    std::string why;
    BOOST_CHECK(!rc::RCStage3EpisodeRelationsReady());
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeRelations(proof, &why));
    BOOST_CHECK(why.find("native_witness_engine_forbidden") != std::string::npos);

    rc::RCStage3EpisodeRelationProof first;
    BOOST_REQUIRE(rc::DecodeRCStage3EpisodeRelationProof(
        proof.sections[0].proof, first, &why));
    first.covered_obligations &= first.covered_obligations - 1;
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(rc::EncodeRCStage3EpisodeRelationProof(first, encoded, &why));
    proof.sections[0].proof = encoded;
    proof.commitments[0].root = rc::RCStage3EpisodeSectionCommitment(encoded);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeRelations(proof, &why));
    BOOST_CHECK(why.find("incomplete_obligation_mask") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_only_is_rejected_and_prover_emits_no_partial_authority)
{
    auto coupled = MakeEpisodeProof();
    coupled.statement = rc::RCStage3StatementKind::Coupled;
    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeRelations(coupled, &why));
    BOOST_CHECK(why.find("coupled_only_statement") != std::string::npos);

    const auto episode = MakeEpisodeProof();
    std::vector<rc::RCStage3EpisodeRelationProof> typed;
    BOOST_REQUIRE(
        rc::ValidateRCStage3EpisodeRelationBindings(episode, &typed, &why));
    const auto result = rc::ProveRCStage3EpisodeRelations(episode, typed);
    BOOST_CHECK(!result.ok);
    BOOST_CHECK(result.commitments.empty());
    BOOST_CHECK(result.sections.empty());
    BOOST_CHECK_EQUAL(result.gaps.size(), 6U);
    BOOST_CHECK(result.note.find("no_complete_proof_only_engine") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(gap_report_names_every_registered_episode_role)
{
    const auto gaps = rc::CurrentRCStage3EpisodeRelationGaps();
    const auto roles =
        rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Episode);
    BOOST_REQUIRE_EQUAL(gaps.size(), roles.size());
    for (size_t i = 0; i < gaps.size(); ++i) {
        BOOST_CHECK(gaps[i].role == roles[i]);
        BOOST_CHECK_NE(gaps[i].missing_obligations, 0U);
        BOOST_CHECK(!gaps[i].reason.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
