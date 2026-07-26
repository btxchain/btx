// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_composition.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_composition_tests, BasicTestingSetup)

namespace {

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3SuccinctProof MakeProof(rc::RCStage3StatementKind statement)
{
    rc::RCStage3SuccinctProof proof;
    proof.statement = statement;
    auto& p = proof.public_inputs;
    p.height = 700;
    p.n_bits = 0x207fffff;
    p.episode_profile = statement == rc::RCStage3StatementKind::Coupled ? 0 : 2;
    p.coupled_profile = statement == rc::RCStage3StatementKind::Episode ? 0 : 3;
    p.transcript_version = 4;
    p.program_consensus_pin.recursive_alg_hash_root = Filled(0x08);
    p.program_consensus_pin.external_sha256d_audit_root = Filled(0x09);
    p.program_consensus_pin.registry_binding = Filled(0x0a);
    p.header_commitment = Filled(0x11);
    p.params_commitment = Filled(0x22);
    p.target = Filled(0x7f);
    p.sigma = Filled(0x33);
    p.episode_digest =
        statement == rc::RCStage3StatementKind::Coupled ? uint256{} : Filled(0x44);
    p.coupled_digest =
        statement == rc::RCStage3StatementKind::Episode ? uint256{} : Filled(0x55);

    const auto roles = rc::RequiredRCStage3RelationRoles(statement);
    for (size_t i = 0; i < roles.size(); ++i) {
        proof.commitments.push_back(
            {roles[i], Filled(static_cast<unsigned char>(0x80 + i))});
        proof.sections.push_back(
            {roles[i], {static_cast<unsigned char>(i), 0xa5, 0x5a}});
    }
    p.final_digest = rc::ComputeRCStage3FinalDigest(proof);
    p.transcript_commitment = rc::ComputeRCStage3TranscriptCommitment(proof);
    return proof;
}

} // namespace

BOOST_AUTO_TEST_CASE(composition_accepts_each_complete_statement_shape)
{
    for (const auto statement : {rc::RCStage3StatementKind::Episode,
                                 rc::RCStage3StatementKind::Coupled,
                                 rc::RCStage3StatementKind::Composed}) {
        const auto proof = MakeProof(statement);
        std::string why;
        BOOST_CHECK_MESSAGE(rc::VerifyRCStage3CompositionLink(proof, &why), why);
    }
}

BOOST_AUTO_TEST_CASE(composition_binds_both_legs_and_context)
{
    const auto proof = MakeProof(rc::RCStage3StatementKind::Composed);
    std::string why;

    auto bad = proof;
    bad.public_inputs.episode_digest.data()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(why.find("final_digest_mismatch") != std::string::npos);

    bad = proof;
    bad.public_inputs.coupled_digest.data()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(why.find("final_digest_mismatch") != std::string::npos);

    bad = proof;
    bad.public_inputs.header_commitment.data()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(why.find("final_digest_mismatch") != std::string::npos);

    bad = proof;
    bad.public_inputs.params_commitment.data()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(why.find("final_digest_mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(transcript_binds_every_commitment_and_section)
{
    const auto proof = MakeProof(rc::RCStage3StatementKind::Composed);
    std::string why;

    auto bad = proof;
    bad.commitments[3].root.data()[7] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(why.find("transcript_commitment_mismatch") != std::string::npos);

    bad = proof;
    bad.sections[8].proof[1] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(why.find("transcript_commitment_mismatch") != std::string::npos);

    bad = proof;
    bad.public_inputs.program_consensus_pin
        .recursive_alg_hash_root.data()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(bad, &why));
    BOOST_CHECK(
        why.find("transcript_commitment_mismatch") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(aggregation_seed_binds_statement_without_proof_cycle)
{
    const auto proof = MakeProof(rc::RCStage3StatementKind::Composed);
    const uint256 seed = rc::ComputeRCStage3AggregationSeed(proof);
    BOOST_CHECK(!seed.IsNull());

    // Proof bytes are produced after the aggregate FS seed is known and are
    // therefore deliberately excluded from it.
    auto changed_section = proof;
    changed_section.sections[2].proof.push_back(0x42);
    BOOST_CHECK(rc::ComputeRCStage3AggregationSeed(changed_section) == seed);

    // Outer commitments hash complete typed sections and therefore are also
    // proof-produced data. Child trace/fold roots are instead pinned inside
    // the recursive verifier's canonical public-pin object.
    auto changed_outer_commitment = proof;
    changed_outer_commitment.commitments[2].root.data()[0] ^= 1;
    BOOST_CHECK(rc::ComputeRCStage3AggregationSeed(changed_outer_commitment) == seed);

    auto changed_context = proof;
    changed_context.public_inputs.height += 1;
    BOOST_CHECK(rc::ComputeRCStage3AggregationSeed(changed_context) != seed);
}

BOOST_AUTO_TEST_CASE(single_leg_final_digest_is_not_substitutable)
{
    auto episode = MakeProof(rc::RCStage3StatementKind::Episode);
    auto coupled = MakeProof(rc::RCStage3StatementKind::Coupled);
    std::string why;

    BOOST_CHECK(episode.public_inputs.final_digest == episode.public_inputs.episode_digest);
    BOOST_CHECK(coupled.public_inputs.final_digest == coupled.public_inputs.coupled_digest);

    episode.public_inputs.final_digest = Filled(0x55);
    episode.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(episode);
    BOOST_CHECK(!rc::VerifyRCStage3CompositionLink(episode, &why));
    BOOST_CHECK(why.find("final_digest_mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
