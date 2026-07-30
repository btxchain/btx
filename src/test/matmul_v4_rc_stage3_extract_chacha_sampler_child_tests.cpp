// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_extract_chacha_sampler_child.h>
#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>

#include <cstdlib>
#include <numeric>

namespace child =
    matmul::v4::rc::extract_chacha_sampler_child;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;
namespace rp = matmul::v4::rc::recursive_parent_air;

namespace {

uint256 H(uint8_t tag)
{
    uint256 out;
    out.SetNull();
    out.data()[0] = tag;
    out.data()[31] = static_cast<uint8_t>(tag ^ 0xa5U);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_extract_chacha_sampler_child_tests)

BOOST_AUTO_TEST_CASE(retained_node_is_fail_closed)
{
    child::TileStatementV1 statement;
    BOOST_CHECK(
        child::ComputeRetainedNodeCommitmentV1(statement)
            .IsNull());
    statement.statement_commitment = H(1);
    statement.public_fs_seed = H(2);
    statement.prf_key = H(3);
    statement.chacha_blocks = 1;
    statement.candidate_rows = 1;
    statement.trace_rows = 2048;
    statement.public_boundary_statement = H(4);
    statement.r0_root = H(5);
    statement.preprocessed_schedule_commitment = H(6);
    statement.program_challenge_commitment = H(7);
    statement.position_cells.resize(1);
    statement.input_bit_cells.resize(1);
    BOOST_CHECK(
        !child::ComputeRetainedNodeCommitmentV1(statement)
             .IsNull());
    statement.candidate_rows = 0;
    BOOST_CHECK(
        child::ComputeRetainedNodeCommitmentV1(statement)
            .IsNull());
}

BOOST_AUTO_TEST_CASE(
    challenge_domains_and_preprocessed_columns_are_distinct)
{
    child::TileStatementV1 statement;
    statement.statement_commitment = H(0x21);
    statement.public_fs_seed = H(0x22);
    statement.prf_key = H(0x23);
    statement.row = 7;
    statement.block = 9;
    statement.chacha_blocks = 1;
    statement.candidate_rows = 64;
    statement.trace_rows = 2048;
    statement.scale_e = 3;
    statement.r0_root = H(0x24);
    const auto challenge =
        child::DeriveChallengePairForAuditV1(statement);
    // Regression: serializing decayed C-string labels made the two labels
    // identical and allowed alpha == gamma.
    BOOST_CHECK(!gf::Eq(challenge[0], challenge[1]));

    child::aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 2;
    const std::vector<gf::Fp3> canonical{
        gf::Fp3::One(), gf::Fp3::Zero()};
    cs.preprocessed.emplace_back(1, canonical);
    std::vector<std::vector<gf::Fp3>> columns(
        2, std::vector<gf::Fp3>(
               2, gf::Fp3::Zero()));
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        child::MaterializeVerifierOwnedPreprocessedV1(
            cs, columns, &why),
        why);
    BOOST_CHECK_EQUAL(
        columns[1].size(), canonical.size());
    for (uint32_t row = 0; row < canonical.size(); ++row) {
        BOOST_CHECK(gf::Eq(columns[1][row], canonical[row]));
    }

    cs.preprocessed.emplace_back(
        1,
        std::vector<gf::Fp3>{
            gf::Fp3::Zero(), gf::Fp3::One()});
    BOOST_CHECK(
        !child::MaterializeVerifierOwnedPreprocessedV1(
            cs, columns, &why));
}

BOOST_AUTO_TEST_CASE(
    complete_program_challenge_binding_rejects_r0_and_schedule_substitution)
{
    child::TileStatementV1 statement;
    statement.statement_commitment = H(0x31);
    statement.public_fs_seed = H(0x32);
    statement.prf_key = H(0x33);
    statement.row = 7;
    statement.block = 9;
    statement.chacha_blocks = 1;
    statement.candidate_rows = 64;
    statement.trace_rows = 2048;
    statement.scale_e = 3;
    statement.r0_root = H(0x34);

    // Rebuild once to obtain the verifier-owned boundary and preprocessing
    // handles; neither is caller-selectable in an accepted statement.
    auto provisional =
        child::BuildProgramChallengeBindingV1(statement);
    BOOST_CHECK(!provisional.valid);
    BOOST_CHECK(
        !provisional.public_boundary_statement
             .IsNull());
    BOOST_CHECK(
        !provisional
             .preprocessed_schedule_commitment
             .IsNull());
    BOOST_CHECK(
        !provisional.challenge_commitment.IsNull());

    statement.public_boundary_statement =
        provisional.public_boundary_statement;
    statement.preprocessed_schedule_commitment =
        provisional
            .preprocessed_schedule_commitment;
    statement.program_challenge_commitment =
        provisional.challenge_commitment;
    const auto honest =
        child::BuildProgramChallengeBindingV1(
            statement);
    BOOST_REQUIRE(honest.valid);
    BOOST_CHECK_EQUAL(
        honest.challenges.size(),
        child::kProgramChallengeWidthV1);
    BOOST_CHECK(
        honest.preprocessed_schedule_commitment ==
        statement
            .preprocessed_schedule_commitment);

    auto wrong_r0 = statement;
    wrong_r0.r0_root = H(0x35);
    const auto substituted =
        child::BuildProgramChallengeBindingV1(
            wrong_r0);
    BOOST_CHECK(!substituted.valid);
    BOOST_CHECK(
        substituted.challenge_commitment !=
        honest.challenge_commitment);

    auto wrong_schedule = statement;
    wrong_schedule.preprocessed_schedule_commitment =
        H(0x36);
    BOOST_CHECK(
        !child::BuildProgramChallengeBindingV1(
             wrong_schedule).valid);
}

BOOST_AUTO_TEST_CASE(
    p2_v2_six_draws_are_parent_owned_replayable_and_domain_separated)
{
    child::TileStatementV1 statement;
    statement.version = child::kVersionV2;
    statement.statement_commitment = H(0x51);
    statement.public_fs_seed = H(0x52);
    statement.prf_key = H(0x53);
    statement.row = 7;
    statement.block = 9;
    statement.chacha_blocks = 1;
    statement.candidate_rows = 64;
    statement.trace_rows = 2048;
    statement.scale_e = 3;
    statement.r0_root = H(0x54);

    auto provisional =
        child::BuildProgramChallengeBindingV2(
            statement);
    BOOST_CHECK(!provisional.valid);
    BOOST_REQUIRE(
        !provisional.public_boundary_statement
             .IsNull());
    BOOST_REQUIRE(
        !provisional
             .preprocessed_schedule_commitment
             .IsNull());
    BOOST_REQUIRE(
        !provisional.challenge_commitment.IsNull());
    statement.public_boundary_statement =
        provisional.public_boundary_statement;
    statement.preprocessed_schedule_commitment =
        provisional.preprocessed_schedule_commitment;
    statement.program_challenge_commitment =
        provisional.challenge_commitment;

    const auto binding =
        child::BuildProgramChallengeBindingV2(
            statement);
    BOOST_REQUIRE(binding.valid);
    BOOST_CHECK(
        binding.exact_domain_and_ordinal_order);
    BOOST_CHECK(
        binding.all_challenges_parent_r0_derived);
    for (uint32_t i = 0;
         i < child::kProgramChallengeWidthV1; ++i) {
        const auto digest =
            rc::alg_hash::SpongeHashFp(
                binding.absorb_lanes[i]);
        const gf::Fp3 replayed{
            gf::Canonical(digest[0]),
            gf::Canonical(digest[1]),
            gf::Canonical(digest[2])};
        BOOST_CHECK(
            gf::Eq(replayed, binding.challenges[i]));
        for (uint32_t prior = 0;
             prior < i; ++prior) {
            BOOST_CHECK(
                !gf::Eq(
                    binding.challenges[i],
                    binding.challenges[prior]));
            BOOST_CHECK(
                binding.absorb_lanes[i] !=
                    binding.absorb_lanes[prior]);
        }
    }

    // Exercise the actual in-parent Poseidon2 chip on both relation families,
    // not merely the native sponge helper.
    for (const uint32_t i : {0U, 4U}) {
        const auto digest =
            rc::alg_hash::SpongeHashFp(
                binding.absorb_lanes[i]);
        const auto companion =
            rp::BuildChildFsChallengeP2ReplayFromLanesV1(
                binding.absorb_lanes[i],
                rc::Fri3AlgDigestToUint256(digest),
                binding.challenges[i]);
        BOOST_REQUIRE(companion.valid);
        BOOST_CHECK(companion.output_binds_digest);
        BOOST_CHECK(
            companion.challenge_bound_to_consumed);
        BOOST_CHECK_EQUAL(
            companion.witness_violations, 0U);
    }

    auto root_attack = statement;
    root_attack.r0_root = H(0x55);
    BOOST_CHECK(
        !child::BuildProgramChallengeBindingV2(
             root_attack).valid);

    auto version_attack = statement;
    version_attack.version = child::kVersionV1;
    BOOST_CHECK(
        !child::BuildProgramChallengeBindingV2(
             version_attack).valid);

    const auto wrong_digest =
        rc::alg_hash::SpongeHashFp(
            binding.absorb_lanes[1]);
    const auto substitution =
        rp::BuildChildFsChallengeP2ReplayFromLanesV1(
            binding.absorb_lanes[1],
            rc::Fri3AlgDigestToUint256(
                wrong_digest),
            binding.challenges[0]);
    BOOST_CHECK(!substitution.valid);
    BOOST_CHECK(
        !substitution
             .challenge_bound_to_consumed);
}

BOOST_AUTO_TEST_CASE(
    deterministic_component_finalizes_only_after_one_parent_r0)
{
    std::array<int64_t, 32> input{};
    for (uint32_t i = 0; i < input.size(); ++i) {
        input[i] =
            i & 1U
            ? -static_cast<int64_t>(
                  UINT64_C(0x100000000) + 7U * i)
            : static_cast<int64_t>(
                  UINT64_C(0x100000000) + 11U * i);
    }
    child::DeterministicComponentV1 component;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        child::BuildDeterministicComponentV1(
            H(0x41), H(0x42), H(0x43),
            7, 9, input, component, &why),
        why);
    BOOST_REQUIRE(component.valid);
    BOOST_CHECK(component.challenge_columns_absent);
    BOOST_CHECK(
        component.every_preprocessed_column_in_r0);
    BOOST_CHECK(
        component.cs.n_columns <
        component.full_relation_columns);
    BOOST_CHECK(component.cs.constraints.empty());

    child::aq::AirConstraintSystem<gf::Fp3>
        parent_cs;
    std::vector<std::vector<gf::Fp3>>
        parent_columns;
    matmul::v4::rc::stage3_air_parent_composer::
        ChildAttachmentV1 attachment;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::
            stage3_air_parent_composer::AppendChildV1(
                parent_cs, parent_columns,
                component.cs, component.columns,
                2, attachment, &why),
        why);
    BOOST_REQUIRE(attachment.valid);
    BOOST_CHECK(!attachment.row_lifted);

    // A sibling deterministic cell is committed by the same R0.  Extract
    // finalization may not sample its challenges before this cell exists.
    const uint32_t sibling_column =
        parent_cs.n_columns++;
    parent_columns.push_back(
        std::vector<gf::Fp3>(
            parent_cs.n_rows,
            gf::Fp3::FromFp(
                gf::FromU64(0x5aU))));
    std::vector<uint32_t> parent_base(
        parent_cs.n_columns);
    std::iota(
        parent_base.begin(),
        parent_base.end(), 0U);
    const auto r0 =
        child::aq::
            AirQuotientBuildTwoEpochBaseRowSession(
                parent_cs, parent_columns,
                parent_base);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const auto verifier_parent_prefix_cs =
        parent_cs;

    child::ParentFinalizationV1 finalized;
    BOOST_REQUIRE_MESSAGE(
        child::AppendFinalRelationToParentV1(
            component, attachment, r0,
            parent_cs, parent_columns,
            finalized, &why),
        why);
    BOOST_REQUIRE(finalized.valid);
    BOOST_CHECK(finalized.parent_owned_r0_consumed);
    BOOST_CHECK(
        finalized.deterministic_witness_preserved);
    BOOST_CHECK(
        finalized.exact_six_challenge_order);
    BOOST_CHECK_EQUAL(
        finalized.dependent_column_base,
        sibling_column + 1U);
    BOOST_CHECK(
        finalized.dependent_columns > 0);
    BOOST_CHECK_EQUAL(
        finalized.constraints_appended,
        component.full_relation_constraints);
    BOOST_CHECK_EQUAL(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(
                parent_cs, parent_columns),
        0U);

    child::VerifierComponentV1
        verifier_component;
    BOOST_REQUIRE_MESSAGE(
        child::BuildVerifierComponentV1(
            finalized.statement,
            verifier_component, &why),
        why);
    BOOST_REQUIRE(verifier_component.valid);
    BOOST_CHECK(
        verifier_component
            .deterministic_to_full_column ==
        component
            .deterministic_to_full_column);
    auto verifier_parent_cs =
        verifier_parent_prefix_cs;
    child::VerifierParentFinalizationV1
        verifier_finalized;
    BOOST_REQUIRE_MESSAGE(
        child::AppendVerifierRelationToParentV1(
            verifier_component, attachment,
            r0.base_row_commitment,
            verifier_parent_cs,
            verifier_finalized, &why),
        why);
    BOOST_REQUIRE(verifier_finalized.valid);
    BOOST_CHECK_EQUAL(
        verifier_parent_cs.n_columns,
        parent_cs.n_columns);
    BOOST_CHECK_EQUAL(
        verifier_parent_cs.constraints.size(),
        parent_cs.constraints.size());
    BOOST_CHECK(
        verifier_finalized.output_cells ==
        finalized.output_cells);
    BOOST_CHECK_EQUAL(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(
                verifier_parent_cs,
                parent_columns),
        0U);
    auto wrong_parent_cs =
        verifier_parent_prefix_cs;
    child::VerifierParentFinalizationV1
        wrong_parent;
    BOOST_CHECK(
        !child::AppendVerifierRelationToParentV1(
             verifier_component, attachment,
             H(0x45), wrong_parent_cs,
             wrong_parent, &why));

    // One-coordinate transcript substitution cannot be made authoritative
    // by recomputing the compact retained-node handle.  The verifier rebuilds
    // the exact six coordinates from the parent R0.
    auto substituted = finalized.statement;
    substituted.program_challenge_commitment =
        H(0x44);
    substituted.retained_node_commitment =
        child::ComputeRetainedNodeCommitmentV1(
            substituted);
    BOOST_CHECK(
        !child::BuildProgramChallengeBindingV1(
             substituted).valid);

    // The V2 construction runs the identical semantic relation and column
    // partition, but all six dependent coordinates come from the one
    // parent-owned Poseidon2 transcript.
    child::DeterministicComponentV1 p2_component;
    BOOST_REQUIRE_MESSAGE(
        child::BuildDeterministicComponentV2(
            H(0x41), H(0x42), H(0x43),
            7, 9, input, p2_component, &why),
        why);
    BOOST_REQUIRE(p2_component.valid);
    child::aq::AirConstraintSystem<gf::Fp3>
        p2_parent_cs;
    std::vector<std::vector<gf::Fp3>>
        p2_parent_columns;
    matmul::v4::rc::stage3_air_parent_composer::
        ChildAttachmentV1 p2_attachment;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::
            stage3_air_parent_composer::AppendChildV1(
                p2_parent_cs, p2_parent_columns,
                p2_component.cs,
                p2_component.columns,
                2, p2_attachment, &why),
        why);
    p2_parent_cs.n_columns++;
    p2_parent_columns.push_back(
        std::vector<gf::Fp3>(
            p2_parent_cs.n_rows,
            gf::Fp3::FromFp(
                gf::FromU64(0x5aU))));
    std::vector<uint32_t> p2_base(
        p2_parent_cs.n_columns);
    std::iota(
        p2_base.begin(), p2_base.end(), 0U);
    const auto p2_r0 =
        child::aq::
            AirQuotientBuildTwoEpochBaseRowSession(
                p2_parent_cs,
                p2_parent_columns, p2_base);
    BOOST_REQUIRE_MESSAGE(
        p2_r0.valid, p2_r0.note);
    const auto p2_verifier_prefix =
        p2_parent_cs;
    child::ParentFinalizationV1 p2_finalized;
    BOOST_REQUIRE_MESSAGE(
        child::AppendFinalRelationToParentV2(
            p2_component, p2_attachment, p2_r0,
            p2_parent_cs, p2_parent_columns,
            p2_finalized, &why),
        why);
    BOOST_REQUIRE(p2_finalized.valid);
    BOOST_CHECK_EQUAL(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(
                p2_parent_cs,
                p2_parent_columns),
        0U);
    const auto p2_binding =
        child::BuildProgramChallengeBindingV2(
            p2_finalized.statement);
    BOOST_REQUIRE(p2_binding.valid);
    BOOST_CHECK(
        p2_binding
            .all_challenges_parent_r0_derived);
    child::VerifierComponentV1
        p2_verifier_component;
    BOOST_REQUIRE_MESSAGE(
        child::BuildVerifierComponentV2(
            p2_finalized.statement,
            p2_verifier_component, &why),
        why);
    auto p2_verifier_cs =
        p2_verifier_prefix;
    child::VerifierParentFinalizationV1
        p2_verifier_finalized;
    BOOST_REQUIRE_MESSAGE(
        child::AppendVerifierRelationToParentV2(
            p2_verifier_component,
            p2_attachment,
            p2_r0.base_row_commitment,
            p2_verifier_cs,
            p2_verifier_finalized, &why),
        why);
    BOOST_REQUIRE(
        p2_verifier_finalized.valid);
    BOOST_CHECK_EQUAL(
        p2_verifier_cs.n_columns,
        p2_parent_cs.n_columns);
    BOOST_CHECK_EQUAL(
        p2_verifier_cs.constraints.size(),
        p2_parent_cs.constraints.size());
    BOOST_CHECK_EQUAL(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(
                p2_verifier_cs,
                p2_parent_columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    safe_split_rap_binds_chacha_nibbles_sampler_mix_and_output)
{
    if (std::getenv(
            "BTX_RUN_EXTRACT_CHACHA_SAMPLER_CHILD") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_EXTRACT_CHACHA_SAMPLER_CHILD=1 "
            "for the complete local Extract tile proof");
        return;
    }
    std::array<int64_t, 32> input{};
    for (uint32_t i = 0; i < input.size(); ++i) {
        input[i] =
            i & 1U
            ? -static_cast<int64_t>(
                  UINT64_C(0x100000000) + 17U * i)
            : static_cast<int64_t>(
                  UINT64_C(0x100000000) + 29U * i);
    }
    child::TileProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        child::ProveTileV1(
            H(0x11), H(0x12), H(0x13),
            7, 9, input, proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        child::VerifyTileV1(proof, &why), why);
    BOOST_CHECK(proof.native_verified);
    BOOST_CHECK(!proof.normalized_parent_consumed);
    BOOST_CHECK_EQUAL(
        proof.statement.output_cells.size(), 32U);
    BOOST_CHECK_EQUAL(
        proof.statement.position_cells.size(),
        proof.statement.candidate_rows);
    BOOST_CHECK_EQUAL(
        proof.statement.input_bit_cells.size(),
        proof.statement.candidate_rows);

    auto schedule_attack = proof;
    ++schedule_attack.statement.output_cells[0].column;
    schedule_attack.statement.retained_node_commitment =
        child::ComputeRetainedNodeCommitmentV1(
            schedule_attack.statement);
    BOOST_CHECK(
        !child::VerifyTileV1(
            schedule_attack, &why));

    auto nonce_attack = proof;
    ++nonce_attack.statement.row;
    nonce_attack.statement.retained_node_commitment =
        child::ComputeRetainedNodeCommitmentV1(
            nonce_attack.statement);
    BOOST_CHECK(
        !child::VerifyTileV1(nonce_attack, &why));

    auto proof_attack = proof;
    BOOST_REQUIRE(
        !proof_attack.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_attack.quotient.batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE(
        !proof_attack.quotient.batch.queries[0]
             .group_rows[0].values.empty());
    auto& value =
        proof_attack.quotient.batch.queries[0]
            .group_rows[0].values[0];
    value = gf::Add(value, gf::Fp3::One());
    BOOST_CHECK(
        !child::VerifyTileV1(
            proof_attack, &why));
}

BOOST_AUTO_TEST_SUITE_END()
