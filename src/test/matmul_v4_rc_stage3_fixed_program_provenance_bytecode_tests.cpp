// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_fixed_program_provenance_bytecode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace rc = matmul::v4::rc;
namespace fp = rc::fixed_program_provenance_bytecode;
namespace cb = rc::constraint_bytecode;
namespace ha = rc::stage3_hash_air;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_fixed_program_provenance_bytecode_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    sha_provenance_bytecode_is_exact_but_external_links_stay_open)
{
    cb::ProgramTable table;
    fp::ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildCanonicalProgramTableV1(
            rc::RCStage3RelationRole::EpisodeExtract,
            ha::ProgramKind::Sha256Compression,
            table, &manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(table, &why), why);
    BOOST_CHECK_EQUAL(table.current_width, fp::kColumnsV1);
    BOOST_CHECK_EQUAL(
        table.challenge_width, fp::kChallengeWidthV1);
    BOOST_CHECK_EQUAL(table.programs.size(), fp::kProgramsV1);
    BOOST_CHECK_EQUAL(manifest.programs, fp::kProgramsV1);
    BOOST_CHECK(manifest.exact_native_constraint_order);
    BOOST_CHECK(manifest.canonical_program_table);
    BOOST_CHECK(manifest.immutable_schedule_reconstructed);
    BOOST_CHECK(manifest.internal_ssa_provenance_complete);
    BOOST_CHECK(!manifest.immutable_schedule_root.IsNull());
    BOOST_CHECK(
        manifest.residual_mask &
        fp::kResidualPublicBoundarySourceLink);
    BOOST_CHECK(
        manifest.residual_mask &
        fp::kResidualFixedTraceRootConsumption);
    BOOST_CHECK(
        manifest.residual_mask &
        fp::kResidualExactAllInstanceAggregation);
    BOOST_CHECK(
        manifest.residual_mask &
        fp::kResidualRecursiveChildConsumption);
    BOOST_CHECK(!manifest.authority_eligible);

    const auto audit = fp::AuditAgainstNativeV1(
        rc::RCStage3RelationRole::EpisodeExtract,
        ha::ProgramKind::Sha256Compression, 16);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.native_constraints, 488U);
    BOOST_CHECK_EQUAL(audit.bytecode_programs, 497U);
    BOOST_CHECK_EQUAL(audit.mismatches, 0U);
    BOOST_CHECK(audit.challenge_products_checked);
}

BOOST_AUTO_TEST_CASE(
    chacha_uses_same_relation_but_a_distinct_immutable_schedule_root)
{
    cb::ProgramTable sha;
    cb::ProgramTable chacha;
    fp::ManifestV1 sha_manifest;
    fp::ManifestV1 chacha_manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildCanonicalProgramTableV1(
            rc::RCStage3RelationRole::EpisodeExtract,
            ha::ProgramKind::Sha256Compression,
            sha, &sha_manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fp::BuildCanonicalProgramTableV1(
            rc::RCStage3RelationRole::EpisodeExtract,
            ha::ProgramKind::ChaCha20Block,
            chacha, &chacha_manifest, &why),
        why);
    BOOST_CHECK(sha == chacha);
    BOOST_CHECK_NE(
        sha_manifest.fixed_program_commitment,
        chacha_manifest.fixed_program_commitment);
    BOOST_CHECK_NE(
        sha_manifest.immutable_schedule_root,
        chacha_manifest.immutable_schedule_root);

    const auto audit = fp::AuditAgainstNativeV1(
        rc::RCStage3RelationRole::EpisodeExtract,
        ha::ProgramKind::ChaCha20Block, 16);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
}

BOOST_AUTO_TEST_CASE(
    role_and_program_substitution_change_the_bound_keys)
{
    cb::ProgramTable episode;
    cb::ProgramTable coupled;
    fp::ManifestV1 episode_manifest;
    fp::ManifestV1 coupled_manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildCanonicalProgramTableV1(
            rc::RCStage3RelationRole::EpisodeExtract,
            ha::ProgramKind::Sha256Compression,
            episode, &episode_manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fp::BuildCanonicalProgramTableV1(
            rc::RCStage3RelationRole::CoupledExtract,
            ha::ProgramKind::Sha256Compression,
            coupled, &coupled_manifest, &why),
        why);
    BOOST_CHECK_NE(
        cb::CommitProgramTable(episode),
        cb::CommitProgramTable(coupled));
    BOOST_CHECK_EQUAL(
        episode_manifest.immutable_schedule_root,
        coupled_manifest.immutable_schedule_root);

    auto substituted = episode;
    substituted.programs.pop_back();
    BOOST_REQUIRE(cb::ValidateProgramTable(substituted, &why));
    BOOST_CHECK_NE(
        cb::CommitProgramTable(substituted),
        cb::CommitProgramTable(episode));
    BOOST_CHECK_EQUAL(
        substituted.programs.size(),
        fp::kProgramsV1 - 1);
}

BOOST_AUTO_TEST_SUITE_END()
