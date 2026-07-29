// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_production_canonical_registry.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

namespace rc = matmul::v4::rc;
namespace cr = rc::production_canonical_registry;
namespace cb = rc::constraint_bytecode;
namespace sites = rc::soundness_scenarios;
namespace sched = rc::aggregation_scheduler;
namespace ut = rc::universal_topology;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_production_canonical_registry_tests,
    BasicTestingSetup)

namespace {

sites::ProductionProofSiteManifest Manifest()
{
    return sites::BuildProductionProofSiteManifest(
        sites::SelectedProductionProofSitePolicy());
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_parent_program_roots_reconstruct_and_current_families_fail_closed)
{
    const auto manifest = Manifest();
    const auto schedule =
        sched::BuildProductionAggregationSchedule(manifest);
    const auto assessment =
        cr::AssessCanonicalProductionRegistryV1(
            manifest, schedule);

    BOOST_REQUIRE(assessment.canonical_family_sources);
    BOOST_REQUIRE(
        assessment.parent_program_roots_reconstructed);
    BOOST_REQUIRE(assessment.registry_roots_reconstructed);
    BOOST_REQUIRE(
        assessment.structurally_valid_diagnostic_registry);
    BOOST_REQUIRE(assessment.exact_parent_program_slots);
    BOOST_CHECK(
        assessment.diagnostic_registry
            .universal_parent_verifier ==
        assessment.universal_parent_program_root);
    BOOST_CHECK(
        assessment.diagnostic_registry
            .normalized_root_verifier ==
        assessment.normalized_root_program_root);
    BOOST_CHECK_EQUAL(
        assessment.family_migration.families_total, 28U);
    BOOST_CHECK_EQUAL(
        assessment.family_migration.families_real, 14U);
    BOOST_CHECK_EQUAL(
        assessment.family_migration.families_partial, 14U);
    BOOST_CHECK_EQUAL(
        assessment.family_residuals.size(), 14U);
    BOOST_CHECK(std::all_of(
        assessment.family_residuals.begin(),
        assessment.family_residuals.end(),
        [](const cr::FamilySemanticResidualV1& residual) {
            return residual.missing_obligations != 0;
        }));
    BOOST_CHECK(
        assessment.residual_mask &
        cr::kResidualIncompleteFamilySemantics);
    BOOST_CHECK(
        assessment.residual_mask &
        cr::kResidualNormalizedProgramExecution);
    BOOST_CHECK(!assessment.authority_eligible);

    ut::ProductionProgramRegistryV1 production;
    cr::AssessmentV1 rebuilt;
    std::string why;
    BOOST_CHECK(!cr::BuildCanonicalProductionRegistryV1(
        manifest, schedule, production, &rebuilt, &why));
    BOOST_CHECK(production.external_registry_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        rebuilt.family_residuals.size(), 14U);
    BOOST_CHECK(
        why.find("residuals_open") != std::string::npos);

    BOOST_CHECK(
        cr::ValidateCanonicalDiagnosticRegistryV1(
            manifest, schedule,
            assessment.diagnostic_registry, &why));
}

BOOST_AUTO_TEST_CASE(
    structurally_valid_parent_program_substitution_is_rejected)
{
    const auto manifest = Manifest();
    const auto schedule =
        sched::BuildProductionAggregationSchedule(manifest);
    const auto assessment =
        cr::AssessCanonicalProductionRegistryV1(
            manifest, schedule);
    BOOST_REQUIRE(
        assessment.structurally_valid_diagnostic_registry);

    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    const auto substituted =
        ut::BuildProductionProgramRegistryV1(
            manifest, schedule, sources,
            assessment.universal_parent_program,
            assessment.universal_parent_program);
    BOOST_REQUIRE(
        !substituted.external_registry_commitment.IsNull());
    BOOST_REQUIRE(ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, substituted,
        substituted.external_registry_commitment,
        substituted.recursive_registry_commitment));
    BOOST_CHECK(
        substituted.normalized_root_verifier !=
        assessment.diagnostic_registry
            .normalized_root_verifier);

    std::string why;
    BOOST_CHECK(
        !cr::ValidateCanonicalDiagnosticRegistryV1(
            manifest, schedule, substituted, &why));
    BOOST_CHECK(
        why.find("substitution") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    canonical_family_and_registry_root_substitutions_are_rejected)
{
    const auto manifest = Manifest();
    const auto schedule =
        sched::BuildProductionAggregationSchedule(manifest);
    const auto assessment =
        cr::AssessCanonicalProductionRegistryV1(
            manifest, schedule);
    BOOST_REQUIRE(
        assessment.structurally_valid_diagnostic_registry);

    auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    BOOST_REQUIRE_EQUAL(sources.size(), 28U);
    auto& source = sources.front();
    source.public_input_schema.push_back(0x42);
    const auto substituted =
        ut::BuildProductionProgramRegistryV1(
            manifest, schedule, sources,
            assessment.universal_parent_program,
            assessment.normalized_root_program);
    BOOST_REQUIRE(
        !substituted.external_registry_commitment.IsNull());
    BOOST_REQUIRE(ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, substituted,
        substituted.external_registry_commitment,
        substituted.recursive_registry_commitment));

    std::string why;
    BOOST_CHECK(
        !cr::ValidateCanonicalDiagnosticRegistryV1(
            manifest, schedule, substituted, &why));

    auto root_substitution =
        assessment.diagnostic_registry;
    root_substitution.external_registry_commitment.data()[0] ^=
        0x80;
    BOOST_CHECK(
        !cr::ValidateCanonicalDiagnosticRegistryV1(
            manifest, schedule, root_substitution, &why));
}

BOOST_AUTO_TEST_CASE(
    parent_program_codec_round_trip_preserves_both_commitment_roots)
{
    const auto manifest = Manifest();
    const auto schedule =
        sched::BuildProductionAggregationSchedule(manifest);
    const auto assessment =
        cr::AssessCanonicalProductionRegistryV1(
            manifest, schedule);
    BOOST_REQUIRE(
        assessment.parent_program_roots_reconstructed);

    for (const cb::ProgramTable* table : {
             &assessment.universal_parent_program,
             &assessment.normalized_root_program}) {
        std::vector<unsigned char> bytes;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            cb::SerializeProgramTable(*table, bytes, &why), why);
        cb::ProgramTable decoded;
        BOOST_REQUIRE_MESSAGE(
            cb::DeserializeProgramTable(
                bytes, decoded, &why), why);
        BOOST_CHECK(decoded == *table);
        BOOST_CHECK(
            cb::CommitProgramTableForExternalAndRecursiveUse(
                decoded) ==
            cb::CommitProgramTableForExternalAndRecursiveUse(
                *table));
    }
}

BOOST_AUTO_TEST_SUITE_END()
