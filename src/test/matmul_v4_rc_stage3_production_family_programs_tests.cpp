// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>

namespace rc = matmul::v4::rc;
namespace ut = rc::universal_topology;
namespace ss = rc::soundness_scenarios;
namespace sch = rc::aggregation_scheduler;
namespace cb = rc::constraint_bytecode;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
using gf::Fp3;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_production_family_programs_tests)

namespace {

Fp3 U(uint64_t value) { return gf::FromU64_3(value); }

/** Same structural stub the topology tests use for the aggregation
 * verifiers; those are out of this lane's scope (universal_parent_verifier /
 * normalized_root_verifier), so both stay the pre-existing placeholder. */
cb::ProgramTable OneColumnProgram(rc::RCStage3RelationRole role)
{
    cb::ProgramTable table;
    table.role = role;
    table.current_width = 1;
    table.next_width = 1;
    cb::Program program;
    program.role = role;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back(
        {cb::Opcode::Current, 0, 0, Fp3::Zero()});
    table.programs.push_back(std::move(program));
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    return table;
}

size_t FindFamilyIndex(
    const ss::ProductionProofSiteManifest& manifest,
    ss::ProductionProofSiteKind kind)
{
    const auto it = std::find_if(
        manifest.entries.begin(), manifest.entries.end(),
        [kind](const ss::ProductionProofSiteEntry& e) {
            return e.kind == kind;
        });
    BOOST_REQUIRE(it != manifest.entries.end());
    return static_cast<size_t>(it - manifest.entries.begin());
}

std::vector<Fp3> EvaluateAll(
    const cb::ProgramTable& table,
    const std::vector<Fp3>& current,
    const std::vector<Fp3>& next)
{
    std::vector<Fp3> results;
    results.reserve(table.programs.size());
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(cb::EvaluateProgram(program, current, next, value));
        results.push_back(value);
    }
    return results;
}

bool AllZero(const std::vector<Fp3>& values)
{
    return std::all_of(
        values.begin(), values.end(),
        [](const Fp3& v) { return gf::IsZero(v); });
}

bool AnyNonzero(const std::vector<Fp3>& values)
{
    return std::any_of(
        values.begin(), values.end(),
        [](const Fp3& v) { return !gf::IsZero(v); });
}

bool ConstraintApplies(
    aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    real_and_partial_family_programs_are_honestly_classified)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    BOOST_REQUIRE_EQUAL(sources.size(), manifest.entries.size());

    const size_t builder_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeBuilderCounterXof);
    const auto& builder = sources[builder_idx];
    BOOST_CHECK(
        builder.role ==
        rc::RCStage3RelationRole::EpisodeDeterministicBuilder);
    BOOST_CHECK_EQUAL(builder.program.current_width, 6U);
    BOOST_CHECK_EQUAL(builder.program.programs.size(), 5U);
    BOOST_REQUIRE_EQUAL(builder.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        builder.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderTrace));
    BOOST_CHECK(builder.semantic_relation_complete);

    const size_t digest_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeDigestSha256d);
    const auto& digest = sources[digest_idx];
    BOOST_CHECK(digest.role == rc::RCStage3RelationRole::EpisodeDigest);
    BOOST_CHECK_EQUAL(digest.program.current_width, 12U);
    BOOST_CHECK_EQUAL(digest.program.programs.size(), 14U);
    BOOST_REQUIRE_EQUAL(digest.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        digest.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeDigestPow));
    BOOST_CHECK(digest.semantic_relation_complete);

    const size_t tile_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeTileTreeSha256d);
    const auto& tile = sources[tile_idx];
    BOOST_CHECK(tile.role == rc::RCStage3RelationRole::EpisodeTileTree);
    BOOST_CHECK_EQUAL(tile.program.current_width, 15U);
    BOOST_CHECK_EQUAL(tile.program.programs.size(), 16U);
    BOOST_REQUIRE_EQUAL(tile.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        tile.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeTileTreeStream));
    BOOST_CHECK(tile.semantic_relation_complete);

    const size_t gemm_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeGemmSumcheck);
    const auto& gemm = sources[gemm_idx];
    BOOST_CHECK(gemm.role == rc::RCStage3RelationRole::EpisodeGemm);
    BOOST_CHECK_EQUAL(gemm.program.current_width, 3U);
    BOOST_CHECK_EQUAL(gemm.program.programs.size(), 1U);
    BOOST_REQUIRE_EQUAL(gemm.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        gemm.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeGemmSumcheck));
    BOOST_CHECK(gemm.semantic_relation_complete);

    const size_t wiring_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeWiring);
    const auto& wiring = sources[wiring_idx];
    BOOST_CHECK(wiring.role == rc::RCStage3RelationRole::EpisodeWiring);
    BOOST_CHECK_EQUAL(wiring.program.current_width, 2U);
    BOOST_CHECK_EQUAL(wiring.program.programs.size(), 1U);
    BOOST_REQUIRE_EQUAL(wiring.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        wiring.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeWiringCopy));
    BOOST_CHECK(wiring.semantic_relation_complete);

    const size_t extract_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeExtractCore);
    const auto& extract = sources[extract_idx];
    BOOST_CHECK(extract.role == rc::RCStage3RelationRole::EpisodeExtract);
    BOOST_CHECK_EQUAL(extract.program.current_width, aq::kRcSamplerNumCols);
    BOOST_CHECK_EQUAL(extract.program.challenge_width, 2U);
    BOOST_CHECK_EQUAL(extract.program.programs.size(), 47U);
    BOOST_REQUIRE_EQUAL(extract.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        extract.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeExtractSampler));
    BOOST_CHECK(extract.semantic_relation_complete);

    const size_t coupled_bank_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledBank);
    const auto& coupled_bank = sources[coupled_bank_idx];
    BOOST_CHECK(coupled_bank.role == rc::RCStage3RelationRole::CoupledBank);
    BOOST_CHECK_EQUAL(coupled_bank.program.current_width, 6U);
    BOOST_CHECK_EQUAL(coupled_bank.program.programs.size(), 5U);
    BOOST_REQUIRE_EQUAL(coupled_bank.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        coupled_bank.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBankPages));
    BOOST_CHECK(coupled_bank.semantic_relation_complete);

    const size_t coupled_gemm_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledGemm);
    const auto& coupled_gemm = sources[coupled_gemm_idx];
    BOOST_CHECK(coupled_gemm.role == rc::RCStage3RelationRole::CoupledGemm);
    BOOST_CHECK_EQUAL(coupled_gemm.program.current_width, 5U);
    BOOST_CHECK_EQUAL(coupled_gemm.program.programs.size(), 6U);
    BOOST_REQUIRE_EQUAL(coupled_gemm.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        coupled_gemm.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledGemmOutputY));
    BOOST_CHECK(coupled_gemm.semantic_relation_complete);

    const size_t coupled_extract_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledExtractCore);
    const auto& coupled_extract = sources[coupled_extract_idx];
    BOOST_CHECK(
        coupled_extract.role == rc::RCStage3RelationRole::CoupledExtract);
    BOOST_CHECK_EQUAL(
        coupled_extract.program.current_width, aq::kRcSamplerNumCols);
    BOOST_CHECK_EQUAL(coupled_extract.program.challenge_width, 2U);
    BOOST_CHECK_EQUAL(coupled_extract.program.programs.size(), 47U);
    BOOST_REQUIRE_EQUAL(coupled_extract.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        coupled_extract.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledExtractSampler));
    BOOST_CHECK(coupled_extract.semantic_relation_complete);

    const size_t coupled_barrier_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledBarrierSha256d);
    const auto& coupled_barrier = sources[coupled_barrier_idx];
    BOOST_CHECK(
        coupled_barrier.role == rc::RCStage3RelationRole::CoupledBarrier);
    BOOST_CHECK_EQUAL(coupled_barrier.program.current_width, 145U);
    BOOST_CHECK_EQUAL(coupled_barrier.program.programs.size(), 463U);
    BOOST_REQUIRE_EQUAL(coupled_barrier.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        coupled_barrier.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBarrierHash));
    BOOST_CHECK(coupled_barrier.semantic_relation_complete);

    const size_t coupled_digest_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledDigestSha256d);
    const auto& coupled_digest = sources[coupled_digest_idx];
    BOOST_CHECK(
        coupled_digest.role == rc::RCStage3RelationRole::CoupledDigest);
    BOOST_CHECK_EQUAL(coupled_digest.program.current_width, 145U);
    BOOST_CHECK_EQUAL(coupled_digest.program.programs.size(), 463U);
    BOOST_REQUIRE_EQUAL(coupled_digest.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        coupled_digest.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledDigestHash));
    BOOST_CHECK(coupled_digest.semantic_relation_complete);

    const size_t exchange_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledExchange);
    const auto& exchange = sources[exchange_idx];
    BOOST_CHECK(
        exchange.role ==
        rc::RCStage3RelationRole::CoupledExchange);
    BOOST_CHECK_EQUAL(exchange.program.current_width, 214U);
    BOOST_CHECK_EQUAL(exchange.program.challenge_width, 12U);
    BOOST_CHECK_EQUAL(exchange.program.programs.size(), 6U);
    BOOST_REQUIRE_EQUAL(exchange.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        exchange.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledExchangeOutput));
    BOOST_CHECK(exchange.semantic_relation_complete);
    cb::ProgramTable canonical_exchange;
    BOOST_REQUIRE(
        rc::BuildRCStage3CoupledExchangeTransportProgramTable(
            canonical_exchange));
    BOOST_CHECK(
        cb::CommitProgramTable(exchange.program) ==
        cb::CommitProgramTable(canonical_exchange));

    const size_t permutation_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledPermutation);
    const auto& permutation = sources[permutation_idx];
    BOOST_CHECK(
        permutation.role ==
        rc::RCStage3RelationRole::CoupledPermutation);
    BOOST_CHECK_EQUAL(permutation.program.current_width, 14U);
    BOOST_CHECK_EQUAL(permutation.program.challenge_width, 12U);
    BOOST_CHECK_EQUAL(permutation.program.programs.size(), 6U);
    BOOST_REQUIRE_EQUAL(permutation.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        permutation.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledPermutationOutput));
    BOOST_CHECK(permutation.semantic_relation_complete);
    cb::ProgramTable canonical_permutation;
    BOOST_REQUIRE(
        rc::BuildRCStage3CoupledPermutationTransportProgramTable(
            canonical_permutation));
    BOOST_CHECK(
        cb::CommitProgramTable(permutation.program) ==
        cb::CommitProgramTable(canonical_permutation));

    const size_t mix_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledMix);
    const auto& mix = sources[mix_idx];
    BOOST_CHECK(
        mix.role == rc::RCStage3RelationRole::CoupledMix);
    BOOST_CHECK_EQUAL(mix.program.current_width, 280U);
    BOOST_CHECK_EQUAL(mix.program.challenge_width, 0U);
    BOOST_CHECK_EQUAL(mix.program.programs.size(), 288U);
    BOOST_REQUIRE_EQUAL(mix.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        mix.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledMixArithmetic));
    BOOST_CHECK(mix.semantic_relation_complete);
    cb::ProgramTable canonical_mix;
    BOOST_REQUIRE(
        rc::BuildRCStage3CoupledLocalKernelProgramTable(
            rc::RCStage3RelationRole::CoupledMix,
            canonical_mix));
    BOOST_CHECK(
        cb::CommitProgramTable(mix.program) ==
        cb::CommitProgramTable(canonical_mix));

    // A site whose whole provenance relation is not closed now carries a real
    // canonical local kernel, but remains honestly INCOMPLETE: no endpoint
    // claim and no completeness bit.
    const size_t untouched_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeGemmOpenings);
    const auto& untouched = sources[untouched_idx];
    BOOST_CHECK_EQUAL(untouched.program.current_width, 7U);
    BOOST_CHECK_EQUAL(untouched.program.programs.size(), 3U);
    BOOST_CHECK(untouched.semantic_endpoints.empty());
    BOOST_CHECK(!untouched.semantic_relation_complete);

    const auto status =
        ut::AssessProductionFamilyProgramMigrationV1(sources);
    BOOST_CHECK_EQUAL(
        status.families_total,
        static_cast<uint32_t>(manifest.entries.size()));
    BOOST_CHECK_EQUAL(status.families_non_stub, 28U);
    BOOST_CHECK_EQUAL(status.families_partial, 14U);
    BOOST_CHECK_EQUAL(status.families_structural_stubs, 0U);
    BOOST_CHECK_EQUAL(status.families_real, 14U);
    BOOST_REQUIRE_EQUAL(status.partial_residuals.size(), 14U);
    for (const auto& residual : status.partial_residuals) {
        BOOST_CHECK_NE(residual.missing_obligations, 0U);
        BOOST_CHECK(
            (residual.missing_obligations &
             ut::ProductionResidualRecursiveConsumption) != 0);
        BOOST_CHECK(
            (residual.missing_obligations &
             ut::ProductionResidualExactAllInstanceAggregation) != 0);
    }
    const auto signed_residual = std::find_if(
        status.partial_residuals.begin(),
        status.partial_residuals.end(),
        [](const ut::ProductionPartialFamilyResidualV1& residual) {
            return residual.kind ==
                ss::ProductionProofSiteKind::EpisodeSignedRange;
        });
    BOOST_REQUIRE(signed_residual != status.partial_residuals.end());
    BOOST_CHECK_EQUAL(
        signed_residual->missing_obligations,
        ut::ProductionResidualPublicParameterOwnership |
        ut::ProductionResidualSourceRootProvenance |
        ut::ProductionResidualExactAllInstanceAggregation |
        ut::ProductionResidualRecursiveConsumption);
    const auto ctl_residual = std::find_if(
        status.partial_residuals.begin(),
        status.partial_residuals.end(),
        [](const ut::ProductionPartialFamilyResidualV1& residual) {
            return residual.kind ==
                ss::ProductionProofSiteKind::EpisodeRangeExtractCtl;
        });
    BOOST_REQUIRE(ctl_residual != status.partial_residuals.end());
    BOOST_CHECK(
        (ctl_residual->missing_obligations &
         ut::ProductionResidualImmutableScheduleBinding) != 0);
    BOOST_CHECK_EQUAL(status.roles_with_real_program, 14U);
    BOOST_CHECK_EQUAL(status.roles_total, 14U);
    const std::vector<rc::RCStage3RelationRole> expected_roles{
        rc::RCStage3RelationRole::EpisodeDeterministicBuilder,
        rc::RCStage3RelationRole::EpisodeGemm,
        rc::RCStage3RelationRole::EpisodeExtract,
        rc::RCStage3RelationRole::EpisodeWiring,
        rc::RCStage3RelationRole::EpisodeTileTree,
        rc::RCStage3RelationRole::EpisodeDigest,
        rc::RCStage3RelationRole::CoupledBank,
        rc::RCStage3RelationRole::CoupledGemm,
        rc::RCStage3RelationRole::CoupledExchange,
        rc::RCStage3RelationRole::CoupledPermutation,
        rc::RCStage3RelationRole::CoupledMix,
        rc::RCStage3RelationRole::CoupledExtract,
        rc::RCStage3RelationRole::CoupledBarrier,
        rc::RCStage3RelationRole::CoupledDigest};
    auto sorted_roles = expected_roles;
    std::sort(sorted_roles.begin(), sorted_roles.end());
    BOOST_CHECK(status.real_roles == sorted_roles);
    const std::vector<uint16_t> expected_endpoints{
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderTrace),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeGemmSumcheck),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeExtractSampler),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeWiringCopy),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeTileTreeStream),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeDigestPow),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBankPages),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledGemmOutputY),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledExchangeOutput),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledPermutationOutput),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledMixArithmetic),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledExtractSampler),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBarrierHash),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledDigestHash)};
    auto sorted_expected = expected_endpoints;
    std::sort(sorted_expected.begin(), sorted_expected.end());
    BOOST_CHECK(status.real_endpoints == sorted_expected);
    std::string why;
    BOOST_CHECK_MESSAGE(
        ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, sources, &why),
        why);

    // The generic registry validator is structural; this production-source
    // validator is the fail-closed seam that prevents a valid but vacuous
    // one-column table from replacing a canonical relation program.
    auto stub_substitution = sources;
    stub_substitution[exchange_idx].program =
        OneColumnProgram(
            rc::RCStage3RelationRole::CoupledExchange);
    BOOST_CHECK(
        !ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, stub_substitution, &why));

    // A different role's valid canonical table cannot be replayed at this
    // site, even if the attacker substitutes both the role tag and program.
    auto role_program_substitution = sources;
    role_program_substitution[exchange_idx].role =
        role_program_substitution[permutation_idx].role;
    role_program_substitution[exchange_idx].program =
        role_program_substitution[permutation_idx].program;
    BOOST_CHECK(
        !ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, role_program_substitution, &why));
}

BOOST_AUTO_TEST_CASE(
    production_registry_accepts_real_families_and_stays_honestly_incomplete)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        sch::BuildProductionAggregationSchedule(manifest);
    const auto sources = ut::BuildProductionFamilyProgramSourcesV1(manifest);
    const auto verifier =
        OneColumnProgram(rc::RCStage3RelationRole::CompositionLink);

    const auto registry = ut::BuildProductionProgramRegistryV1(
        manifest, schedule, sources, verifier, verifier);
    BOOST_REQUIRE(!registry.external_registry_commitment.IsNull());
    // Honest: only 14 of 28 families are real, so the registry-wide
    // completeness flag must stay false. A registry that flips this true
    // from stub-only or partially-real families would be exactly the
    // structural-only theatre this module exists to avoid.
    BOOST_CHECK(!registry.every_semantic_relation_complete);
    BOOST_CHECK(ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, registry,
        registry.external_registry_commitment,
        registry.recursive_registry_commitment));

    const size_t builder_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeBuilderCounterXof);
    const auto& builder_entry = registry.families[builder_idx];
    BOOST_CHECK_EQUAL(builder_entry.maximum_columns, 6U);
    BOOST_CHECK_EQUAL(builder_entry.constraint_count, 5U);
    BOOST_CHECK_GE(builder_entry.maximum_constraint_degree, 2U);
    BOOST_CHECK(builder_entry.semantic_relation_complete);

    const size_t gemm_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeGemmSumcheck);
    const auto& gemm_entry = registry.families[gemm_idx];
    BOOST_CHECK_EQUAL(gemm_entry.maximum_columns, 3U);
    BOOST_CHECK_EQUAL(gemm_entry.constraint_count, 1U);
    BOOST_CHECK(gemm_entry.semantic_relation_complete);

    const size_t wiring_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeWiring);
    const auto& wiring_entry = registry.families[wiring_idx];
    BOOST_CHECK_EQUAL(wiring_entry.maximum_columns, 2U);
    BOOST_CHECK_EQUAL(wiring_entry.constraint_count, 1U);
    BOOST_CHECK(wiring_entry.semantic_relation_complete);

    const size_t extract_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeExtractCore);
    const auto& extract_entry = registry.families[extract_idx];
    BOOST_CHECK_EQUAL(extract_entry.maximum_columns, aq::kRcSamplerNumCols);
    BOOST_CHECK_EQUAL(extract_entry.constraint_count, 47U);
    BOOST_CHECK(extract_entry.semantic_relation_complete);

    const size_t coupled_bank_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledBank);
    const auto& coupled_bank_entry = registry.families[coupled_bank_idx];
    BOOST_CHECK_EQUAL(coupled_bank_entry.maximum_columns, 6U);
    BOOST_CHECK_EQUAL(coupled_bank_entry.constraint_count, 5U);
    BOOST_CHECK(coupled_bank_entry.semantic_relation_complete);

    const size_t coupled_gemm_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledGemm);
    const auto& coupled_gemm_entry = registry.families[coupled_gemm_idx];
    BOOST_CHECK_EQUAL(coupled_gemm_entry.maximum_columns, 5U);
    BOOST_CHECK_EQUAL(coupled_gemm_entry.constraint_count, 6U);
    BOOST_CHECK(coupled_gemm_entry.semantic_relation_complete);

    const size_t coupled_extract_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledExtractCore);
    const auto& coupled_extract_entry =
        registry.families[coupled_extract_idx];
    BOOST_CHECK_EQUAL(
        coupled_extract_entry.maximum_columns, aq::kRcSamplerNumCols);
    BOOST_CHECK_EQUAL(coupled_extract_entry.constraint_count, 47U);
    BOOST_CHECK(coupled_extract_entry.semantic_relation_complete);

    const size_t coupled_barrier_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledBarrierSha256d);
    const auto& coupled_barrier_entry =
        registry.families[coupled_barrier_idx];
    BOOST_CHECK_EQUAL(coupled_barrier_entry.maximum_columns, 145U);
    BOOST_CHECK_EQUAL(coupled_barrier_entry.constraint_count, 463U);
    BOOST_CHECK(coupled_barrier_entry.semantic_relation_complete);

    const size_t coupled_digest_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledDigestSha256d);
    const auto& coupled_digest_entry =
        registry.families[coupled_digest_idx];
    BOOST_CHECK_EQUAL(coupled_digest_entry.maximum_columns, 145U);
    BOOST_CHECK_EQUAL(coupled_digest_entry.constraint_count, 463U);
    BOOST_CHECK(coupled_digest_entry.semantic_relation_complete);

    const size_t exchange_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledExchange);
    const auto& exchange_entry = registry.families[exchange_idx];
    BOOST_CHECK_EQUAL(exchange_entry.maximum_columns, 214U);
    BOOST_CHECK_EQUAL(exchange_entry.constraint_count, 6U);
    BOOST_CHECK(exchange_entry.semantic_relation_complete);

    const size_t permutation_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledPermutation);
    const auto& permutation_entry =
        registry.families[permutation_idx];
    BOOST_CHECK_EQUAL(permutation_entry.maximum_columns, 14U);
    BOOST_CHECK_EQUAL(permutation_entry.constraint_count, 6U);
    BOOST_CHECK(permutation_entry.semantic_relation_complete);

    const size_t mix_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::CoupledMix);
    const auto& mix_entry = registry.families[mix_idx];
    BOOST_CHECK_EQUAL(mix_entry.maximum_columns, 280U);
    BOOST_CHECK_EQUAL(mix_entry.constraint_count, 288U);
    BOOST_CHECK(mix_entry.semantic_relation_complete);

    const size_t partial_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeGemmOpenings);
    const auto& partial_entry = registry.families[partial_idx];
    BOOST_CHECK_EQUAL(partial_entry.maximum_columns, 7U);
    BOOST_CHECK_EQUAL(partial_entry.constraint_count, 3U);
    BOOST_CHECK_EQUAL(partial_entry.maximum_constraint_degree, 2U);
    BOOST_CHECK(!partial_entry.semantic_relation_complete);

    // Non-vacuity of the wiring itself: tampering a real program's bytes
    // (not merely a stub) must change BOTH root commitments the registry is
    // pinned by, proving the ProgramTable content actually flows into
    // consensus-facing commitments rather than being decorative. Checked for
    // every real family this session wired, not just the first one.
    for (size_t real_idx = 0; real_idx < sources.size(); ++real_idx) {
        BOOST_REQUIRE_GT(
            sources[real_idx].program.current_width, 1U);
        auto tampered_sources = sources;
        auto& load = *std::find_if(
            tampered_sources[real_idx]
                .program.programs.back()
                .instructions.begin(),
            tampered_sources[real_idx]
                .program.programs.back()
                .instructions.end(),
            [](const cb::Instruction& instr) {
                return instr.opcode == cb::Opcode::Current;
            });
        load.lhs = (load.lhs + 1) %
            tampered_sources[real_idx].program.current_width;
        const auto tampered_registry = ut::BuildProductionProgramRegistryV1(
            manifest, schedule, tampered_sources, verifier, verifier);
        BOOST_REQUIRE(
            !tampered_registry.external_registry_commitment.IsNull());
        BOOST_CHECK(
            tampered_registry.external_registry_commitment !=
            registry.external_registry_commitment);
        BOOST_CHECK(
            tampered_registry.recursive_registry_commitment !=
            registry.recursive_registry_commitment);
        BOOST_CHECK(!ut::ValidateProductionProgramRegistryV1(
            manifest, schedule, tampered_registry,
            registry.external_registry_commitment,
            registry.recursive_registry_commitment));
    }
}

BOOST_AUTO_TEST_CASE(
    partial_family_programs_match_native_airs_and_reject_substitution)
{
    namespace ha = rc::stage3_hash_air;
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    std::string why;

    // Every SHA/XOF/ChaCha site executes the same selector-pinned fixed-opcode
    // AIR.  SHA and ChaCha have different immutable selector schedules, but
    // the 462 local polynomial constraints must match at every field point.
    // Production appends one role-local selector-muxed OUTPUT relation so an
    // endpoint can name one result column across all eleven opcode layouts.
    rc::air_quotient::AirConstraintSystem<Fp3> native_sha;
    rc::air_quotient::AirConstraintSystem<Fp3> native_chacha;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(
            ha::BuildCanonicalProgram(
                ha::ProgramKind::Sha256Compression),
            native_sha, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(
            ha::BuildCanonicalProgram(
                ha::ProgramKind::ChaCha20Block),
            native_chacha, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        native_sha.constraints.size(),
        native_chacha.constraints.size());

    const std::vector<ss::ProductionProofSiteKind> fixed_sites{
        ss::ProductionProofSiteKind::EpisodeScaleSha,
        ss::ProductionProofSiteKind::EpisodeExtractChaCha,
        ss::ProductionProofSiteKind::CoupledBankCounterXof,
        ss::ProductionProofSiteKind::CoupledBankCommitmentSha256d,
        ss::ProductionProofSiteKind::CoupledLobeInitCounterXof,
        ss::ProductionProofSiteKind::CoupledPageScheduleXof,
        ss::ProductionProofSiteKind::CoupledExchangeXof,
        ss::ProductionProofSiteKind::CoupledPermutationXof,
        ss::ProductionProofSiteKind::CoupledMixXof,
        ss::ProductionProofSiteKind::CoupledExtractScaleSha,
        ss::ProductionProofSiteKind::CoupledExtractChaCha};
    uint64_t rng = 0x243f6a8885a308d3ULL;
    const auto next_field = [&rng]() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return U(rng);
    };
    const auto opcode_output =
        [](const std::vector<Fp3>& row) {
            Fp3 selected = Fp3::Zero();
            for (uint32_t opcode = 0; opcode <= 4; ++opcode) {
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        row[ha::kFixedProgramSelectorBase + opcode],
                        row[ha::ValueColumn(2)]));
            }
            for (uint32_t opcode = 5; opcode <= 6; ++opcode) {
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        row[ha::kFixedProgramSelectorBase + opcode],
                        row[ha::ValueColumn(3)]));
            }
            for (uint32_t opcode = 7; opcode <= 10; ++opcode) {
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        row[ha::kFixedProgramSelectorBase + opcode],
                        row[ha::ValueColumn(1)]));
            }
            return selected;
        };
    for (const auto kind : fixed_sites) {
        const auto& table =
            sources[FindFamilyIndex(manifest, kind)].program;
        BOOST_CHECK_EQUAL(
            table.current_width,
            rc::kRCStage3HashKernelOutputColumnV1 + 1U);
        BOOST_REQUIRE_EQUAL(
            table.programs.size(),
            native_sha.constraints.size() + 1U);
        for (uint32_t trial = 0; trial < 4; ++trial) {
            std::vector<Fp3> current(table.current_width);
            std::vector<Fp3> next(table.next_width);
            for (auto& value : current) value = next_field();
            for (auto& value : next) value = next_field();
            current[rc::kRCStage3HashKernelOutputColumnV1] =
                opcode_output(current);
            for (uint32_t i = 0;
                 i < native_sha.constraints.size(); ++i) {
                Fp3 interpreted;
                BOOST_REQUIRE(cb::EvaluateProgram(
                    table.programs[i], current, next, interpreted));
                BOOST_CHECK(gf::Eq(
                    interpreted,
                    native_sha.constraints[i].eval(current, next)));
                BOOST_CHECK(gf::Eq(
                    interpreted,
                    native_chacha.constraints[i].eval(current, next)));
            }
            Fp3 output_residual;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs.back(), current, next,
                output_residual));
            BOOST_CHECK(gf::IsZero(output_residual));
            current[rc::kRCStage3HashKernelOutputColumnV1] =
                gf::Add(
                    current[
                        rc::kRCStage3HashKernelOutputColumnV1],
                    Fp3::One());
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs.back(), current, next,
                output_residual));
            BOOST_CHECK(!gf::IsZero(output_residual));
        }
    }
    for (const auto [program_kind, site_kind] : {
             std::pair{
                 ha::ProgramKind::Sha256Compression,
                 ss::ProductionProofSiteKind::EpisodeScaleSha},
             std::pair{
                 ha::ProgramKind::ChaCha20Block,
                 ss::ProductionProofSiteKind::EpisodeExtractChaCha}}) {
        const auto program =
            ha::BuildCanonicalProgram(program_kind);
        std::vector<uint32_t> external(
            program.external_address_count);
        for (uint32_t i = 0; i < external.size(); ++i) {
            external[i] = 0x9e3779b9U * (i + 1U);
        }
        ha::ProgramWitness witness;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildProgramWitness(
                program, external, witness, &why),
            why);
        std::vector<std::vector<Fp3>> columns;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildFixedProgramAirWitness(
                program, witness, columns, &why),
            why);
        const uint32_t rows =
            static_cast<uint32_t>(columns.front().size());
        columns.emplace_back(rows, Fp3::Zero());
        for (uint32_t row = 0; row < rows; ++row) {
            std::vector<Fp3> current(
                rc::kRCStage3HashKernelOutputColumnV1,
                Fp3::Zero());
            for (uint32_t col = 0; col < current.size(); ++col) {
                current[col] = columns[col][row];
            }
            columns.back()[row] = opcode_output(current);
        }
        const auto& table =
            sources[FindFamilyIndex(
                manifest, site_kind)].program;
        BOOST_REQUIRE_EQUAL(
            columns.size(), table.current_width);
        for (uint32_t row = 0; row < rows; ++row) {
            std::vector<Fp3> current(table.current_width);
            std::vector<Fp3> next(table.next_width);
            for (uint32_t col = 0; col < table.current_width; ++col) {
                current[col] = columns[col][row];
                next[col] = columns[col][(row + 1) % rows];
            }
            for (const auto& bytecode : table.programs) {
                if (!ConstraintApplies(bytecode.kind, row, rows)) {
                    continue;
                }
                Fp3 value;
                BOOST_REQUIRE(cb::EvaluateProgram(
                    bytecode, current, next, value));
                BOOST_CHECK(gf::IsZero(value));
            }
        }
    }

    // GEMM A/B/Y opening shards use the production semantic-memory AIR. The
    // family table is role-bound and byte-for-byte equal to the table
    // reconstructed by that native builder.
    const auto& openings = sources[FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::EpisodeGemmOpenings)].program;
    const std::vector<Fp3> opening_values{U(3), U(5), U(8), U(13)};
    const auto opening_root =
        rc::ComputeRCStage3EpisodeSemanticValueRoot(
            opening_values, /*logical_rows=*/4, /*n_rows=*/4, &why);
    BOOST_REQUIRE_MESSAGE(opening_root.has_value(), why);
    const auto opening_manifest =
        rc::BuildRCStage3EpisodeSemanticMemoryManifest(
            rc::RCStage3RelationEndpoint::EpisodeGemmOperandA,
            uint256::ONE, /*instance_count=*/4, /*logical_rows=*/4,
            /*address_begin=*/0, /*address_stride=*/1,
            *opening_root, &why);
    BOOST_REQUIRE_MESSAGE(opening_manifest.has_value(), why);
    rc::air_quotient::AirConstraintSystem<Fp3> native_openings;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
            *opening_manifest, native_openings, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        openings.programs.size(),
        native_openings.constraints.size());
    for (uint32_t trial = 0; trial < 16; ++trial) {
        std::vector<Fp3> current(openings.current_width);
        std::vector<Fp3> next(openings.next_width);
        for (auto& value : current) value = next_field();
        for (auto& value : next) value = next_field();
        for (uint32_t i = 0; i < openings.programs.size(); ++i) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                openings.programs[i], current, next, interpreted));
            BOOST_CHECK(gf::Eq(
                interpreted,
                native_openings.constraints[i].eval(current, next)));
        }
    }

    // The signed-range table parameterizes the live 69-column AIR with
    // root-pinnable MAX_ABS and LOGICAL_ROWS trace columns. Differentially
    // compare every native constraint against a fully populated pin.
    const auto& range = sources[FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::EpisodeSignedRange)].program;
    constexpr uint32_t RANGE_MAX_ABS =
        rc::kRCStage3SignedRangeColumns;
    constexpr uint32_t RANGE_MAX_BITS =
        RANGE_MAX_ABS + 1;
    constexpr uint32_t RANGE_LOGICAL_ROWS =
        RANGE_MAX_BITS + rc::kRCStage3SignedRangeBits;
    BOOST_CHECK_EQUAL(
        range.current_width, RANGE_LOGICAL_ROWS + 1U);
    BOOST_REQUIRE_EQUAL(range.programs.size(), 177U);
    rc::RCStage3SignedRangePin pin;
    pin.statement_commitment = uint256::ONE;
    pin.manifest_commitment = uint256::ONE;
    pin.shard_count = 1;
    pin.logical_rows = 4;
    pin.n_rows = 8;
    pin.max_abs = 127;
    pin.column_roots.resize(rc::kRCStage3SignedRangeColumns);
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        pin.column_roots[i].column = i;
        pin.column_roots[i].root = uint256::ONE;
    }
    rc::air_quotient::AirConstraintSystem<Fp3> native_range;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3SignedRangeKernelConstraintSystem(
            pin, native_range, &why),
        why);
    BOOST_REQUIRE_EQUAL(native_range.constraints.size(), 143U);
    for (uint32_t trial = 0; trial < 16; ++trial) {
        std::vector<Fp3> current(range.current_width);
        std::vector<Fp3> next(range.next_width);
        for (auto& value : current) value = next_field();
        for (auto& value : next) value = next_field();
        current[RANGE_MAX_ABS] = U(pin.max_abs);
        next[RANGE_MAX_ABS] = U(pin.max_abs);
        current[RANGE_LOGICAL_ROWS] = U(pin.logical_rows);
        next[RANGE_LOGICAL_ROWS] = U(pin.logical_rows);
        for (uint32_t bit = 0;
             bit < rc::kRCStage3SignedRangeBits;
             ++bit) {
            current[RANGE_MAX_BITS + bit] =
                U((pin.max_abs >> bit) & 1U);
            next[RANGE_MAX_BITS + bit] =
                current[RANGE_MAX_BITS + bit];
        }
        for (uint32_t i = 0;
             i < native_range.constraints.size();
             ++i) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                range.programs[i], current, next, interpreted));
            BOOST_CHECK_MESSAGE(
                gf::Eq(
                    interpreted,
                    native_range.constraints[i].eval(
                        current, next)),
                "range differential trial=" << trial
                << " constraint=" << i);
        }
        for (uint32_t i =
                 static_cast<uint32_t>(
                     native_range.constraints.size());
             i < range.programs.size(); ++i) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                range.programs[i], current, next, interpreted));
            BOOST_CHECK(gf::IsZero(interpreted));
        }
    }

    // Honest full native witness satisfies all 177 programs, including
    // parameter canonicity. Parameter forgeries cannot float independently.
    std::vector<std::vector<Fp3>> range_columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            pin, {-7, 0, 31, -127}, range_columns, &why),
        why);
    range_columns.resize(
        range.current_width,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    for (uint32_t row = 0; row < pin.n_rows; ++row) {
        range_columns[RANGE_MAX_ABS][row] = U(pin.max_abs);
        range_columns[RANGE_LOGICAL_ROWS][row] =
            U(pin.logical_rows);
        for (uint32_t bit = 0;
             bit < rc::kRCStage3SignedRangeBits;
             ++bit) {
            range_columns[RANGE_MAX_BITS + bit][row] =
                U((pin.max_abs >> bit) & 1U);
        }
    }
    auto range_violations =
        [&range, &range_columns]() {
            uint32_t violations = 0;
            const uint32_t rows =
                static_cast<uint32_t>(
                    range_columns.front().size());
            for (uint32_t row = 0; row < rows; ++row) {
                std::vector<Fp3> current(range.current_width);
                std::vector<Fp3> next(range.next_width);
                for (uint32_t col = 0;
                     col < range.current_width;
                     ++col) {
                    current[col] = range_columns[col][row];
                    next[col] =
                        range_columns[col][(row + 1) % rows];
                }
                for (const auto& program : range.programs) {
                    if (!ConstraintApplies(
                            program.kind, row, rows)) {
                        continue;
                    }
                    Fp3 value;
                    const bool evaluated =
                        cb::EvaluateProgram(
                            program, current, next, value);
                    BOOST_CHECK(evaluated);
                    violations +=
                        !evaluated || !gf::IsZero(value);
                }
            }
            return violations;
        };
    BOOST_CHECK_EQUAL(range_violations(), 0U);
    range_columns[RANGE_MAX_ABS][3] = U(pin.max_abs + 1);
    BOOST_CHECK_GT(range_violations(), 0U);
    range_columns[RANGE_MAX_ABS][3] = U(pin.max_abs);
    range_columns[RANGE_MAX_BITS][3] =
        gf::Sub(Fp3::One(), range_columns[RANGE_MAX_BITS][3]);
    BOOST_CHECK_GT(range_violations(), 0U);
    range_columns[RANGE_MAX_BITS][3] =
        U(pin.max_abs & 1U);
    range_columns[RANGE_LOGICAL_ROWS][0] =
        U(pin.logical_rows + 1);
    BOOST_CHECK_GT(range_violations(), 0U);
    range_columns[RANGE_LOGICAL_ROWS][0] =
        U(pin.logical_rows);

    // Range->Extract uses the live additive LogUp transport bytecode. Its
    // tile parameter is now a canonical u32; exact-set manifest aggregation
    // and root ownership remain outside the fragment.
    const auto& range_ctl = sources[FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::EpisodeRangeExtractCtl)].program;
    rc::RCStage3CtlChallenges challenges;
    challenges.gamma1 = U(0x12345);
    challenges.alpha1 = U(0x23456);
    challenges.gamma2 = U(0x34567);
    challenges.alpha2 = U(0x45678);
    rc::RCStage3CtlTerminal terminal;
    terminal.alpha1_sum = U(0x56789);
    terminal.alpha2_sum = U(0x6789a);
    const std::vector<Fp3> challenge{
        challenges.gamma1, challenges.alpha1,
        challenges.gamma2, challenges.alpha2,
        terminal.alpha1_sum, terminal.alpha2_sum};
    constexpr uint32_t CTL_TILE = 7;
    constexpr uint32_t CTL_MULTIPLICITY = 8;
    constexpr uint32_t CTL_TILE_BITS = 9;
    BOOST_CHECK_EQUAL(range_ctl.current_width, 41U);
    BOOST_REQUIRE_EQUAL(range_ctl.programs.size(), 48U);
    for (uint32_t trial = 0; trial < 16; ++trial) {
        const uint32_t tile =
            0x10203U + trial * 17U;
        const int8_t multiplicity =
            (trial & 1U) == 0 ? 1 : -1;
        const auto native_ctl =
            rc::BuildRCStage3ExtractStreamSelectedCtlConstraintSystem(
                /*base_columns=*/1, /*n_rows=*/64,
                /*source_column=*/0, tile, multiplicity,
                challenges, terminal);
        BOOST_REQUIRE_EQUAL(
            native_ctl.constraints.size(), 12U);
        std::vector<Fp3> current(range_ctl.current_width);
        std::vector<Fp3> next(range_ctl.next_width);
        for (auto& value : current) value = next_field();
        for (auto& value : next) value = next_field();
        current[CTL_TILE] = U(tile);
        next[CTL_TILE] = U(tile);
        current[CTL_MULTIPLICITY] =
            gf::FromSigned3(multiplicity);
        next[CTL_MULTIPLICITY] =
            current[CTL_MULTIPLICITY];
        for (uint32_t bit = 0; bit < 32; ++bit) {
            current[CTL_TILE_BITS + bit] =
                U((tile >> bit) & 1U);
            next[CTL_TILE_BITS + bit] =
                current[CTL_TILE_BITS + bit];
        }
        for (uint32_t i = 0;
             i < native_ctl.constraints.size();
             ++i) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                range_ctl.programs[i], current, next, challenge,
                interpreted));
            BOOST_CHECK_MESSAGE(
                gf::Eq(
                    interpreted,
                    native_ctl.constraints[i].eval(
                        current, next)),
                "ctl differential trial=" << trial
                << " constraint=" << i);
        }
        for (uint32_t i =
                 static_cast<uint32_t>(
                     native_ctl.constraints.size());
             i < range_ctl.programs.size(); ++i) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                range_ctl.programs[i], current, next, challenge,
                interpreted));
            BOOST_CHECK(gf::IsZero(interpreted));
        }
    }
    std::vector<Fp3> ctl_honest(
        range_ctl.current_width, Fp3::Zero());
    std::vector<Fp3> ctl_next = ctl_honest;
    ctl_honest[CTL_TILE] = U(7);
    ctl_next[CTL_TILE] = U(7);
    ctl_honest[CTL_MULTIPLICITY] = Fp3::One();
    ctl_next[CTL_MULTIPLICITY] = Fp3::One();
    for (uint32_t bit = 0; bit < 32; ++bit) {
        ctl_honest[CTL_TILE_BITS + bit] =
            U((7U >> bit) & 1U);
        ctl_next[CTL_TILE_BITS + bit] =
            ctl_honest[CTL_TILE_BITS + bit];
    }
    const std::vector<Fp3> zero_terminal_challenge{
        challenges.gamma1, challenges.alpha1,
        challenges.gamma2, challenges.alpha2,
        Fp3::Zero(), Fp3::Zero()};
    for (const auto& program : range_ctl.programs) {
        Fp3 value;
        BOOST_REQUIRE(cb::EvaluateProgram(
            program, ctl_honest, ctl_next,
            zero_terminal_challenge, value));
        BOOST_CHECK(gf::IsZero(value));
    }
    ctl_honest[CTL_TILE_BITS] =
        gf::Sub(Fp3::One(), ctl_honest[CTL_TILE_BITS]);
    bool ctl_attack_rejected = false;
    for (const auto& program : range_ctl.programs) {
        Fp3 value;
        BOOST_REQUIRE(cb::EvaluateProgram(
            program, ctl_honest, ctl_next,
            zero_terminal_challenge, value));
        ctl_attack_rejected |= !gf::IsZero(value);
    }
    BOOST_CHECK(ctl_attack_rejected);
    ctl_honest[CTL_TILE_BITS] = Fp3::One();
    ctl_honest[CTL_MULTIPLICITY] = Fp3::Zero();
    ctl_attack_rejected = false;
    for (const auto& program : range_ctl.programs) {
        Fp3 value;
        BOOST_REQUIRE(cb::EvaluateProgram(
            program, ctl_honest, ctl_next,
            zero_terminal_challenge, value));
        ctl_attack_rejected |= !gf::IsZero(value);
    }
    BOOST_CHECK(ctl_attack_rejected);

    // Site/role substitution is rejected even between identical fixed-opcode
    // kernels, because canonical family order, role and schema are all bound.
    auto substituted = sources;
    const size_t sha_idx = FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::EpisodeScaleSha);
    const size_t foreign_role_idx = FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::CoupledBankCounterXof);
    std::swap(
        substituted[sha_idx].program,
        substituted[foreign_role_idx].program);
    BOOST_CHECK(!ut::ValidateProductionFamilyProgramSourcesV1(
        manifest, substituted, &why));
    auto reordered_same_role = sources;
    const size_t chacha_idx = FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::EpisodeExtractChaCha);
    BOOST_CHECK(
        sources[sha_idx].public_input_schema !=
        sources[chacha_idx].public_input_schema);
    std::swap(
        reordered_same_role[sha_idx],
        reordered_same_role[chacha_idx]);
    BOOST_CHECK(!ut::ValidateProductionFamilyProgramSourcesV1(
        manifest, reordered_same_role, &why));
    auto one_column = sources;
    one_column[sha_idx].program =
        OneColumnProgram(one_column[sha_idx].role);
    BOOST_CHECK(!ut::ValidateProductionFamilyProgramSourcesV1(
        manifest, one_column, &why));
}

BOOST_AUTO_TEST_CASE(
    real_family_programs_have_satisfying_witnesses_and_reject_tampering)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources = ut::BuildProductionFamilyProgramSourcesV1(manifest);

    // --- EpisodeDeterministicBuilder: mantissa/scale dequant, 6 columns. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeBuilderCounterXof);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row{
            gf::FromSigned3(-7), U(2), U(0), U(1), U(4),
            gf::FromSigned3(-28)};
        const std::vector<Fp3> next(6, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[5] = gf::FromSigned3(-27); // wrong output
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeDigest: PoW borrow-chain, 12 columns, single-row slice
    // (first row: borrow=0; not the last row: borrow_out=0). Chosen so
    // target - digest - borrow + 256*borrow_out == the 8-bit difference:
    // 9 - 5 - 0 + 0 == 4 == 0b0000_0100.
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeDigestSha256d);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row(12, Fp3::Zero());
        row[0] = U(5);  // digest byte
        row[1] = U(9);  // target byte
        row[2] = U(0);  // borrow (first row)
        row[3] = U(0);  // borrow_out (not last row)
        row[4 + 2] = Fp3::One(); // difference = 4 -> bit 2 set
        const std::vector<Fp3> next(12, Fp3::Zero()); // next borrow == 0
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[1] = U(10); // wrong target: difference no longer matches
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeTileTree: signed-byte <-> octet bridge, 15 columns. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeTileTreeSha256d);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row(15, Fp3::Zero());
        row[0] = Fp3::One();
        row[1] = U(9);
        row[2] = Fp3::FromFp(gf::FromSigned(-91));
        row[3] = Fp3::FromFp(gf::FromSigned(-91));
        row[4] = Fp3::FromFp(gf::FromSigned(-91));
        row[5] = U(0xa5);
        row[6] = Fp3::One();
        for (uint32_t bit = 0; bit < 8; ++bit) {
            row[7 + bit] = U((0xa5U >> bit) & 1U);
        }
        const std::vector<Fp3> next(15, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[6] = Fp3::Zero(); // wrong sign bit
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeGemm: terminal sumcheck identity gf = a*b, 3 columns. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeGemmSumcheck);
        const auto& table = sources[idx].program;
        const std::vector<Fp3> row{U(12), U(3), U(4)}; // gf, a, b: 12 == 3*4
        const std::vector<Fp3> next(3, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[0] = U(13); // gf no longer equals a*b
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeWiring: direct row-copy equality u = v, 2 columns. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeWiring);
        const auto& table = sources[idx].program;
        const std::vector<Fp3> row{U(41), U(41)};
        const std::vector<Fp3> next(2, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[1] = U(42); // copy no longer matches its source
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeExtract: full RcSampler local kernel is differentially
    // tested bit-identical to air_quotient::BuildRcSamplerConstraintSystem
    // over genuine (non-zero) rows and the [gamma, alpha] challenge class
    // elsewhere (matmul_v4_rc_stage3_role_bytecode_tests.cpp); a hand-picked
    // 40-column/47-constraint all-zero witness is not a meaningfully
    // different check, so non-vacuity for this family is instead proved
    // above by the registry-commitment tamper test, which shows this exact
    // 47-program table (not a placeholder) drives the production registry's
    // consensus-facing commitments.

    // --- CoupledBank: same six-column dequant relation as
    // EpisodeBuilderTraceDequant above, committed under a different role. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::CoupledBank);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row{
            gf::FromSigned3(-7), U(2), U(0), U(1), U(4),
            gf::FromSigned3(-28)};
        const std::vector<Fp3> next(6, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[5] = gf::FromSigned3(-27); // wrong output
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- CoupledGemm: five-column running-accumulation identity. Columns
    // are [A, B, ACC, OUT, ACTIVE]. current: a=3, b=4, acc=a*b=12 (first-row
    // identity), out=12, active=1. next: acc advances to
    // current_acc + next_active*next_a*next_b = 12 + 1*3*4 = 24, out stays
    // 12 (transition), active=1 (so the active-gated A/B-zero constraints,
    // which only read CURRENT, are vacuously satisfied). ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::CoupledGemm);
        const auto& table = sources[idx].program;
        const std::vector<Fp3> row{U(3), U(4), U(12), U(12), Fp3::One()};
        const std::vector<Fp3> next{U(3), U(4), U(24), U(12), Fp3::One()};
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[2] = U(13); // acc no longer equals a*b
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- CoupledExtract and the two coupled hash kernels (CoupledBarrier /
    // CoupledDigest, 145 columns / 463 constraints including the canonical
    // opcode-output mux)
    // are, like EpisodeExtract above, differentially tested against their
    // canonical constraint-system builders elsewhere
    // (matmul_v4_rc_stage3_role_bytecode_tests.cpp); non-vacuity for all
    // three is proved above by the registry-commitment tamper test.
}

BOOST_AUTO_TEST_CASE(
    hash_family_output_mux_names_the_actual_opcode_result)
{
    namespace ha = rc::stage3_hash_air;
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    const size_t index = FindFamilyIndex(
        manifest,
        ss::ProductionProofSiteKind::CoupledBarrierSha256d);
    const auto& table = sources[index].program;
    BOOST_REQUIRE_EQUAL(
        table.current_width,
        rc::kRCStage3HashKernelOutputColumnV1 + 1U);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 463U);
    const auto& output_program = table.programs.back();

    for (uint32_t opcode = 0; opcode < 11; ++opcode) {
        std::vector<Fp3> current(
            table.current_width, Fp3::Zero());
        std::vector<Fp3> next(
            table.next_width, Fp3::Zero());
        current[
            ha::kFixedProgramSelectorBase + opcode] =
            Fp3::One();
        const uint32_t result_slot =
            opcode <= 4 ? 2U : (opcode <= 6 ? 3U : 1U);
        current[ha::ValueColumn(result_slot)] = U(0x1234U);
        current[rc::kRCStage3HashKernelOutputColumnV1] =
            U(0x1234U);
        Fp3 residual;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                output_program, current, next, residual));
        BOOST_CHECK(gf::IsZero(residual));

        current[rc::kRCStage3HashKernelOutputColumnV1] =
            U(0x1235U);
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                output_program, current, next, residual));
        BOOST_CHECK(!gf::IsZero(residual));
    }

    std::vector<Fp3> padding(
        table.current_width, Fp3::Zero());
    std::vector<Fp3> next(
        table.next_width, Fp3::Zero());
    Fp3 residual;
    BOOST_REQUIRE(
        cb::EvaluateProgram(
            output_program, padding, next, residual));
    BOOST_CHECK(gf::IsZero(residual));
    padding[rc::kRCStage3HashKernelOutputColumnV1] =
        Fp3::One();
    BOOST_REQUIRE(
        cb::EvaluateProgram(
            output_program, padding, next, residual));
    BOOST_CHECK(!gf::IsZero(residual));
}

BOOST_AUTO_TEST_SUITE_END()
