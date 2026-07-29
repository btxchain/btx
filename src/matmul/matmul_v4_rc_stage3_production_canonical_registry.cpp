// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_production_canonical_registry.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <set>
#include <utility>

namespace matmul::v4::rc::production_canonical_registry {
namespace {

namespace gf = gkr_field;

bool Fail(std::string* why, const char* suffix)
{
    if (why != nullptr) {
        *why =
            std::string{"stage3:production_canonical_registry:"} +
            suffix;
    }
    return false;
}

bool DigestZero(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return gf::Canonical(value) == 0;
        });
}

uint256 AcceptanceStatementRoot()
{
    HashWriter hash;
    hash << "BTX/RC/STAGE3/CANONICAL-REGISTRY/"
            "ACCEPTANCE-STATEMENT/V1";
    hash << kCanonicalRegistryBuilderVersionV1;
    return hash.GetHash();
}

av::AcceptanceInstanceV1 CanonicalAcceptanceInstance()
{
    std::array<gf::Fp3, av::kAcceptanceSemanticColumnsV1> first{};
    std::array<gf::Fp3, av::kAcceptanceSemanticColumnsV1> second{};
    const auto layout = av::rp::CanonicalLayoutV1();
    first[layout.active] = gf::Fp3::One();
    first[layout.ordinal] = gf::Fp3::Zero();
    first[layout.accepted] = gf::Fp3::One();
    second[layout.active] = gf::Fp3::One();
    second[layout.ordinal] = gf::Fp3::One();
    second[layout.accepted] = gf::Fp3::One();
    return av::BuildAcceptanceInstanceV1(
        first, second, AcceptanceStatementRoot());
}

bool ReconstructProgramRoot(
    const cb::ProgramTable& table,
    cb::ProgramTableCommitmentPair& root)
{
    std::vector<unsigned char> bytes;
    std::string why;
    if (!cb::SerializeProgramTable(table, bytes, &why) ||
        bytes.empty()) {
        return false;
    }
    cb::ProgramTable decoded;
    if (!cb::DeserializeProgramTable(bytes, decoded, &why) ||
        decoded != table) {
        return false;
    }
    const auto first =
        cb::CommitProgramTableForExternalAndRecursiveUse(table);
    const auto second =
        cb::CommitProgramTableForExternalAndRecursiveUse(decoded);
    if (first != second ||
        !first.same_canonical_serialization ||
        first.external_sha256d.IsNull() ||
        DigestZero(first.recursive_alg_hash)) {
        return false;
    }
    root = first;
    return true;
}

uint32_t ResidualForKind(
    sites::ProductionProofSiteKind kind,
    const ut::ProductionFamilyProgramMigrationStatusV1& migration)
{
    const auto it = std::find_if(
        migration.partial_residuals.begin(),
        migration.partial_residuals.end(),
        [kind](const ut::ProductionPartialFamilyResidualV1& residual) {
            return residual.kind == kind;
        });
    return it == migration.partial_residuals.end()
        ? 0
        : it->missing_obligations;
}

bool ExactSemanticEndpointUnion(
    const std::vector<ut::ProductionFamilyProgramSourceV1>& sources)
{
    std::set<uint16_t> endpoints;
    for (const auto& source : sources) {
        if (!source.semantic_relation_complete) return false;
        endpoints.insert(
            source.semantic_endpoints.begin(),
            source.semantic_endpoints.end());
    }
    if (endpoints.size() != 52) return false;
    uint16_t expected = 1;
    for (const uint16_t endpoint : endpoints) {
        if (endpoint != expected++) return false;
    }
    return true;
}

bool NormalizedProgramExactlyLowered(
    const cb::ProgramTable& table,
    const np::ManifestV1& manifest)
{
    return
        cb::ValidateProgramTable(table, nullptr) &&
        table.role == RCStage3RelationRole::CompositionLink &&
        manifest.canonical_program_table &&
        manifest.canonical_field_encodings &&
        manifest.opcode_and_operand_bounds &&
        manifest.exact_native_constraint_order &&
        manifest.no_opaque_callbacks &&
        manifest.unlowered_relations == 0 &&
        manifest.program_count == np::kExpectedProgramsV1 &&
        np::ProgramRootMatchesV1(table, manifest.program_root);
}

} // namespace

AssessmentV1 AssessCanonicalProductionRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule)
{
    AssessmentV1 out;
    std::string why;
    if (!sites::ValidateProductionProofSiteManifest(
            manifest, &why) ||
        !sched::ValidateProductionAggregationSchedule(
            manifest, schedule, &why)) {
        out.residual_mask |= kResidualManifestOrSchedule;
        out.note =
            "stage3:production_canonical_registry:"
            "manifest_or_schedule";
        return out;
    }

    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    out.canonical_family_sources =
        ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, sources, &why);
    out.family_migration =
        ut::AssessProductionFamilyProgramMigrationV1(sources);
    if (!out.canonical_family_sources) {
        out.residual_mask |= kResidualCanonicalFamilySources;
    }

    out.every_family_semantically_complete =
        sources.size() ==
            ut::kProductionProgramFamilyCountV1 &&
        std::all_of(
            sources.begin(), sources.end(),
            [](const ut::ProductionFamilyProgramSourceV1& source) {
                return source.semantic_relation_complete;
            });
    out.exact_semantic_endpoint_union =
        ExactSemanticEndpointUnion(sources);
    for (uint32_t index = 0; index < sources.size(); ++index) {
        const auto& source = sources[index];
        if (source.semantic_relation_complete) continue;
        const uint32_t missing =
            ResidualForKind(source.kind, out.family_migration);
        out.family_residuals.push_back({
            index, source.kind, source.role, missing});
    }
    if (!out.every_family_semantically_complete ||
        !out.exact_semantic_endpoint_union ||
        std::any_of(
            out.family_residuals.begin(),
            out.family_residuals.end(),
            [](const FamilySemanticResidualV1& residual) {
                return residual.missing_obligations == 0;
            })) {
        out.residual_mask |= kResidualIncompleteFamilySemantics;
    }

    const auto acceptance_instance =
        CanonicalAcceptanceInstance();
    bool acceptance_exact =
        acceptance_instance.valid &&
        av::BuildCanonicalProgramTableV1(
            acceptance_instance,
            out.universal_parent_program,
            &why);
    if (acceptance_exact) {
        const auto binding =
            av::AssessCanonicalProgramV1(
                acceptance_instance,
                out.universal_parent_program);
        acceptance_exact =
            binding.canonical_bytecode_complete &&
            binding.exact_program_table &&
            binding.exact_callback_order &&
            binding.fixed_trace_pin_redundancy_proved &&
            binding.statement_independent_program;
    }
    if (!acceptance_exact) {
        out.residual_mask |= kResidualAcceptanceProgram;
    }

    const bool normalized_built =
        np::BuildCanonicalProgramTableV1(
            out.normalized_root_program,
            &out.normalized_program_manifest,
            &why);
    const bool normalized_exact =
        normalized_built &&
        NormalizedProgramExactlyLowered(
            out.normalized_root_program,
            out.normalized_program_manifest);
    if (!normalized_exact) {
        out.residual_mask |= kResidualNormalizedProgram;
    }
    if (!out.normalized_program_manifest
             .canonical_program_executable ||
        out.normalized_program_manifest.residual_mask != 0) {
        out.residual_mask |=
            kResidualNormalizedProgramExecution;
    }

    cb::ProgramTableCommitmentPair parent_root;
    cb::ProgramTableCommitmentPair normalized_root;
    out.parent_program_roots_reconstructed =
        acceptance_exact &&
        normalized_exact &&
        ReconstructProgramRoot(
            out.universal_parent_program, parent_root) &&
        ReconstructProgramRoot(
            out.normalized_root_program, normalized_root);
    if (out.parent_program_roots_reconstructed) {
        out.universal_parent_program_root = parent_root;
        out.normalized_root_program_root = normalized_root;
    } else {
        out.residual_mask |=
            kResidualParentProgramRootReconstruction;
    }

    if (out.canonical_family_sources &&
        acceptance_exact && normalized_exact) {
        out.diagnostic_registry =
            ut::BuildProductionProgramRegistryV1(
                manifest, schedule, sources,
                out.universal_parent_program,
                out.normalized_root_program);
    }
    out.exact_parent_program_slots =
        !out.diagnostic_registry
             .external_registry_commitment.IsNull() &&
        out.diagnostic_registry.universal_parent_verifier ==
            out.universal_parent_program_root &&
        out.diagnostic_registry.normalized_root_verifier ==
            out.normalized_root_program_root &&
        out.diagnostic_registry.universal_parent_columns ==
            out.universal_parent_program.current_width &&
        out.diagnostic_registry.normalized_root_columns ==
            out.normalized_root_program.current_width;
    out.structurally_valid_diagnostic_registry =
        out.exact_parent_program_slots &&
        ut::ValidateProductionProgramRegistryV1(
            manifest, schedule, out.diagnostic_registry,
            out.diagnostic_registry.external_registry_commitment,
            out.diagnostic_registry.recursive_registry_commitment,
            &why);

    if (out.structurally_valid_diagnostic_registry) {
        const auto rebuilt =
            ut::BuildProductionProgramRegistryV1(
                manifest, schedule, sources,
                out.universal_parent_program,
                out.normalized_root_program);
        out.registry_roots_reconstructed =
            rebuilt == out.diagnostic_registry &&
            !rebuilt.external_registry_commitment.IsNull() &&
            !DigestZero(
                rebuilt.recursive_registry_commitment);
    }
    if (!out.registry_roots_reconstructed) {
        out.residual_mask |=
            kResidualRegistryRootReconstruction;
    }

    out.authority_eligible =
        out.residual_mask == 0 &&
        out.every_family_semantically_complete &&
        out.exact_semantic_endpoint_union &&
        out.exact_parent_program_slots &&
        out.parent_program_roots_reconstructed &&
        out.registry_roots_reconstructed &&
        out.structurally_valid_diagnostic_registry;
    out.note = out.authority_eligible
        ? "stage3:production_canonical_registry:"
          "authority_eligible"
        : "stage3:production_canonical_registry:"
          "fail_closed_with_exact_residuals";
    return out;
}

bool BuildCanonicalProductionRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    ut::ProductionProgramRegistryV1& out,
    AssessmentV1* assessment,
    std::string* why)
{
    out = {};
    AssessmentV1 local =
        AssessCanonicalProductionRegistryV1(
            manifest, schedule);
    if (assessment != nullptr) {
        *assessment = local;
    }
    if (!local.authority_eligible) {
        return Fail(why, "residuals_open");
    }
    out = std::move(local.diagnostic_registry);
    return true;
}

bool ValidateCanonicalDiagnosticRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ut::ProductionProgramRegistryV1& candidate,
    std::string* why)
{
    const AssessmentV1 expected =
        AssessCanonicalProductionRegistryV1(
            manifest, schedule);
    if (!expected.structurally_valid_diagnostic_registry ||
        !expected.parent_program_roots_reconstructed ||
        !expected.registry_roots_reconstructed) {
        return Fail(why, "canonical_rebuild");
    }
    if (candidate != expected.diagnostic_registry) {
        return Fail(why, "canonical_registry_substitution");
    }
    return ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, candidate,
        expected.diagnostic_registry
            .external_registry_commitment,
        expected.diagnostic_registry
            .recursive_registry_commitment,
        why);
}

} // namespace matmul::v4::rc::production_canonical_registry
