// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_canonical_parent_production_verifier.h>

#include <consensus/params.h>
#include <hash.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_normalized_block_transport.h>
#include <primitives/block.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::canonical_parent_production_verifier {
namespace {

namespace ut = universal_topology;
namespace transport = normalized_block_transport;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_production_verifier:" +
            detail;
    }
    return false;
}

void Missing(
    FrozenSpecAssessmentV1& out,
    uint32_t residual,
    const char* name)
{
    out.residual_mask |= residual;
    out.missing_inputs.emplace_back(name);
}

uint256 DimensionCommitment(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const RCEpisodeParams& episode,
    const RCCoupParams& coupled)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_FROZEN_PARENT_DIMENSIONS_V1";
    hash << kVersionV1;
    hash << height;
    hash << block.matmul_dim;
    hash << params.nMatMulV4Dimension;
    hash << params.nMatMulRCProfile;
    hash << params.nMatMulRCCoupledProfile;
    hash << params.fMatMulRCUseToyDims;
    hash << params.fMatMulRCCoupledUseToyDims;
    hash << episode.rounds << episode.d_head;
    hash << episode.n_q << episode.n_ctx;
    hash << episode.L_lyr << episode.d_model;
    hash << episode.d_ff << episode.b_seq;
    hash << episode.T_leaf;
    hash << coupled.barriers << coupled.lobes;
    hash << coupled.lobe_width << coupled.bank_pages;
    hash << coupled.rows_per_lobe;
    hash << coupled.pages_per_barrier_lobe;
    return hash.GetHash();
}

const sites::ProductionProofSiteEntry* FindSite(
    const sites::ProductionProofSiteManifest& manifest,
    sites::ProductionProofSiteKind kind,
    RCStage3RelationRole role)
{
    const auto found = std::find_if(
        manifest.entries.begin(),
        manifest.entries.end(),
        [=](const auto& entry) {
            return entry.kind == kind &&
                entry.role == role;
        });
    return found == manifest.entries.end()
        ? nullptr
        : &*found;
}

const bridge::SemanticEndpointProgramBindingV1*
FindEndpoint(
    const bridge::SemanticEndpointProgramBridgeManifestV1&
        manifest,
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role)
{
    const auto found = std::find_if(
        manifest.endpoints.begin(),
        manifest.endpoints.end(),
        [=](const auto& item) {
            return item.endpoint == endpoint &&
                item.role == role;
        });
    return found == manifest.endpoints.end()
        ? nullptr
        : &*found;
}

uint256 RoleProgramRoot(
    RCStage3RelationRole role,
    const std::vector<
        const bridge::SemanticEndpointProgramBindingV1*>&
        endpoints)
{
    // This root selects the immutable ProgramTable/output ABI, not evidence
    // that a live leaf proof already exports and CTL-aliases the cell.
    // `relation_column_exact` and `same_trace_ctl_alias` remain production
    // semantic-closure gates; requiring them here would circularly prevent
    // construction of the frozen recursive verifier that must consume those
    // leaf proofs.
    if (endpoints.empty()) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_FROZEN_ROLE_PROGRAM_SCHEDULE_V1";
    hash << kVersionV1;
    hash << static_cast<uint16_t>(role);
    hash << static_cast<uint32_t>(endpoints.size());
    for (const auto* endpoint : endpoints) {
        if (endpoint == nullptr ||
            !endpoint->selected_program_key ||
            !endpoint->exact_program_table_match ||
            !endpoint->canonical_output_metadata) {
            return {};
        }
        hash << static_cast<uint16_t>(
            endpoint->endpoint);
        hash << endpoint->family_index;
        hash << endpoint->relation_column;
        for (uint32_t word :
             endpoint
                 ->program_external_sha256d_words) {
            hash << word;
        }
        for (uint32_t word :
             endpoint
                 ->program_recursive_alg_hash_words) {
            hash << word;
        }
    }
    return hash.GetHash();
}

uint256 EndpointOccurrenceManifestRoot(
    const uint256& dimension_root,
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const sites::ProductionProofSiteEntry& site,
    const bridge::SemanticEndpointProgramBindingV1& endpoint)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_FROZEN_ENDPOINT_OCCURRENCE_V1";
    hash << kVersionV1;
    hash << dimension_root;
    hash << manifest.commitment;
    hash << schedule.commitment;
    hash << endpoint.endpoint_ordinal;
    hash << static_cast<uint16_t>(endpoint.role);
    hash << static_cast<uint16_t>(endpoint.endpoint);
    hash << static_cast<uint8_t>(site.kind);
    hash << site.logical_units;
    hash << site.units_per_site;
    hash << site.proof_sites;
    hash << endpoint.family_index;
    hash << endpoint.relation_column;
    return hash.GetHash();
}

bool RegistryPinMatches(
    const Consensus::Params& params,
    const pcr::AssessmentV1& registry)
{
    if (!registry.structurally_valid_diagnostic_registry ||
        !registry.registry_roots_reconstructed) {
        return false;
    }
    const auto pin =
        ut::BuildProductionProgramConsensusPinV1(
            registry.diagnostic_registry);
    return
        !pin.recursive_alg_hash_root.IsNull() &&
        pin.recursive_alg_hash_root ==
            params
                .hashMatMulRCStage3ProgramRegistryAlgRoot &&
        pin.external_sha256d_audit_root ==
            params
                .hashMatMulRCStage3ProgramRegistryShaAuditRoot &&
        pin.registry_binding ==
            params
                .hashMatMulRCStage3ProgramRegistryBinding;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value != 0 &&
        (value & (value - 1U)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value == 0) return 0;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value ==
            std::numeric_limits<uint32_t>::max()
        ? 0
        : value + 1;
}

uint32_t Log2Exact(uint32_t value)
{
    if (!IsPowerOfTwo(value)) return 0;
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

bool AppendProgramComponent(
    const constraint_bytecode::ProgramTable& component,
    constraint_bytecode::ProgramTable& aggregate,
    uint32_t& column_offset,
    uint32_t& challenge_offset,
    std::string* why)
{
    namespace cb = constraint_bytecode;
    if (!cb::ValidateProgramTable(component, why) ||
        column_offset >
            std::numeric_limits<uint32_t>::max() -
                component.current_width ||
        challenge_offset >
            std::numeric_limits<uint32_t>::max() -
                component.challenge_width ||
        aggregate.programs.size() >
            cb::kConstraintBytecodeMaxInstructions -
                component.programs.size()) {
        return Fail(why, "role_half_component");
    }
    for (const auto& source : component.programs) {
        cb::Program program = source;
        program.role =
            RCStage3RelationRole::CompositionLink;
        program.constraint_ordinal =
            static_cast<uint32_t>(
                aggregate.programs.size());
        for (auto& instruction : program.instructions) {
            switch (instruction.opcode) {
            case cb::Opcode::Current:
            case cb::Opcode::Next:
                instruction.lhs += column_offset;
                break;
            case cb::Opcode::Challenge:
                instruction.lhs += challenge_offset;
                break;
            default:
                break;
            }
        }
        aggregate.programs.push_back(
            std::move(program));
    }
    // A boundary-only component may declare next_width < current_width.
    // Embedding it in the aggregate's square current/next trace only adds
    // unused next-row columns; it does not alter or manufacture a relation.
    column_offset += component.current_width;
    challenge_offset += component.challenge_width;
    return true;
}

bool AppendConstantPublicOutputColumns(
    uint32_t first_column,
    uint32_t count,
    constraint_bytecode::ProgramTable& table,
    std::string* why)
{
    namespace cb = constraint_bytecode;
    if (count == 0 ||
        first_column >
            std::numeric_limits<uint32_t>::max() - count ||
        table.programs.size() >
            cb::kConstraintBytecodeMaxInstructions - count) {
        return Fail(why, "role_half_public_output_count");
    }
    const uint32_t final_width = first_column + count;
    for (uint32_t offset = 0; offset < count; ++offset) {
        cb::Program program;
        program.role =
            RCStage3RelationRole::CompositionLink;
        program.constraint_ordinal =
            static_cast<uint32_t>(table.programs.size());
        program.kind =
            air_quotient::AirKind::kTransition;
        program.declared_degree = 1;
        program.current_width = final_width;
        program.next_width = final_width;
        program.challenge_width =
            table.challenge_width;
        const uint32_t column = first_column + offset;
        program.instructions = {
            {cb::Opcode::Current, column, 0,
             gkr_field::Fp3::Zero()},
            {cb::Opcode::Next, column, 0,
             gkr_field::Fp3::Zero()},
            {cb::Opcode::Sub, 0, 1,
             gkr_field::Fp3::Zero()},
        };
        table.programs.push_back(std::move(program));
    }
    table.current_width = final_width;
    table.next_width = final_width;
    for (auto& program : table.programs) {
        program.current_width = final_width;
        program.next_width = final_width;
        program.challenge_width =
            table.challenge_width;
    }
    return cb::ValidateProgramTable(table, why);
}

bool BuildManifestDerivedShape(
    const sites::ProductionProofSiteManifest& manifest,
    const constraint_bytecode::ProgramTable& program,
    universal_two_child_parent::PublicShapeV1& out,
    std::string* why)
{
    namespace cb = constraint_bytecode;
    namespace aq = air_quotient;
    out = {};
    const uint32_t rows =
        manifest.policy.relation_rows_per_site;
    if (!IsPowerOfTwo(rows) ||
        rows == 0 ||
        rows > manifest.policy.max_air_trace_rows ||
        !cb::ValidateProgramTable(program, why)) {
        return Fail(why, "role_half_shape_rows");
    }
    aq::AirConstraintSystem<gkr_field::Fp3> cs;
    // This adapter needs only the manifest-derived degree/shape.  Challenge
    // values cannot change a canonical program's declared degree, kind,
    // column width or quotient length; they affect evaluation values only.
    // Supply an exact-width placeholder solely to instantiate the typed
    // evaluator so challenge-bearing production tables do not masquerade as
    // challenge-free tables.  No proof is evaluated or accepted here, and
    // the executable parent must still replay the proof-owned challenge epoch.
    const std::vector<gkr_field::Fp3> shape_challenges(
        program.challenge_width,
        gkr_field::Fp3::Zero());
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            program, rows, shape_challenges, cs, why)) {
        return Fail(why, "role_half_shape_cs");
    }
    const uint32_t quotient_len = cs.QuotientLen();
    const uint32_t coefficients =
        NextPowerOfTwo(
            std::max(rows, quotient_len));
    if (quotient_len == 0 ||
        coefficients == 0 ||
        coefficients >
            std::numeric_limits<uint32_t>::max() /
                kRCFriBlowup) {
        return Fail(why, "role_half_shape_domain");
    }
    const uint32_t lde = coefficients * kRCFriBlowup;
    out.version =
        universal_two_child_parent::
            kUniversalTwoChildParentVersionV1;
    out.child_rows = rows;
    out.child_columns = program.current_width;
    out.child_quotient_len = quotient_len;
    out.child_coefficients = coefficients;
    out.child_lde = lde;
    out.merkle_depth = Log2Exact(lde);
    out.folds = Log2Exact(coefficients);
    out.queries = kRCFri3AlgNumQueries;
    out.independent_fri_batching =
        Fri3AlgQ192IndependentBatching();
    out.column_lengths.assign(
        uint64_t{out.child_columns} + 1U, rows);
    out.column_lengths.back() = quotient_len;
    return out.merkle_depth != 0 &&
        out.folds != 0;
}

bool SameFrozenSpec(
    const cpc::FrozenBinaryParentSpecV1& lhs,
    const cpc::FrozenBinaryParentSpecV1& rhs)
{
    return lhs.version == rhs.version &&
        lhs.child_shape == rhs.child_shape &&
        lhs.child_registry == rhs.child_registry &&
        lhs.role_schedule == rhs.role_schedule &&
        lhs.child_public_output ==
            rhs.child_public_output;
}

bool ValidateRoleHalfAdapter(
    const cpc::FrozenBinaryParentSpecV1& expected,
    const cpc::FrozenBinaryParentSpecV1& candidate,
    std::string* why)
{
    namespace cb = constraint_bytecode;
    if (!SameFrozenSpec(expected, candidate)) {
        return Fail(why, "role_half_adapter_substitution");
    }
    for (uint32_t child = 0; child < 2; ++child) {
        const auto& registry =
            candidate.child_registry[child];
        if (!cb::ValidateProgramTable(
                registry.child_relation_program, why) ||
            registry.program_root.IsNull() ||
            registry.program_root !=
                cb::CommitProgramTable(
                    registry.child_relation_program) ||
            registry.child_relation_program.current_width !=
                candidate.child_shape[child]
                    .child_columns ||
            registry.child_relation_program.next_width !=
                candidate.child_shape[child]
                    .child_columns) {
            return Fail(why, "role_half_program_root");
        }
        const uint32_t cells =
            cpc::CanonicalChildPublicOutputCellCountV1(
                candidate, child);
        const uint64_t end =
            uint64_t{
                candidate.child_public_output[child]
                    .first_trace_column} +
            cells;
        if (cells == 0 ||
            end !=
                candidate.child_shape[child]
                    .child_columns) {
            return Fail(why, "role_half_public_output_abi");
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_production_verifier:"
            "canonical_role_half_adapter_valid";
    }
    return true;
}

bool BuildCanonicalRoleHalfAdapter(
    const sites::ProductionProofSiteManifest& manifest,
    const pcr::AssessmentV1& registry,
    const std::vector<cpc::FrozenRoleScheduleV1>& roles,
    cpc::FrozenBinaryParentSpecV1& out,
    std::array<std::vector<uint32_t>, 2>&
        child_r0_base_columns,
    std::array<uint256, 2>&
        child_phase_commitment,
    std::vector<uint32_t>&
        missing_phase_family_indices,
    std::string* why)
{
    namespace cb = constraint_bytecode;
    namespace utp = universal_topology;
    out = {};
    child_r0_base_columns = {};
    child_phase_commitment = {};
    missing_phase_family_indices.clear();
    out.role_schedule = roles;
    if (roles.size() != nav3::kRoleCountV3 ||
        !registry.canonical_family_sources ||
        registry.family_migration.families_structural_stubs != 0) {
        return Fail(why, "role_half_canonical_sources");
    }
    const auto sources =
        utp::BuildProductionFamilyProgramSourcesV1(
            manifest);
    if (!utp::ValidateProductionFamilyProgramSourcesV1(
            manifest, sources, why) ||
        sources.size() != manifest.entries.size()) {
        return Fail(why, "role_half_source_inventory");
    }
    const auto& order = RCStage3UnifiedRoleOrder();
    for (uint32_t child = 0; child < 2; ++child) {
        cb::ProgramTable aggregate;
        aggregate.role =
            RCStage3RelationRole::CompositionLink;
        uint32_t column_offset = 0;
        uint32_t challenge_offset = 0;
        bool phase_complete = true;
        std::vector<std::vector<unsigned char>>
            ordered_phase_bytes;
        std::array<bool, cpc::kCanonicalRoleSplitV1>
            role_present{};
        const uint32_t begin =
            child == 0 ? 0 : cpc::kCanonicalRoleSplitV1;
        const uint32_t end =
            child == 0
            ? cpc::kCanonicalRoleSplitV1
            : nav3::kRoleCountV3;
        for (const auto& source : sources) {
            const auto found =
                std::find(
                    order.begin() + begin,
                    order.begin() + end,
                    source.role);
            if (found == order.begin() + end) {
                continue;
            }
            role_present[
                static_cast<size_t>(
                    found - (order.begin() + begin))] =
                true;
            std::vector<unsigned char> phase_bytes;
            if (!utp::
                    ValidateProductionFamilyPhaseDescriptorV1(
                        source.program, source.phase,
                        /*require_producer_export=*/false,
                        why) ||
                !utp::
                    SerializeProductionFamilyPhaseDescriptorV1(
                        source.phase, phase_bytes, why)) {
                out = {};
                child_r0_base_columns = {};
                child_phase_commitment = {};
                missing_phase_family_indices.clear();
                return false;
            }
            if (!source.phase.producer_manifest_exported) {
                phase_complete = false;
                missing_phase_family_indices.push_back(
                    source.family_index);
            } else {
                for (const uint32_t local_column :
                     source.phase.r0_base_columns) {
                    child_r0_base_columns[child]
                        .push_back(
                            column_offset +
                            local_column);
                }
            }
            ordered_phase_bytes.push_back(
                std::move(phase_bytes));
            if (!AppendProgramComponent(
                    source.program, aggregate,
                    column_offset, challenge_offset,
                    why)) {
                out = {};
                return false;
            }
        }
        if (aggregate.programs.empty() ||
            std::find(
                role_present.begin(),
                role_present.end(), false) !=
                role_present.end()) {
            out = {};
            return Fail(why, "role_half_role_coverage");
        }
        aggregate.current_width = column_offset;
        aggregate.next_width = column_offset;
        aggregate.challenge_width =
            challenge_offset;
        out.child_public_output[child]
            .first_trace_column = column_offset;
        const uint32_t cells =
            cpc::CanonicalChildPublicOutputCellCountV1(
                out, child);
        if (!AppendConstantPublicOutputColumns(
                column_offset, cells, aggregate, why)) {
            out = {};
            return false;
        }
        // Public output columns are deterministic pre-challenge statement
        // cells.  They are appended after all family components and therefore
        // join R0 directly without any family-local offset ambiguity.
        for (uint32_t cell = 0; cell < cells; ++cell) {
            child_r0_base_columns[child]
                .push_back(column_offset + cell);
        }
        auto& frozen = out.child_registry[child];
        frozen.child_relation_program =
            std::move(aggregate);
        frozen.program_root =
            cb::CommitProgramTable(
                frozen.child_relation_program);
        if (frozen.program_root.IsNull() ||
            !BuildManifestDerivedShape(
                manifest,
                frozen.child_relation_program,
                out.child_shape[child], why)) {
            out = {};
            return false;
        }
        if (phase_complete) {
            const auto& base =
                child_r0_base_columns[child];
            if (base.empty() ||
                base.size() >=
                    frozen.child_relation_program
                        .current_width ||
                !std::is_sorted(
                    base.begin(), base.end()) ||
                std::adjacent_find(
                    base.begin(), base.end()) !=
                    base.end()) {
                out = {};
                child_r0_base_columns = {};
                child_phase_commitment = {};
                missing_phase_family_indices.clear();
                return Fail(
                    why, "role_half_phase_schedule");
            }
            HashWriter hash;
            hash <<
                "BTX_RC_STAGE3_ROLE_HALF_R0_PHASE_V1";
            hash << uint16_t{1};
            hash << child;
            hash << registry.diagnostic_registry
                        .external_registry_commitment;
            hash << frozen.program_root;
            hash << universal_two_child_parent::
                CommitPublicShapeV1(
                out.child_shape[child]);
            hash << static_cast<uint32_t>(
                ordered_phase_bytes.size());
            for (const auto& bytes :
                 ordered_phase_bytes) {
                hash << bytes;
            }
            hash << static_cast<uint32_t>(base.size());
            for (const uint32_t column : base) {
                hash << column;
            }
            child_phase_commitment[child] =
                hash.GetHash();
            if (child_phase_commitment[child]
                    .IsNull()) {
                out = {};
                child_r0_base_columns = {};
                child_phase_commitment = {};
                missing_phase_family_indices.clear();
                return Fail(
                    why, "role_half_phase_commitment");
            }
        } else {
            child_r0_base_columns[child].clear();
            child_phase_commitment[child].SetNull();
        }
    }
    std::sort(
        missing_phase_family_indices.begin(),
        missing_phase_family_indices.end());
    missing_phase_family_indices.erase(
        std::unique(
            missing_phase_family_indices.begin(),
            missing_phase_family_indices.end()),
        missing_phase_family_indices.end());
    return ValidateRoleHalfAdapter(out, out, why);
}

} // namespace

FrozenSpecAssessmentV1
AssessFrozenBinaryParentSpecV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height)
{
    FrozenSpecAssessmentV1 out;
    const RCEpisodeParams episode =
        ResolveRCEpisodeParams(params, height);
    const RCCoupParams coupled =
        ResolveRCCoupParams(params);
    const auto required =
        RequiredRCStage3Statement(params, height);
    out.block_dimensions_canonical =
        height >= 0 &&
        required.has_value() &&
        *required == RCStage3StatementKind::Composed &&
        ValidateRCEpisodeParams(episode) &&
        ValidateRCCoupParams(coupled) &&
        block.matmul_dim ==
            params.nMatMulV4Dimension;
    out.block_dimension_commitment =
        out.block_dimensions_canonical
        ? DimensionCommitment(
              block, params, height,
              episode, coupled)
        : uint256{};
    if (!out.block_dimensions_canonical ||
        out.block_dimension_commitment.IsNull()) {
        Missing(
            out, kResidualBlockDimensions,
            "canonical_block_episode_coupled_dimensions");
    }

    out.site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    out.manifest_canonical =
        sites::ValidateProductionProofSiteManifest(
            out.site_manifest, nullptr);
    if (!out.manifest_canonical) {
        Missing(
            out, kResidualSiteManifest,
            "selected_production_site_manifest");
    }

    out.aggregation_schedule =
        sched::BuildProductionAggregationSchedule(
            out.site_manifest);
    out.aggregation_schedule_canonical =
        out.manifest_canonical &&
        sched::ValidateProductionAggregationSchedule(
            out.site_manifest,
            out.aggregation_schedule, nullptr);
    if (!out.aggregation_schedule_canonical) {
        Missing(
            out, kResidualAggregationSchedule,
            "selected_production_aggregation_schedule");
    }

    out.registry =
        pcr::AssessCanonicalProductionRegistryV1(
            out.site_manifest,
            out.aggregation_schedule);
    out.registry_rebuilt_from_canonical_sources =
        out.registry.canonical_family_sources &&
        out.registry.parent_program_roots_reconstructed &&
        out.registry.registry_roots_reconstructed &&
        out.registry
            .structurally_valid_diagnostic_registry;
    if (!out.registry_rebuilt_from_canonical_sources ||
        !out.registry.authority_eligible) {
        Missing(
            out, kResidualCanonicalRegistry,
            "semantically_complete_28_family_registry");
    }
    out.consensus_registry_pin_matches =
        RegistryPinMatches(params, out.registry);
    if (!out.consensus_registry_pin_matches) {
        Missing(
            out, kResidualConsensusRegistryPin,
            "consensus_frozen_registry_pin");
    }

    out.endpoint_program_map =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    out.exact_endpoint_order =
        out.endpoint_program_map.exact_endpoint_order &&
        out.endpoint_program_map.endpoints.size() ==
            nav3::kEndpointCountV3;
    if (!out.exact_endpoint_order ||
        !out.endpoint_program_map
             .production_sources_canonical) {
        Missing(
            out, kResidualEndpointProgramMap,
            "canonical_52_endpoint_program_map");
    }

    const auto& roles = RCStage3UnifiedRoleOrder();
    out.diagnostic_role_schedule.reserve(roles.size());
    uint32_t endpoint_ordinal = 0;
    for (const auto role_kind : roles) {
        cpc::FrozenRoleScheduleV1 role;
        role.role = role_kind;
        std::vector<
            const bridge::
                SemanticEndpointProgramBindingV1*>
            mapped;
        bool complete = true;
        for (const auto endpoint_kind :
             RequiredRCStage3RelationEndpoints(
                 role_kind)) {
            const auto* endpoint =
                FindEndpoint(
                    out.endpoint_program_map,
                    endpoint_kind, role_kind);
            const auto* site =
                endpoint == nullptr
                ? nullptr
                : FindSite(
                      out.site_manifest,
                      endpoint->proof_site_kind,
                      role_kind);
            if (endpoint == nullptr ||
                endpoint->endpoint_ordinal !=
                    endpoint_ordinal ||
                site == nullptr ||
                site->logical_units == 0 ||
                !endpoint->selected_program_key ||
                !endpoint->exact_program_table_match ||
                !endpoint
                     ->canonical_output_metadata) {
                complete = false;
                ++endpoint_ordinal;
                continue;
            }
            cpc::FrozenEndpointScheduleV1 occurrence;
            occurrence.endpoint = endpoint_kind;
            occurrence.instance_count =
                site->logical_units;
            occurrence.manifest_root =
                EndpointOccurrenceManifestRoot(
                    out.block_dimension_commitment,
                    out.site_manifest,
                    out.aggregation_schedule,
                    *site, *endpoint);
            if (occurrence.manifest_root.IsNull()) {
                complete = false;
            } else {
                role.endpoints.push_back(
                    occurrence);
                mapped.push_back(endpoint);
                ++out.derived_endpoint_occurrences;
            }
            ++endpoint_ordinal;
        }
        if (complete &&
            role.endpoints.size() ==
                RequiredRCStage3RelationEndpoints(
                    role_kind).size()) {
            role.program_root =
                RoleProgramRoot(role_kind, mapped);
            if (!role.program_root.IsNull()) {
                ++out.derived_role_programs;
            }
        }
        out.diagnostic_role_schedule.push_back(
            std::move(role));
    }
    out.exact_endpoint_occurrence_schedule =
        out.derived_endpoint_occurrences ==
            nav3::kEndpointCountV3;
    out.exact_role_program_schedule =
        out.derived_role_programs ==
            nav3::kRoleCountV3;
    if (!out.exact_endpoint_occurrence_schedule) {
        Missing(
            out, kResidualEndpointOccurrences,
            "all_52_block_derived_endpoint_occurrences");
    }
    if (!out.exact_role_program_schedule) {
        Missing(
            out, kResidualEndpointProgramMap,
            "all_14_role_program_schedules");
    }

    std::string adapter_why;
    const bool adapter =
        BuildCanonicalRoleHalfAdapter(
            out.site_manifest, out.registry,
            out.diagnostic_role_schedule,
            out.diagnostic_frozen_spec,
            out.diagnostic_child_r0_base_columns,
            out.diagnostic_child_phase_commitment,
            out.missing_r0_phase_family_indices,
            &adapter_why);
    out.role_half_adapter_note = adapter_why;
    out.role_half_programs_available =
        adapter &&
        !out.diagnostic_frozen_spec
             .child_registry[0].program_root.IsNull() &&
        !out.diagnostic_frozen_spec
             .child_registry[1].program_root.IsNull();
    out.role_half_shapes_available =
        adapter &&
        out.diagnostic_frozen_spec
                .child_shape[0].child_rows != 0 &&
        out.diagnostic_frozen_spec
                .child_shape[1].child_rows != 0;
    out.public_output_abi_available =
        adapter &&
        cpc::CanonicalChildPublicOutputCellCountV1(
            out.diagnostic_frozen_spec, 0) != 0 &&
        cpc::CanonicalChildPublicOutputCellCountV1(
            out.diagnostic_frozen_spec, 1) != 0;
    out.role_half_r0_schedules_available =
        adapter &&
        out.missing_r0_phase_family_indices.empty() &&
        !out.diagnostic_child_r0_base_columns[0]
             .empty() &&
        !out.diagnostic_child_r0_base_columns[1]
             .empty() &&
        !out.diagnostic_child_phase_commitment[0]
             .IsNull() &&
        !out.diagnostic_child_phase_commitment[1]
             .IsNull();
    if (!out.role_half_programs_available) {
        Missing(
            out, kResidualRoleHalfPrograms,
            "two_canonical_seven_role_child_program_tables");
    }
    if (!out.role_half_shapes_available) {
        Missing(
            out, kResidualRoleHalfShapes,
            "two_manifest_derived_child_fri_shapes");
    }
    if (!out.public_output_abi_available) {
        Missing(
            out, kResidualPublicOutputAbi,
            "registry_pinned_child_public_output_column_bases");
    }
    if (!out.role_half_r0_schedules_available) {
        Missing(
            out, kResidualRoleHalfR0Schedule,
            "producer_exported_safe_split_rap_r0_phase_schedules");
        for (const uint32_t family :
             out.missing_r0_phase_family_indices) {
            out.missing_inputs.push_back(
                "r0_phase_family_" +
                std::to_string(family));
        }
    }

    out.spec_derivable =
        out.residual_mask == 0 &&
        out.block_dimensions_canonical &&
        out.manifest_canonical &&
        out.aggregation_schedule_canonical &&
        out.registry_rebuilt_from_canonical_sources &&
        out.registry.authority_eligible &&
        out.consensus_registry_pin_matches &&
        out.exact_endpoint_order &&
        out.exact_endpoint_occurrence_schedule &&
        out.exact_role_program_schedule &&
        out.role_half_programs_available &&
        out.role_half_shapes_available &&
        out.public_output_abi_available &&
        out.role_half_r0_schedules_available;
    out.authority = false;
    out.note = out.spec_derivable
        ? "stage3:canonical_parent_production_verifier:"
          "frozen_spec_derivable_not_authority"
        : "stage3:canonical_parent_production_verifier:"
          "frozen_spec_fail_closed_with_exact_missing_inputs";
    return out;
}

bool BuildFrozenBinaryParentSpecV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    cpc::FrozenBinaryParentSpecV1& out,
    FrozenSpecAssessmentV1* assessment,
    std::string* why)
{
    out = {};
    FrozenSpecAssessmentV1 local =
        AssessFrozenBinaryParentSpecV1(
            block, params, height);
    if (assessment != nullptr) {
        *assessment = local;
    }
    if (!local.spec_derivable) {
        return Fail(why, "frozen_spec_unavailable");
    }
    if (!ValidateRoleHalfAdapter(
            local.diagnostic_frozen_spec,
            local.diagnostic_frozen_spec, why)) {
        return false;
    }
    out = local.diagnostic_frozen_spec;
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_production_verifier:"
            "frozen_spec_built_from_canonical_registry";
    }
    return true;
}

bool ValidateDiagnosticRoleHalfAdapterV1(
    const FrozenSpecAssessmentV1& assessment,
    const cpc::FrozenBinaryParentSpecV1& candidate,
    std::string* why)
{
    if (!assessment.registry_rebuilt_from_canonical_sources ||
        !assessment.exact_endpoint_order ||
        !assessment.exact_endpoint_occurrence_schedule ||
        !assessment.exact_role_program_schedule ||
        !assessment.role_half_programs_available ||
        !assessment.role_half_shapes_available ||
        !assessment.public_output_abi_available) {
        return Fail(why, "diagnostic_adapter_prerequisites");
    }
    return ValidateRoleHalfAdapter(
        assessment.diagnostic_frozen_spec,
        candidate, why);
}

MechanismVerifyStatusV1
VerifyAttachedCanonicalParentMechanismV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    FrozenSpecAssessmentV1* assessment,
    cpc::RebuiltCanonicalParentV1* rebuilt,
    std::string* why)
{
    nav3::NormalizedAuthorityReceiptV3 receipt;
    ncb::DirectReceiptConsensusStatementV3 statement;
    if (!ncb::DecodeAndBindAttachedDirectReceiptV3(
            block, params, height, target,
            receipt, statement, why)) {
        return
            MechanismVerifyStatusV1::
                AttachmentDecodeFailed;
    }
    cpc::FrozenBinaryParentSpecV1 frozen;
    FrozenSpecAssessmentV1 local;
    if (!BuildFrozenBinaryParentSpecV1(
            block, params, height, frozen,
            &local, why)) {
        if (assessment != nullptr) {
            *assessment = std::move(local);
        }
        return
            MechanismVerifyStatusV1::
                FrozenSpecUnavailable;
    }
    if (assessment != nullptr) {
        *assessment = local;
    }
    const auto receipt_bytes =
        transport::UnpackReceiptWordsV3(
            block.matrix_c_data, why);
    if (!receipt_bytes.has_value()) {
        return
            MechanismVerifyStatusV1::
                AttachmentDecodeFailed;
    }
    cpc::CompleteChildStatementsV1 claims;
    claims.roles = receipt.roles;
    cpc::RebuiltCanonicalParentV1 local_rebuilt;
    if (!cpc::VerifyCanonicalParentReceiptV1(
            statement, frozen, claims,
            *receipt_bytes, &local_rebuilt, why)) {
        return
            MechanismVerifyStatusV1::
                NativeParentRejected;
    }
    const bool complete_child_acceptance =
        local_rebuilt.verifier
            .full_child_acceptance_constrained;
    const bool authority =
        local_rebuilt.authority;
    if (authority !=
        complete_child_acceptance) {
        Fail(why, "unexpected_authority_state");
        return
            MechanismVerifyStatusV1::
                NativeParentRejected;
    }
    if (rebuilt != nullptr) {
        *rebuilt = std::move(local_rebuilt);
    }
    if (authority) {
        if (why != nullptr) {
            *why =
                "stage3:canonical_parent_production_verifier:"
                "native_parent_authority_verified";
        }
        return
            MechanismVerifyStatusV1::
                AuthorityVerified;
    }
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_production_verifier:"
            "native_parent_mechanism_verified_not_authority";
    }
    return
        MechanismVerifyStatusV1::
            MechanismVerifiedNotAuthority;
}

} // namespace matmul::v4::rc::canonical_parent_production_verifier
