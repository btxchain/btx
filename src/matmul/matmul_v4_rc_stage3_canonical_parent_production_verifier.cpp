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
            !endpoint->canonical_output_metadata ||
            !endpoint->relation_column_exact) {
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
                     ->canonical_output_metadata ||
                !endpoint->relation_column_exact) {
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

    // The immutable registry currently exposes family, universal-parent and
    // normalized-root programs.  It does not expose either exact seven-role
    // aggregate child ProgramTable consumed by FrozenBinaryParentSpecV1.
    out.role_half_programs_available = false;
    out.role_half_shapes_available = false;
    out.public_output_abi_available = false;
    Missing(
        out, kResidualRoleHalfPrograms,
        "two_canonical_seven_role_child_program_tables");
    Missing(
        out, kResidualRoleHalfShapes,
        "two_manifest_derived_child_fri_shapes");
    Missing(
        out, kResidualPublicOutputAbi,
        "registry_pinned_child_public_output_column_bases");

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
        out.public_output_abi_available;
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
    // This assignment becomes reachable only when the production registry
    // exposes the two role-half ProgramTables, shapes and public-output bases.
    // Keeping it unreachable now is intentional: manufacturing those objects
    // from family widths would recreate the structural-stub vulnerability.
    return Fail(why, "role_half_registry_adapter_missing");
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
    if (local_rebuilt.authority ||
        local_rebuilt.verifier
            .full_child_acceptance_constrained) {
        Fail(why, "unexpected_authority_state");
        return
            MechanismVerifyStatusV1::
                NativeParentRejected;
    }
    if (rebuilt != nullptr) {
        *rebuilt = std::move(local_rebuilt);
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
