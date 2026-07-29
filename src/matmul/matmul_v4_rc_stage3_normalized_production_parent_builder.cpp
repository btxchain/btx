// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_production_parent_builder.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>
#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <primitives/block.h>
#include <hash.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace matmul::v4::rc::normalized_production_parent_builder {
namespace {

namespace composer = stage3_air_parent_composer;
namespace gf = gkr_field;
namespace hash_air = stage3_hash_air;
namespace hierarchy = recursive_hierarchy;
namespace nav3 = normalized_authority;
namespace semantic_source = episode_semantic_source_alg;
namespace semantic_intake =
    stage3_semantic_endpoint_receipt_intake;

using AirCS = air_quotient::AirConstraintSystem<gf::Fp3>;
using AirConstraint = air_quotient::AirConstraint<gf::Fp3>;
using Role = RCStage3RelationRole;

constexpr char kNav3InventoryDomain[] =
    "BTX_RC_STAGE3_NAV3_PUBLIC_INVENTORY_V1";
constexpr char kNav3CsCommitmentDomain[] =
    "BTX_RC_STAGE3_NAV3_PARENT_CS_COMMITMENT_V1";
constexpr char kNav3EndpointDomain[] =
    "BTX_RC_STAGE3_NAV3_ENDPOINT_PIN_V1";

void Note(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_production_parent_builder:" +
            detail;
    }
}

uint256 TaggedRoot(
    const char* tag, const uint256& material)
{
    HashWriter hash;
    hash << kNav3InventoryDomain;
    hash << std::string{tag};
    hash << material;
    return hash.GetHash();
}

uint256 EndpointTaggedRoot(
    const char* tag,
    RCStage3RelationEndpoint endpoint,
    const uint256& material)
{
    HashWriter hash;
    hash << kNav3EndpointDomain;
    hash << std::string{tag};
    hash << static_cast<uint16_t>(endpoint);
    hash << material;
    return hash.GetHash();
}

uint256 RecursiveEvidenceStatementRoot(
    const uint256& composed_digest,
    const uint256& evidence_commitment)
{
    if (composed_digest.IsNull() ||
        evidence_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kNav3InventoryDomain;
    hash << std::string{"recursive_receipt_evidence"};
    hash << composed_digest;
    hash << evidence_commitment;
    return hash.GetHash();
}

std::vector<RCStage3RelationClosureRoleAudit>
RoleAuditFromVerifiedEvidence(
    const semantic_intake::
        VerifiedRecursiveReceiptEvidenceV1& evidence)
{
    // Ignore the legacy process-global recursive-consumption bit entirely.
    // The immutable evidence can authorize a cell only after the complete
    // inventory and executable in-parent child verifier both close.
    const auto cells =
        CurrentRCStage3RelationEndpointCellAudit();
    std::vector<RCStage3RelationClosureRoleAudit> out;
    out.reserve(kRCStage3RelationClosureRoleCount);
    for (const RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        RCStage3RelationClosureRoleAudit audit;
        audit.role = role;
        for (const auto& cell : cells) {
            if (cell.role != role) continue;
            ++audit.required_endpoints;
            audit.proof_derived_ctl_endpoints +=
                cell.same_trace_ctl_alias ? 1U : 0U;
            // A partial receipt inventory is useful binding evidence only.
            // It must not import even independently known strict cells into
            // this recursive-evidence audit, because omission of any producer
            // role still leaves the transitive episode statement open.
            audit.strict_transitive_endpoints +=
                evidence.complete_52_and_14 &&
                        cell.strict_transitive_complete
                    ? 1U
                    : 0U;
            const uint32_t ordinal =
                static_cast<uint32_t>(
                    cell.endpoint) - 1U;
            const bool evidence_owned =
                ordinal <
                    evidence
                        .endpoint_receipt_commitments
                        .size() &&
                !evidence
                     .endpoint_receipt_commitments[
                         ordinal]
                     .IsNull();
            const bool recursively_consumed =
                evidence.valid &&
                evidence.recursive_credit_eligible &&
                evidence_owned &&
                cell.strict_transitive_complete &&
                cell.same_trace_ctl_alias;
            audit
                .recursively_consumed_strict_endpoints +=
                recursively_consumed ? 1U : 0U;
        }
        audit.recursive_ctl_consumption =
            audit.required_endpoints != 0 &&
            audit
                .recursively_consumed_strict_endpoints ==
            audit.required_endpoints;
        audit.role_complete =
            audit.recursive_ctl_consumption &&
            audit.proof_derived_ctl_endpoints ==
                audit.required_endpoints &&
            audit.strict_transitive_endpoints ==
                audit.required_endpoints &&
            evidence.complete_52_and_14 &&
            evidence
                .recursive_child_acceptance_constraints_complete &&
            kRCStage3RelationClosureRecursiveChildrenExecutable;
        audit.remaining =
            audit.role_complete
            ? "immutable verified receipt evidence, strict transitive "
              "provenance and in-parent recursive acceptance closed"
            : "verified_receipt_endpoints_" +
              std::to_string(
                  evidence.active_endpoints) +
              "_of_52;strict_or_recursive_acceptance_open";
        out.push_back(std::move(audit));
    }
    return out;
}

uint256 CommitParentCsShapeV1(const AirCS& cs)
{
    HashWriter hash;
    hash << kNav3CsCommitmentDomain;
    hash << cs.n_rows;
    hash << cs.n_columns;
    hash << static_cast<uint64_t>(cs.constraints.size());
    uint32_t max_degree = 0;
    for (const auto& constraint : cs.constraints) {
        max_degree = std::max(max_degree, constraint.alg_degree);
        hash << std::string{constraint.name ? constraint.name : ""};
        hash << static_cast<uint8_t>(constraint.kind);
        hash << constraint.alg_degree;
    }
    hash << max_degree;
    hash << static_cast<uint64_t>(
        cs.preprocessed_row_group_roots.size());
    for (const auto& group : cs.preprocessed_row_group_roots) {
        hash << group.version;
        hash << static_cast<uint8_t>(group.role);
        hash << static_cast<uint64_t>(
            group.ordered_columns.size());
        for (uint32_t column : group.ordered_columns) {
            hash << column;
        }
        hash << group.root;
    }
    return hash.GetHash();
}

bool ConvertCandidateToCanonicalProductV1(
    const ProductionParentBuildInputV1& input,
    const ProductionRelationParentCandidateV1& candidate,
    const ProductionProgramConsensusPinV1& registry_pin,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why)
{
    out = {};
    if (!candidate.production_authority ||
        !candidate.local_parent_valid ||
        candidate.cs.n_rows == 0 ||
        candidate.cs.n_columns == 0 ||
        candidate.direct_parent_base_column_indices.empty() ||
        candidate.direct_parent_base_row_root.IsNull() ||
        candidate.composed_digest.IsNull() ||
        candidate.episode_digest.IsNull() ||
        candidate.coupled_digest.IsNull() ||
        !candidate.recursive_receipt_evidence.valid ||
        candidate.recursive_receipt_evidence
            .evidence_commitment.IsNull() ||
        !candidate.recursive_receipt_evidence_rebuilt ||
        !candidate
             .recursive_receipt_evidence_same_parent_bound ||
        input.params == nullptr) {
        Note(why, "nav3_inventory:candidate_incomplete");
        return false;
    }

    out.version =
        consumer::kNormalizedRelationReceiptConsumerVersionV1;
    out.cs = candidate.cs;
    out.columns = candidate.columns;
    out.r0_base_column_indices =
        candidate.direct_parent_base_column_indices;
    out.r0_session =
        air_quotient::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns, out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        out.r0_session.base_row_commitment.IsNull() ||
        out.r0_session.base_row_commitment !=
            candidate.direct_parent_base_row_root ||
        out.r0_session.base_column_indices !=
            out.r0_base_column_indices) {
        Note(
            why,
            "nav3_inventory:r0_session:" + out.r0_session.note);
        out = {};
        return false;
    }

    std::string shape_why;
    if (!consumer::DeriveParentShapeV1(
            out.cs, out.verifier_inputs.parent_shape,
            &shape_why)) {
        Note(why, "nav3_inventory:shape:" + shape_why);
        out = {};
        return false;
    }

    out.verifier_inputs.fixed_trace_columns =
        out.r0_base_column_indices;
    out.verifier_inputs.fixed_trace_row_root =
        out.r0_session.base_row_commitment;
    out.verifier_inputs.parent_cs_commitment =
        CommitParentCsShapeV1(out.cs);
    out.verifier_inputs.parent_node_binding =
        candidate.episode_digest;
    out.verifier_inputs.parent_context_binding =
        candidate.coupled_digest;
    out.verifier_inputs.outer_statement_root =
        candidate.composed_digest;
    out.verifier_inputs.program_registry_root =
        registry_pin.recursive_alg_hash_root;
    out.verifier_inputs.topology_manifest_root =
        TaggedRoot(
            "topology",
            registry_pin.registry_binding);
    out.verifier_inputs.aggregation_schedule_root =
        TaggedRoot(
            "aggregation_schedule",
            registry_pin.registry_binding);
    out.verifier_inputs.occurrence_manifest_root =
        TaggedRoot(
            "occurrence_manifest",
            RecursiveEvidenceStatementRoot(
                candidate.composed_digest,
                candidate
                    .recursive_receipt_evidence
                    .evidence_commitment));
    out.verifier_inputs.verifier_program_root =
        TaggedRoot(
            "verifier_program",
            registry_pin.recursive_alg_hash_root);
    out.verifier_inputs.abi_plan_root =
        TaggedRoot("abi_plan", candidate.episode_digest);
    out.verifier_inputs.selection_plan_root =
        TaggedRoot(
            "selection_plan", candidate.coupled_digest);
    out.verifier_inputs.derived_hash_plan_root =
        TaggedRoot(
            "derived_hash_plan",
            registry_pin.external_sha256d_audit_root);
    out.verifier_inputs.parent_program_root =
        TaggedRoot(
            "parent_program",
            registry_pin.recursive_alg_hash_root);

    out.verifier_inputs.roles.clear();
    out.verifier_inputs.roles.reserve(candidate.roles.size());
    for (const auto& role_placement : candidate.roles) {
        nav3::RolePinV3 role_pin;
        role_pin.role = role_placement.role;
        role_pin.program_root = TaggedRoot(
            "role_program",
            TaggedRoot(
                RCStage3RelationRoleName(role_placement.role),
                registry_pin.recursive_alg_hash_root));
        role_pin.relation_statement_root = TaggedRoot(
            "role_statement",
            TaggedRoot(
                RCStage3RelationRoleName(role_placement.role),
                candidate.composed_digest));
        role_pin.endpoints.reserve(
            role_placement.endpoints.size());
        for (const auto& endpoint_placement :
             role_placement.endpoints) {
            const uint256 committed =
                Fri3AlgDigestToUint256(
                    endpoint_placement.committed_root);
            if (committed.IsNull()) {
                Note(why, "nav3_inventory:endpoint_root_null");
                out = {};
                return false;
            }
            nav3::EndpointPinV3 endpoint_pin;
            endpoint_pin.endpoint = endpoint_placement.endpoint;
            endpoint_pin.instance_count =
                1U + endpoint_placement.endpoint_ordinal;
            endpoint_pin.manifest_root = committed;
            endpoint_pin.relation_proof_root =
                EndpointTaggedRoot(
                    "relation_proof",
                    endpoint_placement.endpoint,
                    committed);
            endpoint_pin.semantic_root =
                EndpointTaggedRoot(
                    "semantic",
                    endpoint_placement.endpoint,
                    committed);
            endpoint_pin.ctl_terminal_root =
                EndpointTaggedRoot(
                    "ctl_terminal",
                    endpoint_placement.endpoint,
                    committed);
            endpoint_pin.recursive_child_statement_root =
                EndpointTaggedRoot(
                    "recursive_child_statement",
                    endpoint_placement.endpoint,
                    committed);
            role_pin.endpoints.push_back(
                std::move(endpoint_pin));
        }
        role_pin.endpoint_manifest_root =
            nav3::ComputeRoleEndpointManifestRootV3(role_pin);
        role_pin.role_statement_root =
            nav3::ComputeRoleStatementRootV3(role_pin);
        if (role_pin.endpoint_manifest_root.IsNull() ||
            role_pin.role_statement_root.IsNull()) {
            Note(why, "nav3_inventory:role_derived_root");
            out = {};
            return false;
        }
        out.verifier_inputs.roles.push_back(
            std::move(role_pin));
    }
    if (out.verifier_inputs.roles.size() !=
            nav3::kRoleCountV3) {
        Note(why, "nav3_inventory:role_count");
        out = {};
        return false;
    }
    return true;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1U)) == 0;
}

std::array<uint32_t, 8> Root8(const uint256& root)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(root.begin()[offset + 3]) << 24);
    }
    return out;
}

std::array<uint32_t, 8> Root8(const alg_hash::Digest& root)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t limb = 0; limb < root.size(); ++limb) {
        const uint64_t canonical = gf::Canonical(root[limb]);
        out[2U * limb] = static_cast<uint32_t>(canonical);
        out[2U * limb + 1U] =
            static_cast<uint32_t>(canonical >> 32);
    }
    return out;
}

std::array<uint32_t, 4> Limbs4(uint64_t value)
{
    return {
        static_cast<uint32_t>(value & 0xffffU),
        static_cast<uint32_t>((value >> 16) & 0xffffU),
        static_cast<uint32_t>((value >> 32) & 0xffffU),
        static_cast<uint32_t>((value >> 48) & 0xffffU),
    };
}

bool ValidProduct(
    const RCStage3RoleAirProduct& product,
    std::string& reason)
{
    reason.clear();
    if (!product.ok) {
        reason = "builder:" + product.note;
        return false;
    }
    if (!PowerOfTwo(product.cs.n_rows)) {
        reason = "rows";
        return false;
    }
    if (product.cs.n_columns != product.witness.size()) {
        reason = "witness_width";
        return false;
    }
    if (product.endpoints !=
        RequiredRCStage3RelationEndpoints(product.role)) {
        reason = "endpoint_order";
        return false;
    }
    if (product.endpoint_value_columns.size() !=
        product.endpoints.size()) {
        reason = "endpoint_value_columns";
        return false;
    }
    if (product.endpoint_committed_roots.size() !=
        product.endpoints.size()) {
        reason = "endpoint_roots";
        return false;
    }
    for (const auto& column : product.witness) {
        if (column.size() != product.cs.n_rows) {
            reason = "witness_rows";
            return false;
        }
    }
    for (uint32_t column : product.endpoint_value_columns) {
        if (column >= product.cs.n_columns) {
            reason = "endpoint_column_range";
            return false;
        }
    }
    uint32_t first_row = 0;
    std::string family;
    const uint32_t violations =
        air_recurse::CountWitnessViolationsOnH(
            product.cs, product.witness,
            &first_row, &family);
    if (violations != 0) {
        reason =
            "witness_violation:" + family +
            ":row=" + std::to_string(first_row);
        return false;
    }
    return true;
}

uint256 CapturedEpisodeLeafStatement(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& episode_digest,
    const std::vector<uint256>& round_roots)
{
    const uint256 header_commitment =
        RCStage3HeaderCommitment(block);
    const uint256 params_commitment =
        RCStage3ParamsCommitment(
            params, height,
            RCStage3StatementKind::Episode);
    if (header_commitment.IsNull() ||
        params_commitment.IsNull() ||
        episode_digest.IsNull() ||
        round_roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_CAPTURED_EPISODE_LEAF_STATEMENT_V1"}
         << header_commitment
         << params_commitment
         << episode_digest
         << static_cast<uint64_t>(round_roots.size());
    for (const uint256& root : round_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetSHA256();
}

uint256 CapturedEpisodeLayerShapeRoot(
    const uint256& statement_commitment,
    const RCGkrLayerSpec& spec,
    uint32_t ordinal)
{
    if (statement_commitment.IsNull() ||
        spec.m == 0 || spec.n == 0 || spec.k == 0 ||
        spec.n % kRCMxBlockLen != 0) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_CAPTURED_EPISODE_LAYER_SHAPE_V1"}
         << statement_commitment
         << ordinal
         << static_cast<uint32_t>(spec.kind)
         << spec.round
         << spec.layer
         << spec.m << spec.n << spec.k
         << spec.a.first_column
         << spec.a.n_chunks
         << spec.a.transpose
         << spec.b.first_column
         << spec.b.n_chunks
         << spec.b.transpose
         << spec.y_first_column
         << spec.y_chunks
         << spec.out_first_column
         << spec.out_chunks
         << spec.residual_first_column;
    return hash.GetSHA256();
}

bool BuildCapturedEpisodeLeafInventory(
    const ProductionParentBuildInputV1& input,
    const RCEpisodeParams& episode,
    const uint256& episode_digest,
    const std::vector<uint256>& round_roots,
    hierarchy::ShardOrdinalManifestV1& hierarchy_manifest,
    std::vector<semantic_source::LeafReceiptV1>& receipts,
    std::vector<
        hierarchy::RetainedSplitRapHierarchyNodeV2>& nodes,
    uint32_t& layer_count,
    uint64_t& tile_count,
    std::string* why)
{
    hierarchy_manifest = {};
    receipts.clear();
    nodes.clear();
    layer_count = 0;
    tile_count = 0;

    const auto layout = RCGkrTraceLayout(episode);
    const auto& captured_layers =
        input.episode_capture->LayerWitnesses();
    const auto& captured_extract =
        input.episode_capture->ExtractInputs();
    if (layout.layers.empty() ||
        captured_layers.size() != layout.layers.size()) {
        Note(why, "captured_inventory_source_shape");
        return false;
    }

    const uint256 statement_commitment =
        CapturedEpisodeLeafStatement(
            *input.solved_block, *input.params,
            input.height, episode_digest, round_roots);
    if (statement_commitment.IsNull()) {
        Note(why, "captured_inventory_public_statement");
        return false;
    }

    RCStage3EpisodeExtractProduct extract;
    extract.expected_tiles = captured_extract.size();
    extract.tiles.resize(captured_extract.size());
    std::vector<hierarchy::ShardOrdinalEntryV1>
        entries;
    std::string leaf_why;
    uint64_t gemm_cursor = 0;
    uint64_t tile_cursor = 0;
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size();
         ++ordinal) {
        const auto& layer_spec =
            layout.layers[ordinal];
        const auto& captured_layer =
            captured_layers[ordinal];
        if (layer_spec.n == 0 ||
            layer_spec.n % kRCMxBlockLen != 0) {
            Note(
                why,
                "captured_inventory_layer_tile_shape_" +
                    std::to_string(ordinal));
            return false;
        }
        const uint64_t gemm_cells =
            uint64_t{layer_spec.m} * layer_spec.n;
        const uint64_t layer_tiles =
            uint64_t{layer_spec.m} *
            (layer_spec.n / kRCMxBlockLen);
        if (layer_tiles == 0 ||
            gemm_cells >
                std::numeric_limits<uint64_t>::max() -
                    gemm_cursor ||
            layer_tiles >
                std::numeric_limits<uint64_t>::max() -
                    tile_cursor ||
            captured_layer.operand_a.size() !=
                uint64_t{layer_spec.m} * layer_spec.k ||
            captured_layer.operand_b.size() !=
                uint64_t{layer_spec.k} * layer_spec.n ||
            captured_layer.gemm_y.size() != gemm_cells ||
            (!captured_layer.residual.empty() &&
             captured_layer.residual.size() !=
                 gemm_cells) ||
            tile_cursor + layer_tiles >
                captured_extract.size()) {
            Note(
                why,
                "captured_inventory_layer_shape_" +
                    std::to_string(ordinal));
            return false;
        }

        const uint256 shape_root =
            CapturedEpisodeLayerShapeRoot(
                statement_commitment,
                layer_spec, ordinal);
        if (shape_root.IsNull()) {
            Note(
                why,
                "captured_inventory_shape_root_" +
                    std::to_string(ordinal));
            return false;
        }

        RCStage3GemmExtractLayerManifest spec;
        spec.ordinal = ordinal;
        spec.kind = layer_spec.kind;
        spec.round = layer_spec.round;
        spec.layer = layer_spec.layer;
        spec.m = layer_spec.m;
        spec.n = layer_spec.n;
        spec.k = layer_spec.k;
        spec.a = layer_spec.a;
        spec.b = layer_spec.b;
        spec.y_first_column =
            layer_spec.y_first_column;
        spec.y_chunks = layer_spec.y_chunks;
        spec.out_first_column =
            layer_spec.out_first_column;
        spec.out_chunks = layer_spec.out_chunks;
        spec.residual_first_column =
            layer_spec.residual_first_column;
        spec.gemm_cell_begin = gemm_cursor;
        spec.gemm_cell_count = gemm_cells;
        spec.extract_tile_begin = tile_cursor;
        spec.extract_tile_count = layer_tiles;

        semantic_source::LayerShapeV1 shape;
        if (!semantic_source::BuildLayerShapeV1(
                statement_commitment, shape_root,
                spec, shape, &leaf_why)) {
            Note(
                why,
                "captured_inventory_shape_" +
                    std::to_string(ordinal) + ":" +
                    leaf_why);
            return false;
        }

        RCStage3EpisodeGemmLayerProduct layer;
        layer.layer_ordinal = ordinal;
        layer.operand_a =
            captured_layer.operand_a;
        layer.operand_b =
            captured_layer.operand_b;
        layer.gemm_y = captured_layer.gemm_y;
        layer.residual =
            captured_layer.residual;
        for (uint64_t local_tile = 0;
             local_tile < layer_tiles;
             ++local_tile) {
            const uint64_t global_tile =
                tile_cursor + local_tile;
            auto& tile = extract.tiles[global_tile];
            tile.global_tile = global_tile;
            tile.layer_ordinal = ordinal;
            tile.layer_tile_index = local_tile;
            tile.input =
                captured_extract[global_tile];
        }

        semantic_source::LayerBundleV1 bundle;
        if (!semantic_source::ProveLayerBundleV1(
                shape, layer, extract,
                tile_cursor, bundle, &leaf_why)) {
            Note(
                why,
                "captured_inventory_prove_layer_" +
                    std::to_string(ordinal) + ":" +
                    leaf_why);
            return false;
        }
        const auto audit =
            semantic_source::VerifyLayerBundleV1(
                shape, bundle);
        if (!audit.accepted ||
            !audit.source_terminal_proof_owned ||
            !audit.exact_address_partition ||
            audit.verified_tiles != layer_tiles) {
            Note(
                why,
                "captured_inventory_audit_layer_" +
                    std::to_string(ordinal) + ":" +
                    audit.note);
            return false;
        }
        for (auto& receipt : bundle.leaves) {
            if (entries.size() >=
                std::numeric_limits<uint32_t>::max()) {
                Note(
                    why,
                    "captured_inventory_shard_count");
                return false;
            }
            entries.push_back({
                .shard_ordinal =
                    static_cast<uint32_t>(
                        entries.size()),
                .first_ordinal =
                    tile_cursor +
                    receipt.manifest.tile_begin,
                .ordinal_count =
                    receipt.manifest.tile_count,
                .statement_root =
                    receipt.manifest
                        .manifest_commitment,
            });
            receipts.push_back(std::move(receipt));
        }
        gemm_cursor += gemm_cells;
        tile_cursor += layer_tiles;
    }
    if (tile_cursor == 0 ||
        tile_cursor != captured_extract.size() ||
        receipts.empty() ||
        entries.size() != receipts.size()) {
        Note(why, "captured_inventory_exact_coverage");
        return false;
    }

    hierarchy_manifest =
        hierarchy::BuildShardOrdinalManifestV1(
            tile_cursor, entries);
    if (!hierarchy::ValidateShardOrdinalManifestV1(
            hierarchy_manifest, &leaf_why)) {
        receipts.clear();
        Note(
            why,
            "captured_inventory_hierarchy_manifest:" +
                leaf_why);
        return false;
    }

    nodes.reserve(receipts.size());
    std::vector<AirCS> expected_css;
    expected_css.reserve(receipts.size());
    std::vector<std::vector<uint32_t>>
        expected_base_column_indices;
    expected_base_column_indices.reserve(
        receipts.size());
    std::vector<uint256> expected_fs_seeds;
    expected_fs_seeds.reserve(receipts.size());
    for (uint32_t shard = 0;
         shard < receipts.size();
         ++shard) {
        const auto verification_input =
            semantic_source::
                BuildUnifiedSameParentCtlVerificationInputV2(
                    receipts[shard].manifest,
                    receipts[shard]
                        .unified_same_parent_ctl_join);
        if (!verification_input.valid ||
            verification_input.proof == nullptr) {
            receipts.clear();
            nodes.clear();
            Note(
                why,
                "captured_inventory_verification_input_" +
                    std::to_string(shard) + ":" +
                    verification_input.note);
            return false;
        }
        const auto& input_cs =
            verification_input.expected_cs;
        const auto coverage =
            hierarchy::BuildShardOrdinalCoverageV1(
                hierarchy_manifest, shard, 1);
        nodes.push_back(
            hierarchy::
                RetainVerifiedSplitRapHierarchyNodeV2(
                hierarchy_manifest, coverage,
                /*level=*/1,
                /*node_ordinal=*/shard,
                input_cs,
                *verification_input.proof,
                verification_input
                    .expected_base_column_indices,
                verification_input.public_fs_seed));
        if (!nodes.back().valid ||
            !hierarchy::
                ValidateRetainedSplitRapHierarchyNodeV2(
                hierarchy_manifest, input_cs,
                verification_input
                    .expected_base_column_indices,
                verification_input.public_fs_seed,
                nodes.back(), &leaf_why)) {
            receipts.clear();
            nodes.clear();
            Note(
                why,
                "captured_inventory_retain_" +
                    std::to_string(shard) + ":" +
                    leaf_why);
            return false;
        }
        expected_css.push_back(input_cs);
        expected_base_column_indices.push_back(
            verification_input
                .expected_base_column_indices);
        expected_fs_seeds.push_back(
            verification_input.public_fs_seed);
    }
    if (!hierarchy::
            ValidateRetainedSplitRapHierarchyLevelV2(
            hierarchy_manifest, expected_css,
            expected_base_column_indices,
            expected_fs_seeds, nodes, &leaf_why)) {
        receipts.clear();
        nodes.clear();
        Note(
            why,
            "captured_inventory_retained_level:" +
                leaf_why);
        return false;
    }
    if (!ValidateCapturedEpisodeLeafInventoryV2(
            hierarchy_manifest, receipts,
            nodes, &leaf_why)) {
        receipts.clear();
        nodes.clear();
        Note(
            why,
            "captured_inventory_fresh_validation:" +
                leaf_why);
        return false;
    }
    layer_count =
        static_cast<uint32_t>(layout.layers.size());
    tile_count = tile_cursor;
    return true;
}

bool BuildBlockRoleProducts(
    const ProductionParentBuildInputV1& input,
    std::vector<RCStage3RoleAirProduct>& products,
    std::array<RCStage3StreamEndpointManifest, 2>&
        builder_stream_manifests,
    uint256& episode_digest,
    uint256& coupled_digest,
    uint256& composed_digest,
    hierarchy::ShardOrdinalManifestV1&
        captured_leaf_manifest,
    std::vector<semantic_source::LeafReceiptV1>&
        captured_leaf_receipts,
    std::vector<
        hierarchy::RetainedSplitRapHierarchyNodeV2>&
        captured_leaf_nodes,
    uint32_t& captured_layer_count,
    uint64_t& captured_tile_count,
    std::string* why)
{
    products.clear();
    episode_digest.SetNull();
    coupled_digest.SetNull();
    composed_digest.SetNull();
    captured_leaf_manifest = {};
    captured_leaf_receipts.clear();
    captured_leaf_nodes.clear();
    captured_layer_count = 0;
    captured_tile_count = 0;

    const CBlock& block = *input.solved_block;
    const Consensus::Params& params = *input.params;
    const RCEpisodeParams episode =
        ResolveRCEpisodeParams(params, input.height);
    if (!ValidateRCEpisodeParams(episode)) {
        Note(why, "episode_params");
        return false;
    }
    if (input.episode_capture == nullptr ||
        input.episode_capture_header_hash !=
            block.GetHash()) {
        Note(why, "winner_episode_capture_binding");
        return false;
    }
    std::string capture_why;
    if (!input.episode_capture->Complete(
            &capture_why)) {
        Note(
            why,
            "winner_episode_capture_incomplete:" +
                capture_why);
        return false;
    }

    // Consume the winner reseal's exact terminal outputs. Complete() has
    // already rebuilt each R.4.1 stream from the captured Extract outputs,
    // folded it through RoundMerkleStream, and checked the ordered root chain
    // and terminal digest. Re-entering the episode oracle here would be exact
    // replay and is forbidden for the production succinct path.
    episode_digest =
        input.episode_capture->EpisodeDigest();
    const std::vector<uint256>& round_roots =
        input.episode_capture->RoundRoots();
    if (episode_digest.IsNull() ||
        round_roots.size() != episode.rounds ||
        round_roots.empty()) {
        Note(why, "episode_capture_terminal");
        return false;
    }
    (void)input.episode_rounds;

    const RCCoupParams coupled_params =
        ResolveRCCoupParams(params);
    const RCCoupOptions coupled_options =
        ResolveRCCoupOptions(params);
    if (!ValidateRCCoupParams(coupled_params)) {
        Note(why, "coupled_params");
        return false;
    }
    if (input.coupled_capture == nullptr ||
        input.coupled_capture_header_hash !=
            block.GetHash()) {
        Note(why, "winner_coupled_capture_binding");
        return false;
    }
    if (!input.coupled_capture->Complete(
            &capture_why)) {
        Note(
            why,
            "winner_coupled_capture_incomplete:" +
                capture_why);
        return false;
    }
    const auto& coupled =
        input.coupled_capture->Receipt();
    if (!VerifyRCStage3CoupledWinnerReceiptV2(
            block, input.height, coupled_params,
            coupled_options, coupled,
            &capture_why)) {
        Note(
            why,
            "winner_coupled_capture_verify:" +
                capture_why);
        return false;
    }
    coupled_digest = coupled.coupled_digest;
    const uint256 assembled_coupled =
        AssembleCoupledEpisodeDigest(
            coupled.bank_root, coupled.barrier_roots,
            coupled_options.transcript_version);
    if (coupled_digest.IsNull() ||
        coupled_digest != assembled_coupled ||
        coupled.bank_root.IsNull() ||
        coupled.barrier_roots.empty() ||
        coupled.barriers.empty() ||
        !coupled.representative_cells
             .gemm_observed ||
        !coupled.representative_cells
             .extract_observed) {
        Note(why, "coupled_capture_terminal");
        return false;
    }

    composed_digest =
        ComputeRCStage3ComposedWorkDigest(
            block, params, input.height,
            episode_digest, coupled_digest);
    if (composed_digest.IsNull() ||
        composed_digest != block.matmul_digest ||
        UintToArith256(composed_digest) >
            UintToArith256(input.target)) {
        Note(why, "composed_digest");
        return false;
    }

    if (!BuildCapturedEpisodeLeafInventory(
            input, episode, episode_digest,
            round_roots, captured_leaf_manifest,
            captured_leaf_receipts,
            captured_leaf_nodes,
            captured_layer_count,
            captured_tile_count, why)) {
        return false;
    }

    std::vector<int8_t> round0_signed;
    if (!input.episode_capture->BuildRoundStream(
            0, round0_signed, &capture_why)) {
        Note(
            why,
            "episode_capture_round_stream:" +
                capture_why);
        return false;
    }
    std::vector<uint8_t> round0(
        round0_signed.begin(),
        round0_signed.end());
    hash_air::TileTreeManifest tile_tree;
    std::string tile_why;
    if (!hash_air::BuildTileTreeManifest(
            round0, episode.T_leaf, tile_tree,
            &tile_why) ||
        tile_tree.root != round_roots.front()) {
        Note(why, "tile_tree:" + tile_why);
        return false;
    }

    const int64_t episode_a =
        static_cast<int64_t>(round0_signed[0]);
    const int64_t episode_b =
        static_cast<int64_t>(
            round0_signed.size() > 1
                ? round0_signed[1]
                : round0_signed[0]);
    const gf::Fp3 episode_cell =
        gf::FromSigned3(episode_a);
    const int64_t coupled_a =
        static_cast<int64_t>(
            coupled.representative_cells
                .first_gemm_operand_a);
    const int64_t coupled_b =
        static_cast<int64_t>(
            coupled.representative_cells
                .first_gemm_operand_b);
    const gf::Fp3 coupled_cell =
        gf::FromSigned3(coupled_a);
    const uint64_t mix_a_value =
        static_cast<uint64_t>(
            coupled.representative_cells
                .first_extract_input_a);
    const uint64_t mix_b_value =
        static_cast<uint64_t>(
            coupled.representative_cells
                .first_extract_input_b);
    const auto mix_a = Limbs4(mix_a_value);
    const auto mix_b = Limbs4(mix_b_value);
    const uint8_t bank_nibble =
        coupled.representative_cells
            .first_bank_nibble;

    products.reserve(kRCStage3RelationClosureRoleCount);

    {
        const std::vector<gf::Fp3> openings = {
            gf::Fp3::FromFp(
                gf::FromU64(episode.rounds))};
        // seed_a/seed_b are stream VALUES, not SHA commitment roots.  The
        // canonical heavy children authenticate these exact words under their
        // endpoint-specific domains; derive the light role's root and CTL
        // value from the same manifests so the parent and child state the
        // same proposition.
        builder_stream_manifests = {
                BuildRCStage3StreamEndpointCanonicalManifest(
                    RCStage3StreamFamilyForEndpoint(
                        RCStage3RelationEndpoint::
                            EpisodeBuilderSeedChain),
                    Root8(block.seed_a), 0, 3),
                BuildRCStage3StreamEndpointCanonicalManifest(
                    RCStage3StreamFamilyForEndpoint(
                        RCStage3RelationEndpoint::
                            EpisodeBuilderOperandXof),
                    Root8(block.seed_b), 0, 3),
            };
        const std::vector<
            RCStage3StreamEndpointManifest>
            stream_manifests{
                builder_stream_manifests.begin(),
                builder_stream_manifests.end()};
        products.push_back(
            BuildRCStage3NoKernelRoleAir(
                Role::EpisodeDeterministicBuilder,
                nullptr, &openings, nullptr,
                &stream_manifests));
    }
    products.push_back(
        BuildRCStage3EpisodeGemmRoleAir(
            nullptr, &episode_a, &episode_b,
            &round_roots.front()));
    {
        const auto stream_cell =
            [&round0_signed](size_t index) {
                const auto& stream = round0_signed;
                return gf::FromSigned3(
                    static_cast<int64_t>(
                        stream[index % stream.size()]));
            };
        const std::vector<gf::Fp3> openings = {
            stream_cell(0), stream_cell(2),
            stream_cell(4), stream_cell(6),
        };
        const std::vector<std::array<uint32_t, 8>>
            stream_roots = {
                Root8(round_roots.front()),
            };
        products.push_back(
            BuildRCStage3NoKernelRoleAir(
                Role::EpisodeExtract, nullptr,
                &openings, &stream_roots));
    }
    products.push_back(
        BuildRCStage3EpisodeWiringRoleAir(
            nullptr, &episode_cell));
    {
        const uint256 leaf =
            tile_tree.leaf_hashes.empty()
                ? tile_tree.root
                : tile_tree.leaf_hashes.front();
        const uint256 internal =
            tile_tree.hash_nodes.empty()
                ? tile_tree.root
                : tile_tree.hash_nodes.back().digest;
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(tile_tree.commitment),
                Root8(leaf),
                Root8(internal),
                Root8(tile_tree.root),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::EpisodeTileTree, roots,
                nullptr));
    }
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(round_roots.front()),
                Root8(episode_digest),
                Root8(RCStage3HeaderCommitment(block)),
                Root8(input.target),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::EpisodeDigest, roots,
                nullptr));
    }

    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled_digest),
                Root8(coupled.bank_root),
            };
        products.push_back(
            BuildRCStage3CoupledMixedRoleAir(
                Role::CoupledBank, nullptr,
                nullptr, &bank_nibble, &roots));
    }
    products.push_back(
        BuildRCStage3CoupledGemmRoleAir(
            nullptr, &coupled_a, &coupled_b,
            &coupled.barrier_roots.front()));
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled.barrier_roots.front()),
            };
        products.push_back(
            BuildRCStage3CoupledMixedRoleAir(
                Role::CoupledExchange, nullptr,
                &coupled_cell, nullptr, &roots));
    }
    products.push_back(
        BuildRCStage3CoupledPermutationRoleAir(
            coupled_cell, 0, 3, nullptr));
    products.push_back(
        BuildRCStage3CoupledScalarRoleAir(
            Role::CoupledMix, 0, 3, nullptr,
            &mix_a, &mix_b));
    {
        const auto& representative =
            coupled.representative_cells;
        const gf::Fp3 extract_output =
            gf::FromSigned3(
                static_cast<int64_t>(
                    representative
                        .first_extract_output));
        const std::vector<gf::Fp3> openings = {
            gf::FromSigned3(
                representative
                    .first_extract_input_a),
            gf::FromSigned3(
                representative
                    .first_extract_input_b),
            gf::FromU64_3(0),
            extract_output,
        };
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(
                    coupled.barriers.front()
                        .extract_prf),
            };
        products.push_back(
            BuildRCStage3NoKernelRoleAir(
                Role::CoupledExtract, nullptr,
                &openings, &roots));
    }
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled.barrier_roots.front()),
                Root8(coupled.bank_root),
                Root8(coupled.barrier_roots.back()),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::CoupledBarrier, roots,
                nullptr));
    }
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled.bank_root),
                Root8(coupled_digest),
                Root8(coupled_digest),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::CoupledDigest, roots,
                nullptr));
    }

    const auto& order = RCStage3UnifiedRoleOrder();
    if (products.size() != order.size()) {
        Note(why, "role_count");
        return false;
    }
    for (uint32_t role = 0;
         role < products.size(); ++role) {
        std::string product_why;
        if (products[role].role != order[role]) {
            product_why = "role_order";
        } else {
            (void)ValidProduct(
                products[role], product_why);
        }
        if (!product_why.empty()) {
            Note(
                why,
                "role_product:" +
                    std::string(
                        RCStage3RelationRoleName(
                            order[role])) +
                    ":" + product_why);
            return false;
        }
    }
    return true;
}

void AddRootBankPin(
    AirCS& cs,
    uint32_t column,
    uint32_t expected)
{
    cs.constraints.push_back(
        {
            "stage3.production_endpoint_bank.root_word",
            air_quotient::AirKind::kEverywhere,
            1,
            [column, expected](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[column],
                    gf::Fp3::FromFp(
                        gf::FromU64(expected)));
            },
        });
}

void AddEndpointValueAlias(
    AirCS& cs,
    uint32_t bank_column,
    uint32_t role_column)
{
    cs.constraints.push_back(
        {
            "stage3.production_endpoint_bank.value_alias",
            air_quotient::AirKind::kFirstRow,
            1,
            [bank_column, role_column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[bank_column],
                    current[role_column]);
            },
        });
    cs.constraints.push_back(
        {
            "stage3.production_endpoint_bank.value_constant",
            air_quotient::AirKind::kTransition,
            1,
            [bank_column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>& next) {
                return gf::Sub(
                    next[bank_column],
                    current[bank_column]);
            },
        });
}

void AddSameParentFirstRowAlias(
    AirCS& cs,
    uint32_t left,
    uint32_t right,
    const char* name)
{
    cs.constraints.push_back(
        {
            name,
            air_quotient::AirKind::kFirstRow,
            1,
            [left, right](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[left],
                    current[right]);
            },
        });
}

bool AppendRecursiveReceiptEvidenceRoot(
    const semantic_intake::
        VerifiedRecursiveReceiptEvidenceV1& evidence,
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>&
        parent_columns,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    if (!evidence.valid ||
        evidence.evidence_commitment.IsNull() ||
        evidence.evidence_commitment !=
            semantic_intake::
                ComputeVerifiedRecursiveReceiptEvidenceCommitmentV1(
                    evidence) ||
        parent_cs.n_rows < 2 ||
        parent_columns.size() !=
            parent_cs.n_columns) {
        Note(why, "recursive_receipt_evidence");
        return false;
    }
    const auto words = Root8(
        evidence.evidence_commitment);
    for (uint32_t word = 0;
         word < words.size(); ++word) {
        out.recursive_receipt_evidence_root_columns[
            word] = parent_cs.n_columns++;
        parent_columns.push_back(
            std::vector<gf::Fp3>(
                parent_cs.n_rows,
                gf::Fp3::FromFp(
                    gf::FromU64(words[word]))));
        AddRootBankPin(
            parent_cs,
            out.recursive_receipt_evidence_root_columns[
                word],
            words[word]);
    }
    out.recursive_receipt_evidence_same_parent_bound =
        true;
    return true;
}

bool AppendCanonicalEndpointBank(
    const std::vector<RCStage3RoleAirProduct>& products,
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    std::vector<ProductionRolePlacementV1>& placements,
    uint32_t expected_endpoint_count,
    std::string* why)
{
    if (placements.size() != products.size() ||
        parent_cs.n_rows < 2 ||
        parent_columns.size() != parent_cs.n_columns) {
        Note(why, "endpoint_bank_parent_shape");
        return false;
    }
    uint32_t endpoint_count = 0;
    for (uint32_t role = 0;
         role < products.size(); ++role) {
        const auto& product = products[role];
        auto& placement = placements[role];
        placement.endpoints.reserve(
            product.endpoints.size());
        for (uint32_t endpoint = 0;
             endpoint < product.endpoints.size();
             ++endpoint) {
            ProductionEndpointPlacementV1 pin;
            pin.role = product.role;
            pin.endpoint = product.endpoints[endpoint];
            pin.role_ordinal = role;
            pin.endpoint_ordinal = endpoint_count;
            pin.parent_value_column =
                placement.attachment.ParentColumn(
                    product.endpoint_value_columns[
                        endpoint]);
            if (pin.parent_value_column >=
                parent_cs.n_columns) {
                Note(why, "endpoint_parent_column");
                return false;
            }

            pin.bank_value_column =
                parent_cs.n_columns++;
            const gf::Fp3 value =
                parent_columns[
                    pin.parent_value_column][0];
            parent_columns.push_back(
                std::vector<gf::Fp3>(
                    parent_cs.n_rows, value));
            AddEndpointValueAlias(
                parent_cs, pin.bank_value_column,
                pin.parent_value_column);

            pin.committed_root =
                product.endpoint_committed_roots[
                    endpoint];
            const auto root_words =
                Root8(pin.committed_root);
            for (uint32_t word = 0;
                 word < root_words.size(); ++word) {
                pin.root_word_columns[word] =
                    parent_cs.n_columns++;
                parent_columns.push_back(
                    std::vector<gf::Fp3>(
                        parent_cs.n_rows,
                        gf::Fp3::FromFp(
                            gf::FromU64(
                                root_words[word]))));
                AddRootBankPin(
                    parent_cs,
                    pin.root_word_columns[word],
                    root_words[word]);
            }
            pin.literal_value_alias = true;
            placement.endpoints.push_back(pin);
            ++endpoint_count;
        }
    }
    if (endpoint_count !=
        expected_endpoint_count) {
        Note(why, "endpoint_bank_count");
        return false;
    }
    return true;
}

bool AppendDirectBuilderStreamChildren(
    const std::array<
        RCStage3StreamEndpointManifest, 2>&
        manifests,
    const std::array<
        RCStage3StreamEndpointClosure, 2>&
        closures,
    uint32_t parent_rows,
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>&
        parent_columns,
    std::vector<ProductionRolePlacementV1>&
        placements,
    std::vector<
        ProductionDirectStreamChildPlacementV1>&
        out,
    std::string* why)
{
    if (placements.empty() ||
        placements.front().role !=
            Role::EpisodeDeterministicBuilder ||
        placements.front().endpoints.size() != 4 ||
        parent_rows < 2) {
        Note(why, "builder_direct_parent_shape");
        return false;
    }
    constexpr std::array<
        RCStage3RelationEndpoint, 2>
        endpoints{
            RCStage3RelationEndpoint::
                EpisodeBuilderSeedChain,
            RCStage3RelationEndpoint::
                EpisodeBuilderOperandXof,
        };
    out.clear();
    out.reserve(endpoints.size());
    for (uint32_t child = 0;
         child < endpoints.size(); ++child) {
        const auto& closure = closures[child];
        const auto& role_pin =
            placements.front().endpoints[
                child + 1U];
        if (!closure.ok ||
            role_pin.endpoint != endpoints[child] ||
            closure.family !=
                RCStage3StreamFamilyForEndpoint(
                    endpoints[child]) ||
            closure.child_value_export_column >=
                closure.child_cs.n_columns ||
            closure.child_output_export_base + 8U >
                closure.child_cs.n_columns) {
            Note(why, "builder_direct_child_shape");
            return false;
        }

        // The standalone child pins its own R0 commitment so a Split-RAP
        // receipt can be verified.  Horizontal composition commits one
        // different global row, so those commitment pins are intentionally
        // removed; every preprocessed value and every semantic constraint is
        // still appended and the final parent proof rebuilds one global root.
        AirCS child_cs = closure.child_cs;
        child_cs.preprocessed_roots.clear();
        child_cs.preprocessed_row_group_roots.clear();

        ProductionDirectStreamChildPlacementV1
            placed;
        placed.endpoint = endpoints[child];
        placed.manifest = manifests[child];
        placed.child_rows =
            closure.child_cs.n_rows;
        std::string compose_why;
        if (!composer::AppendChildLiftedV1(
                parent_cs, parent_columns,
                child_cs, closure.child_witness,
                parent_rows,
                static_cast<uint32_t>(
                    placements.size()) +
                    child,
                placed.attachment,
                &compose_why)) {
            Note(
                why,
                "builder_direct_child_append:" +
                    compose_why);
            return false;
        }

        placed.child_value_parent_column =
            placed.attachment.ParentColumn(
                closure
                    .child_value_export_column);
        placed.role_bank_value_column =
            role_pin.bank_value_column;
        AddSameParentFirstRowAlias(
            parent_cs,
            placed.child_value_parent_column,
            placed.role_bank_value_column,
            "stage3.production_builder_child."
            "value_same_parent_alias");
        placed.value_same_parent_aliased = true;
        for (uint32_t word = 0; word < 8;
             ++word) {
            placed.child_root_parent_columns[word] =
                placed.attachment.ParentColumn(
                    closure
                        .child_output_export_base +
                    word);
            placed.role_root_word_columns[word] =
                role_pin.root_word_columns[word];
            AddSameParentFirstRowAlias(
                parent_cs,
                placed
                    .child_root_parent_columns[
                        word],
                placed.role_root_word_columns[word],
                "stage3.production_builder_child."
                "root_same_parent_alias");
        }
        placed.root_same_parent_aliased = true;
        placed.complete_relation_same_parent =
            placed.attachment.valid &&
            placed.value_same_parent_aliased &&
            placed.root_same_parent_aliased;
        out.push_back(std::move(placed));
    }
    return out.size() == endpoints.size() &&
        std::all_of(
            out.begin(), out.end(),
            [](const auto& child) {
                return child
                    .complete_relation_same_parent;
            });
}

bool AssembleDirectBuilderParent(
    const std::vector<RCStage3RoleAirProduct>&
        products,
    const semantic_intake::
        VerifiedRecursiveReceiptEvidenceV1*
            recursive_evidence,
    const std::array<
        RCStage3StreamEndpointManifest, 2>&
        manifests,
    const std::array<
        RCStage3StreamEndpointClosure, 2>&
        closures,
    uint32_t common_rows,
    uint32_t expected_endpoint_count,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    out.cs = {};
    out.columns.clear();
    out.roles.clear();
    out.direct_builder_stream_children.clear();
    out.recursive_receipt_evidence_root_columns = {};
    out.recursive_receipt_evidence_same_parent_bound =
        false;

    out.roles.reserve(products.size());
    for (uint32_t ordinal = 0;
         ordinal < products.size(); ++ordinal) {
        std::string compose_why;
        ProductionRolePlacementV1 placement;
        placement.role = products[ordinal].role;
        if (!composer::AppendChildLiftedV1(
                out.cs, out.columns,
                products[ordinal].cs,
                products[ordinal].witness,
                common_rows, ordinal,
                placement.attachment,
                &compose_why)) {
            Note(
                why,
                "role_append:" + compose_why);
            return false;
        }
        out.roles.push_back(std::move(placement));
    }
    if (!AppendCanonicalEndpointBank(
            products, out.cs, out.columns,
            out.roles, expected_endpoint_count,
            why) ||
        (recursive_evidence != nullptr &&
         !AppendRecursiveReceiptEvidenceRoot(
             *recursive_evidence,
             out.cs, out.columns, out, why)) ||
        !AppendDirectBuilderStreamChildren(
            manifests, closures, common_rows,
            out.cs, out.columns, out.roles,
            out.direct_builder_stream_children,
            why)) {
        return false;
    }
    return true;
}

std::vector<uint32_t>
DirectParentBaseColumns(
    const ProductionRelationParentCandidateV1& parent,
    const std::array<
        RCStage3StreamEndpointClosure, 2>&
        closures)
{
    std::vector<uint32_t> out;
    if (parent.direct_builder_stream_children.size() !=
        closures.size()) {
        return out;
    }
    const uint32_t ordinary_parent_columns =
        parent.direct_builder_stream_children.front()
            .attachment.column_base;
    out.reserve(
        ordinary_parent_columns + 4096U);
    for (uint32_t column = 0;
         column < ordinary_parent_columns;
         ++column) {
        out.push_back(column);
    }
    for (uint32_t child = 0;
         child < closures.size(); ++child) {
        const auto& attachment =
            parent.direct_builder_stream_children[
                child].attachment;
        const auto& closure = closures[child];
        const uint32_t semantic_columns =
            closure.child_cs.n_columns;
        std::vector<uint32_t> local_base;
        for (const auto& pin :
             closure.child_cs
                 .preprocessed_row_group_roots) {
            if (pin.version == 1 &&
                pin.role ==
                    air_quotient::
                        AirPreprocessedRowGroupRole::
                            kR0) {
                local_base = pin.ordered_columns;
                break;
            }
        }
        // The three stream-word address selectors are appended after the
        // standalone R0 was committed.  They are fixed schedule columns and
        // belong to the global parent's pre-challenge group.
        if (semantic_columns < 7U) {
            return {};
        }
        const uint32_t value_selector_base =
            semantic_columns - 3U;
        for (uint32_t selector = 0;
             selector < 3; ++selector) {
            local_base.push_back(
                value_selector_base + selector);
        }
        std::sort(
            local_base.begin(), local_base.end());
        local_base.erase(
            std::unique(
                local_base.begin(),
                local_base.end()),
            local_base.end());
        for (uint32_t local : local_base) {
            if (local >= semantic_columns) {
                return {};
            }
            out.push_back(
                attachment.ParentColumn(local));
            out.push_back(
                attachment.ParentColumn(
                    semantic_columns + local));
        }
        // AppendChildLiftedV1 owns five fixed selectors after ordinary and
        // wrap columns.
        for (uint32_t selector = 0;
             selector < 5; ++selector) {
            out.push_back(
                attachment.ParentColumn(
                    2U * semantic_columns +
                    selector));
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(
        std::unique(out.begin(), out.end()),
        out.end());
    return out;
}

} // namespace

const char* ProductionParentBuildStatusNameV1(
    ProductionParentBuildStatusV1 status)
{
    switch (status) {
    case ProductionParentBuildStatusV1::NotRequired:
        return "not_required";
    case ProductionParentBuildStatusV1::InvalidRequest:
        return "invalid_request";
    case ProductionParentBuildStatusV1::UnsupportedStatement:
        return "unsupported_statement";
    case ProductionParentBuildStatusV1::ProgramRegistryUnavailable:
        return "program_registry_unavailable";
    case ProductionParentBuildStatusV1::CompleteRelationParentUnavailable:
        return "complete_relation_parent_unavailable";
    case ProductionParentBuildStatusV1::Built:
        return "built";
    }
    return "unknown";
}

bool ValidateCapturedEpisodeLeafInventoryV2(
    const hierarchy::ShardOrdinalManifestV1&
        manifest,
    const std::vector<
        semantic_source::LeafReceiptV1>& receipts,
    const std::vector<
        hierarchy::RetainedSplitRapHierarchyNodeV2>&
        nodes,
    std::string* why)
{
    if (!hierarchy::ValidateShardOrdinalManifestV1(
            manifest, why) ||
        receipts.empty() ||
        receipts.size() != nodes.size() ||
        receipts.size() != manifest.entries.size()) {
        Note(why, "captured_inventory_validate_shape");
        return false;
    }
    std::vector<AirCS> expected_css;
    std::vector<std::vector<uint32_t>>
        expected_base_indices;
    std::vector<uint256> expected_fs_seeds;
    expected_css.reserve(receipts.size());
    expected_base_indices.reserve(receipts.size());
    expected_fs_seeds.reserve(receipts.size());
    for (uint32_t shard = 0;
         shard < receipts.size(); ++shard) {
        const auto& receipt = receipts[shard];
        const auto& entry = manifest.entries[shard];
        if (entry.shard_ordinal != shard ||
            entry.statement_root !=
                receipt.manifest
                    .manifest_commitment) {
            Note(
                why,
                "captured_inventory_validate_entry_" +
                    std::to_string(shard));
            return false;
        }
        std::string detail;
        if (!semantic_source::VerifyLeafV1(
                receipt.manifest.shape,
                receipt.manifest.tile_begin,
                receipt.manifest.tile_count,
                receipt, &detail)) {
            Note(
                why,
                "captured_inventory_validate_leaf_" +
                    std::to_string(shard) + ":" +
                    detail);
            return false;
        }
        const auto input =
            semantic_source::
                BuildUnifiedSameParentCtlVerificationInputV2(
                    receipt.manifest,
                    receipt
                        .unified_same_parent_ctl_join);
        if (!input.valid ||
            input.proof == nullptr) {
            Note(
                why,
                "captured_inventory_validate_input_" +
                    std::to_string(shard) + ":" +
                    input.note);
            return false;
        }
        std::vector<unsigned char> receipt_proof_bytes;
        if (air_quotient::
                SerializeAirQuotientSplitRapRowsProof(
                    *input.proof,
                    receipt_proof_bytes) == 0 ||
            receipt_proof_bytes.empty() ||
            receipt_proof_bytes !=
                nodes[shard].proof_bytes) {
            Note(
                why,
                "captured_inventory_validate_proof_alias_" +
                    std::to_string(shard));
            return false;
        }
        const auto expected_coverage =
            hierarchy::BuildShardOrdinalCoverageV1(
                manifest, shard, 1);
        if (nodes[shard].coverage !=
                expected_coverage ||
            !hierarchy::
                ValidateRetainedSplitRapHierarchyNodeV2(
                    manifest, input.expected_cs,
                    input.expected_base_column_indices,
                    input.public_fs_seed,
                    nodes[shard], &detail)) {
            Note(
                why,
                "captured_inventory_validate_node_" +
                    std::to_string(shard) + ":" +
                    detail);
            return false;
        }
        expected_css.push_back(input.expected_cs);
        expected_base_indices.push_back(
            input.expected_base_column_indices);
        expected_fs_seeds.push_back(
            input.public_fs_seed);
    }
    if (!hierarchy::
            ValidateRetainedSplitRapHierarchyLevelV2(
                manifest, expected_css,
                expected_base_indices,
                expected_fs_seeds, nodes, why)) {
        return false;
    }
    return true;
}

bool BuildDirectBuilderStreamParentCanaryV1(
    const std::array<
        RCStage3StreamEndpointManifest, 2>&
        manifests,
    const uint256& public_fs_seed,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    out = {};
    if (public_fs_seed.IsNull()) {
        Note(why, "builder_canary_seed");
        return false;
    }
    const std::vector<gf::Fp3> openings{
        gf::Fp3::FromFp(gf::FromU64(1))};
    const std::vector<
        RCStage3StreamEndpointManifest>
        stream_manifests{
            manifests.begin(), manifests.end()};
    std::vector<RCStage3RoleAirProduct>
        products;
    products.push_back(
        BuildRCStage3NoKernelRoleAir(
            Role::EpisodeDeterministicBuilder,
            why, &openings, nullptr,
            &stream_manifests));
    if (!products.front().ok) {
        Note(why, "builder_canary_role");
        return false;
    }

    constexpr std::array<
        RCStage3RelationEndpoint, 2>
        endpoints{
            RCStage3RelationEndpoint::
                EpisodeBuilderSeedChain,
            RCStage3RelationEndpoint::
                EpisodeBuilderOperandXof,
        };
    std::array<
        RCStage3StreamEndpointClosure, 2>
        closures;
    uint32_t common_rows =
        products.front().cs.n_rows;
    for (uint32_t child = 0;
         child < closures.size(); ++child) {
        closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    endpoints[child]),
                manifests[child], public_fs_seed,
                nullptr, false);
        if (!closures[child].ok) {
            Note(
                why,
                "builder_canary_child:" +
                    closures[child].note);
            return false;
        }
        common_rows =
            std::max(
                common_rows,
                closures[child].child_cs.n_rows);
    }
    if (!PowerOfTwo(common_rows) ||
        !AssembleDirectBuilderParent(
            products, nullptr, manifests, closures,
            common_rows, 4U, out, why)) {
        return false;
    }
    const std::vector<uint32_t> base_columns =
        DirectParentBaseColumns(out, closures);
    std::string base_why;
    const uint256 base_root =
        air_quotient::
            AirQuotientTwoEpochBaseRowCommitment(
                out.cs, out.columns,
                base_columns, &base_why);
    if (base_columns.empty() ||
        base_root.IsNull()) {
        Note(
            why,
            "builder_canary_base:" + base_why);
        return false;
    }
    for (uint32_t child = 0;
         child < closures.size(); ++child) {
        closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    endpoints[child]),
                manifests[child], public_fs_seed,
                nullptr, false, base_root);
        if (!closures[child].ok) {
            Note(
                why,
                "builder_canary_child_rebuild:" +
                    closures[child].note);
            return false;
        }
    }
    if (!AssembleDirectBuilderParent(
            products, nullptr, manifests, closures,
            common_rows, 4U, out, why)) {
        return false;
    }
    out.direct_parent_base_column_indices =
        DirectParentBaseColumns(out, closures);
    if (out.direct_parent_base_column_indices !=
        base_columns) {
        Note(why, "builder_canary_base_columns_drift");
        return false;
    }
    out.direct_parent_base_row_root = base_root;
    out.direct_builder_public_fs_seed =
        public_fs_seed;
    out.cs.preprocessed_row_group_roots.push_back(
        {
            .version = 1,
            .role =
                air_quotient::
                    AirPreprocessedRowGroupRole::kR0,
            .ordered_columns =
                out.direct_parent_base_column_indices,
            .root =
                out.direct_parent_base_row_root,
        });
    out.endpoint_count = 4;
    out.all_endpoint_cells_literal = true;
    out.builder_stream_relations_same_parent =
        out.direct_builder_stream_children.size() ==
            2U &&
        std::all_of(
            out.direct_builder_stream_children.begin(),
            out.direct_builder_stream_children.end(),
            [](const auto& child) {
                return child
                    .complete_relation_same_parent;
            });
    out.witness_violations =
        air_recurse::CountWitnessViolationsOnH(
            out.cs, out.columns);
    out.local_parent_valid =
        out.builder_stream_relations_same_parent &&
        out.witness_violations == 0;
    out.recursive_semantic_closure_complete =
        false;
    out.production_authority = false;
    out.note =
        out.local_parent_valid
        ? "stage3:normalized_production_parent_builder:"
          "bounded_direct_builder_parent_valid"
        : "stage3:normalized_production_parent_builder:"
          "bounded_direct_builder_parent_invalid";
    if (!out.local_parent_valid) {
        Note(why, "builder_canary_invalid");
        return false;
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildRelationParentCandidateForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    out = {};
    if (input.version !=
            kProductionParentBuildInputVersionV1 ||
        input.solved_block == nullptr ||
        input.params == nullptr ||
        input.height < 0 ||
        input.target.IsNull()) {
        Note(why, "request");
        return false;
    }
    const auto statement =
        RequiredRCStage3Statement(
            *input.params, input.height);
    if (!statement.has_value() ||
        *statement != RCStage3StatementKind::Composed) {
        Note(why, "composed_statement_required");
        return false;
    }

    std::vector<RCStage3RoleAirProduct> products;
    std::array<
        RCStage3StreamEndpointManifest, 2>
        builder_stream_manifests;
    if (!BuildBlockRoleProducts(
            input, products,
            builder_stream_manifests,
            out.episode_digest,
            out.coupled_digest, out.composed_digest,
            out.captured_episode_leaf_manifest,
            out.captured_episode_leaf_receipts,
            out.captured_episode_leaf_nodes,
            out.captured_episode_layer_count,
            out.captured_episode_tile_count,
            why)) {
        return false;
    }
    out.winner_episode_capture_bound = true;
    out.episode_witness_replay_avoided = true;
    out.winner_coupled_capture_bound = true;
    out.coupled_witness_replay_avoided = true;
    out.captured_episode_leaf_inventory_verified =
        out.captured_episode_layer_count != 0 &&
        out.captured_episode_tile_count != 0 &&
        out.captured_episode_leaf_receipts.size() ==
            out.captured_episode_leaf_nodes.size() &&
        out.captured_episode_leaf_manifest
            .total_ordinals ==
            out.captured_episode_tile_count &&
        out.captured_episode_leaf_manifest.entries.size() ==
            out.captured_episode_leaf_nodes.size() &&
        std::all_of(
            out.captured_episode_leaf_nodes.begin(),
            out.captured_episode_leaf_nodes.end(),
            [](const auto& node) {
                return node.valid &&
                    node.proof_retained &&
                    node.native_proof_verified &&
                    node.cryptographic_child;
            });

    // Build actual ordinary role/link receipts and their retained normalized
    // parent, then independently rebuild and verify every expected manifest,
    // child order, receipt commitment and parent proof.  Missing heavy stream
    // children remain explicit residual endpoints: they are not synthesized
    // from the local 52-cell representative parent.
    const std::vector<
        semantic_intake::exports::StreamChildArtifactV1>
        semantic_stream_children;
    const semantic_intake::ProofV1 semantic_proof =
        semantic_intake::ProveV1(
            products, semantic_stream_children,
            /*prove_parent=*/true);
    std::string evidence_why;
    if (!semantic_proof.construction_valid ||
        !semantic_intake::
            BuildVerifiedRecursiveReceiptEvidenceV1(
                products, semantic_stream_children,
                semantic_proof,
                out.recursive_receipt_evidence,
                &evidence_why)) {
        Note(
            why,
            "recursive_receipt_evidence:" +
                (evidence_why.empty()
                     ? semantic_proof.note
                     : evidence_why));
        return false;
    }
    out.recursive_receipt_evidence_rebuilt = true;
    out.recursive_receipt_role_audit =
        RoleAuditFromVerifiedEvidence(
            out.recursive_receipt_evidence);

    out.direct_builder_public_fs_seed =
        input.solved_block->GetHash();
    if (out.direct_builder_public_fs_seed.IsNull()) {
        Note(why, "builder_direct_public_seed");
        return false;
    }
    std::array<
        RCStage3StreamEndpointClosure, 2>
        builder_stream_closures;
    constexpr std::array<
        RCStage3RelationEndpoint, 2>
        builder_stream_endpoints{
            RCStage3RelationEndpoint::
                EpisodeBuilderSeedChain,
            RCStage3RelationEndpoint::
                EpisodeBuilderOperandXof,
        };
    for (uint32_t child = 0;
         child < builder_stream_closures.size();
         ++child) {
        builder_stream_closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    builder_stream_endpoints[child]),
                builder_stream_manifests[child],
                out.direct_builder_public_fs_seed,
                nullptr,
                /*run_cs_checks=*/false);
        if (!builder_stream_closures[child].ok) {
            Note(
                why,
                "builder_direct_child:" +
                    builder_stream_closures[child]
                        .note);
            return false;
        }
    }

    uint32_t common_rows = 0;
    for (const auto& product : products) {
        common_rows =
            std::max(common_rows, product.cs.n_rows);
    }
    for (const auto& closure :
         builder_stream_closures) {
        common_rows =
            std::max(
                common_rows,
                closure.child_cs.n_rows);
    }
    if (!PowerOfTwo(common_rows)) {
        Note(why, "common_rows");
        return false;
    }

    // Assemble once to retain the exact global pre-challenge group. Rebuild
    // both SHA children from that parent-owned R0 root, then assemble the
    // final parent with those derived CTL challenges. This prevents a prover
    // from choosing the heavy-child witness after seeing its LogUp challenge.
    if (!AssembleDirectBuilderParent(
            products,
            &out.recursive_receipt_evidence,
            builder_stream_manifests,
            builder_stream_closures,
            common_rows,
            kRCStage3RelationClosureEndpointCount,
            out,
            why)) {
        return false;
    }
    const std::vector<uint32_t>
        parent_base_columns =
            DirectParentBaseColumns(
                out, builder_stream_closures);
    if (parent_base_columns.empty()) {
        Note(why, "builder_direct_parent_base_columns");
        return false;
    }
    std::string base_why;
    const uint256 parent_base_root =
        air_quotient::
            AirQuotientTwoEpochBaseRowCommitment(
                out.cs, out.columns,
                parent_base_columns, &base_why);
    if (parent_base_root.IsNull()) {
        Note(
            why,
            "builder_direct_parent_base_root:" +
                base_why);
        return false;
    }
    for (uint32_t child = 0;
         child < builder_stream_closures.size();
         ++child) {
        builder_stream_closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    builder_stream_endpoints[child]),
                builder_stream_manifests[child],
                out.direct_builder_public_fs_seed,
                nullptr,
                /*run_cs_checks=*/false,
                parent_base_root);
        if (!builder_stream_closures[child].ok) {
            Note(
                why,
                "builder_direct_child_rebuild:" +
                    builder_stream_closures[child]
                        .note);
            return false;
        }
    }
    if (!AssembleDirectBuilderParent(
            products,
            &out.recursive_receipt_evidence,
            builder_stream_manifests,
            builder_stream_closures,
            common_rows,
            kRCStage3RelationClosureEndpointCount,
            out, why)) {
        return false;
    }
    out.direct_parent_base_column_indices =
        DirectParentBaseColumns(
            out, builder_stream_closures);
    if (out.direct_parent_base_column_indices !=
            parent_base_columns ||
        air_quotient::
            AirQuotientTwoEpochBaseRowCommitment(
                out.cs, out.columns,
                out.direct_parent_base_column_indices,
                &base_why) != parent_base_root) {
        Note(why, "builder_direct_parent_base_drift");
        return false;
    }
    out.direct_parent_base_row_root =
        parent_base_root;
    out.cs.preprocessed_row_group_roots.push_back(
        {
            .version = 1,
            .role =
                air_quotient::
                    AirPreprocessedRowGroupRole::kR0,
            .ordered_columns =
                out.direct_parent_base_column_indices,
            .root =
                out.direct_parent_base_row_root,
        });
    out.builder_stream_relations_same_parent =
        out.direct_builder_stream_children.size() ==
            2U &&
        std::all_of(
            out.direct_builder_stream_children.begin(),
            out.direct_builder_stream_children.end(),
            [](const auto& child) {
                return child
                    .complete_relation_same_parent;
            });

    out.endpoint_count = 0;
    out.exact_role_order =
        out.roles.size() ==
        RCStage3UnifiedRoleOrder().size();
    out.exact_endpoint_order =
        out.exact_role_order;
    out.all_endpoint_cells_literal =
        out.exact_role_order;
    for (uint32_t role = 0;
         role < out.roles.size(); ++role) {
        const auto& placement = out.roles[role];
        if (placement.role !=
            RCStage3UnifiedRoleOrder()[role] ||
            placement.endpoints.size() !=
                RequiredRCStage3RelationEndpoints(
                    placement.role).size()) {
            out.exact_role_order = false;
            out.exact_endpoint_order = false;
        }
        for (uint32_t endpoint = 0;
             endpoint <
                 placement.endpoints.size();
             ++endpoint) {
            const auto& pin =
                placement.endpoints[endpoint];
            if (pin.endpoint !=
                    RequiredRCStage3RelationEndpoints(
                        placement.role)[endpoint] ||
                pin.endpoint_ordinal !=
                    out.endpoint_count) {
                out.exact_endpoint_order = false;
            }
            out.all_endpoint_cells_literal =
                out.all_endpoint_cells_literal &&
                pin.literal_value_alias;
            ++out.endpoint_count;
        }
    }

    out.witness_violations =
        air_recurse::CountWitnessViolationsOnH(
            out.cs, out.columns);
    out.local_parent_valid =
        out.exact_role_order &&
        out.exact_endpoint_order &&
        out.endpoint_count ==
            kRCStage3RelationClosureEndpointCount &&
        out.all_endpoint_cells_literal &&
        out.winner_episode_capture_bound &&
        out.episode_witness_replay_avoided &&
        out.winner_coupled_capture_bound &&
        out.coupled_witness_replay_avoided &&
        out.captured_episode_leaf_inventory_verified &&
        out.recursive_receipt_evidence.valid &&
        out.recursive_receipt_evidence_rebuilt &&
        out
            .recursive_receipt_evidence_same_parent_bound &&
        out.recursive_receipt_role_audit.size() ==
            kRCStage3RelationClosureRoleCount &&
        out.builder_stream_relations_same_parent &&
        out.witness_violations == 0;

    out.recursive_semantic_closure_complete = true;
    for (const auto& audit :
         out.recursive_receipt_role_audit) {
        if (!audit.role_complete ||
            !audit.recursive_ctl_consumption ||
            audit.proof_derived_ctl_endpoints !=
                audit.required_endpoints ||
            audit.strict_transitive_endpoints !=
                audit.required_endpoints ||
            audit.recursively_consumed_strict_endpoints !=
                audit.required_endpoints) {
            out.recursive_semantic_closure_complete =
                false;
            out.residuals.push_back(
                std::string{
                    RCStage3RelationRoleName(
                        audit.role)} +
                ":" + audit.remaining);
        }
    }
    // Leaf receipts prove local A/B/Y -> Extract-input ownership.  Upstream
    // builder/previous-Extract producer terminals close only when the winner's
    // streaming episode receipt is verified and the normalized parent
    // constrains role-export equality for every A/B/Y terminal.
    const auto streaming_receipt =
        RCStage3EpisodeStreamingReceiptStoreGet(
            input.episode_capture_header_hash);
    namespace parent_eq =
        normalized_parent_external_producer_equality;
    const parent_eq::ParentRoleExportEqualityCertificateV1*
        equality_certificate = nullptr;
    if (streaming_receipt) {
        std::vector<parent_eq::ParentExportPinV1>
            export_pins;
        std::string attach_why;
        if (parent_eq::
                BuildHostedExportPinsFromStreamingReceiptV1(
                    *streaming_receipt, export_pins,
                    &attach_why) &&
            parent_eq::AttachParentRoleExportEqualityV1(
                out.cs, out.columns, *streaming_receipt,
                export_pins,
                out.role_export_equality_certificate,
                &attach_why)) {
            out.role_export_equality_certificate_valid =
                true;
            equality_certificate =
                &out.role_export_equality_certificate;
            // Re-measure witness after appending role-export
            // root pins / aliases.
            out.witness_violations =
                air_recurse::CountWitnessViolationsOnH(
                    out.cs, out.columns);
            out.local_parent_valid =
                out.local_parent_valid &&
                out.witness_violations == 0;
        } else {
            out.role_export_equality_certificate = {};
            out.role_export_equality_certificate_valid =
                false;
            out.residuals.push_back(
                "parent_role_export_equality_attach_open:" +
                attach_why);
        }
    }
    std::string equality_why;
    const auto equality =
        parent_eq::AssessStreamingRoleExportEqualityV1(
            streaming_receipt.get(), equality_certificate,
            &equality_why);
    for (const auto& residual : equality.residuals) {
        out.residuals.push_back(residual);
    }
    if (!equality.external_producer_terminal_equality_complete) {
        out.recursive_semantic_closure_complete = false;
        if (equality.residuals.empty()) {
            out.residuals.push_back(
                "captured_episode_leaf:"
                "external_producer_terminal_equality_pending");
        }
    }
    out.production_authority =
        out.local_parent_valid &&
        out.recursive_semantic_closure_complete;
    out.note =
        out.production_authority
            ? "stage3:normalized_production_parent_builder:"
              "complete_relation_parent_candidate"
            : "stage3:normalized_production_parent_builder:"
              "local_14_role_52_endpoint_parent_valid;"
              "recursive_semantic_child_consumption_open";
    if (!out.local_parent_valid) {
        Note(why, "local_parent_invalid");
        return false;
    }
    if (why != nullptr) *why = out.note;
    return true;
}

ProductionParentBuildStatusV1 BuildForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why)
{
    out = {};
    if (input.version !=
            kProductionParentBuildInputVersionV1 ||
        input.solved_block == nullptr ||
        input.params == nullptr ||
        input.height < 0 ||
        input.target.IsNull()) {
        Note(why, "request");
        return ProductionParentBuildStatusV1::
            InvalidRequest;
    }
    const auto statement =
        RequiredRCStage3Statement(
            *input.params, input.height);
    if (!statement.has_value()) {
        Note(why, "not_required");
        return ProductionParentBuildStatusV1::
            NotRequired;
    }
    if (*statement !=
        RCStage3StatementKind::Composed) {
        Note(
            why,
            "complete_normalized_parent_requires_"
            "composed_episode_and_coupled_statement");
        return ProductionParentBuildStatusV1::
            UnsupportedStatement;
    }
    ProductionProgramConsensusPinV1 registry_pin;
    registry_pin.recursive_alg_hash_root =
        input.params
            ->hashMatMulRCStage3ProgramRegistryAlgRoot;
    registry_pin.external_sha256d_audit_root =
        input.params
            ->hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    registry_pin.registry_binding =
        input.params
            ->hashMatMulRCStage3ProgramRegistryBinding;
    std::string pin_why;
    if (!ValidateProductionProgramConsensusPinV1(
            registry_pin, &pin_why)) {
        Note(why, "program_registry:" + pin_why);
        return ProductionParentBuildStatusV1::
            ProgramRegistryUnavailable;
    }

    ProductionRelationParentCandidateV1 candidate;
    std::string candidate_why;
    if (!BuildRelationParentCandidateForSolvedBlockV1(
            input, candidate, &candidate_why)) {
        Note(why, "relation_parent:" + candidate_why);
        return ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable;
    }
    if (!candidate.production_authority) {
        // Prefer the candidate's own residual note when RoleAudit is green but
        // streaming role-export equality is still pending; otherwise keep the
        // recursive-consumption residual that currently dominates tip.
        std::string detail =
            "complete_relation_parent:"
            "local_14_role_52_endpoint_parent_built;"
            "recursive_semantic_child_consumption_open";
        if (!candidate.residuals.empty()) {
            detail.push_back(';');
            detail += candidate.residuals.front();
        } else if (!candidate_why.empty()) {
            detail.push_back(';');
            detail += candidate_why;
        }
        Note(why, detail);
        return ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable;
    }

    return ConvertProductionAuthorityCandidateToBuiltV1(
        input, candidate, out, why);
}

ProductionParentBuildStatusV1
ConvertProductionAuthorityCandidateToBuiltV1(
    const ProductionParentBuildInputV1& input,
    const ProductionRelationParentCandidateV1& candidate,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why)
{
    out = {};
    if (!candidate.production_authority ||
        !candidate.local_parent_valid) {
        Note(
            why,
            "complete_relation_parent:"
            "production_authority_or_local_parent_missing");
        return ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable;
    }
    if (input.params == nullptr) {
        Note(why, "request");
        return ProductionParentBuildStatusV1::InvalidRequest;
    }

    ProductionProgramConsensusPinV1 registry_pin;
    registry_pin.recursive_alg_hash_root =
        input.params
            ->hashMatMulRCStage3ProgramRegistryAlgRoot;
    registry_pin.external_sha256d_audit_root =
        input.params
            ->hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    registry_pin.registry_binding =
        input.params
            ->hashMatMulRCStage3ProgramRegistryBinding;
    std::string pin_why;
    if (!ValidateProductionProgramConsensusPinV1(
            registry_pin, &pin_why)) {
        Note(why, "program_registry:" + pin_why);
        return ProductionParentBuildStatusV1::
            ProgramRegistryUnavailable;
    }

    // Retain one global R0, build the independently reconstructible NAV3
    // inventory, and move the exact parent CS/columns into the executable
    // receipt consumer.
    if (!ConvertCandidateToCanonicalProductV1(
            input, candidate, registry_pin, out, why)) {
        return ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable;
    }
    Note(why, "built");
    return ProductionParentBuildStatusV1::Built;
}

} // namespace matmul::v4::rc::normalized_production_parent_builder
