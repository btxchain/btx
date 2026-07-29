// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_coupled_winner_capture.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic_source_alg.h>
#include <matmul/matmul_v4_rc_stage3_normalized_relation_receipt_consumer.h>
#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>
#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {
class RCStage3EpisodeWitnessCapture;
}

namespace matmul::v4::rc::normalized_production_parent_builder {

namespace consumer = normalized_relation_receipt_consumer;

inline constexpr uint16_t kProductionParentBuildInputVersionV1 = 1;

/**
 * Typed, immutable production build request.
 *
 * There is deliberately no callback, readiness flag, host verification bit or
 * serialized proof in this request. `episode_capture` and `coupled_capture`
 * are immutable winner-only witnesses emitted by the primary proof-aware
 * workload calls. Their accompanying keys must be the finalized header hash;
 * the builder never erases them and never accepts a capture under a different
 * header. Replaying either datacenter workload is forbidden.
 */
struct ProductionParentBuildInputV1 {
    uint16_t version{kProductionParentBuildInputVersionV1};
    const CBlock* solved_block{nullptr};
    const Consensus::Params* params{nullptr};
    int32_t height{-1};
    uint256 target{};
    const std::vector<RCRoundTranscript>* episode_rounds{nullptr};
    std::shared_ptr<const RCStage3EpisodeWitnessCapture>
        episode_capture{};
    uint256 episode_capture_header_hash{};
    std::shared_ptr<const RCStage3CoupledWinnerCaptureV1>
        coupled_capture{};
    uint256 coupled_capture_header_hash{};
};

/**
 * One literal endpoint cell in the block-derived fourteen-role parent.
 *
 * `parent_value_column` is the exact ordinary parent column occupied by the
 * role product's endpoint cell.  `root_word_columns` are eight ordinary u32
 * columns (lo32/hi32 for each of the four Goldilocks digest limbs) pinned by
 * the parent AIR to `committed_root`.  This is the canonical 52-endpoint bank;
 * no receipt-carried value or host acceptance bit substitutes for these
 * columns.
 */
struct ProductionEndpointPlacementV1 {
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    uint32_t role_ordinal{0};
    uint32_t endpoint_ordinal{0};
    uint32_t parent_value_column{0};
    uint32_t bank_value_column{0};
    std::array<uint32_t, 8> root_word_columns{};
    alg_hash::Digest committed_root{};
    bool literal_value_alias{false};
};

struct ProductionRolePlacementV1 {
    RCStage3RelationRole role{};
    stage3_air_parent_composer::ChildAttachmentV1 attachment;
    std::vector<ProductionEndpointPlacementV1> endpoints;
};

/**
 * One full SHA/XOF stream relation appended directly to the same parent as
 * its role endpoint.  The child output words and child-owned CTL value are
 * equality-constrained to the literal endpoint bank; no serialized receipt
 * or host verifier bit intervenes.
 */
struct ProductionDirectStreamChildPlacementV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3StreamEndpointManifest manifest;
    stage3_air_parent_composer::ChildAttachmentV1
        attachment;
    uint32_t child_rows{0};
    uint32_t child_value_parent_column{0};
    std::array<uint32_t, 8>
        child_root_parent_columns{};
    uint32_t role_bank_value_column{0};
    std::array<uint32_t, 8>
        role_root_word_columns{};
    bool value_same_parent_aliased{false};
    bool root_same_parent_aliased{false};
    bool complete_relation_same_parent{false};
};

/**
 * Executable local-relation candidate built from the solved block.
 *
 * `local_parent_valid` means the exact fourteen role AIRs, their real
 * block-derived witnesses, and all 52 literal endpoint aliases form one
 * satisfying parent.  It deliberately does not imply production authority:
 * `recursive_semantic_closure_complete` is computed from the live semantic
 * audit and stays false while a role defers a required child proof.
 */
struct ProductionRelationParentCandidateV1 {
    uint16_t version{kProductionParentBuildInputVersionV1};
    air_quotient::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> columns;
    std::vector<ProductionRolePlacementV1> roles;
    std::vector<ProductionDirectStreamChildPlacementV1>
        direct_builder_stream_children;
    uint256 direct_builder_public_fs_seed{};
    std::vector<uint32_t>
        direct_parent_base_column_indices;
    uint256 direct_parent_base_row_root{};
    uint256 episode_digest{};
    uint256 coupled_digest{};
    uint256 composed_digest{};
    /**
     * Canonical all-layer/all-tile proof-owned episode leaf inventory.
     * Complete LeafReceipts are retained so every SameParentCtlJoin terminal
     * remains available to the eventual external producer equality CTLs;
     * hierarchy node metadata alone is insufficient for transitive
     * provenance. The manifest partitions the complete global Extract-tile
     * ordinal interval and is the input inventory for universal arity-two
     * recursion, not a host-side acceptance summary.
     */
    recursive_hierarchy::ShardOrdinalManifestV1
        captured_episode_leaf_manifest;
    std::vector<episode_semantic_source_alg::LeafReceiptV1>
        captured_episode_leaf_receipts;
    std::vector<
        recursive_hierarchy::RetainedSplitRapHierarchyNodeV2>
        captured_episode_leaf_nodes;
    uint32_t captured_episode_layer_count{0};
    uint64_t captured_episode_tile_count{0};
    uint32_t endpoint_count{0};
    uint64_t witness_violations{UINT64_MAX};
    bool exact_role_order{false};
    bool exact_endpoint_order{false};
    bool all_endpoint_cells_literal{false};
    bool builder_stream_relations_same_parent{false};
    bool winner_episode_capture_bound{false};
    bool episode_witness_replay_avoided{false};
    bool winner_coupled_capture_bound{false};
    bool coupled_witness_replay_avoided{false};
    bool captured_episode_leaf_inventory_verified{false};
    bool local_parent_valid{false};
    bool recursive_semantic_closure_complete{false};
    bool production_authority{false};
    std::vector<std::string> residuals;
    std::string note;
};

enum class ProductionParentBuildStatusV1 : uint8_t {
    NotRequired = 0,
    InvalidRequest = 1,
    UnsupportedStatement = 2,
    ProgramRegistryUnavailable = 3,
    CompleteRelationParentUnavailable = 4,
    Built = 5,
};

[[nodiscard]] const char* ProductionParentBuildStatusNameV1(
    ProductionParentBuildStatusV1 status);

/**
 * Freshly validate the exact semantic-leaf inventory consumed by recursion.
 *
 * Every retained V2 node must be the canonical unified Split-RAP proof from
 * the corresponding LeafReceipt (not merely another valid proof for the same
 * shape), and is reverified against the receipt-derived CS/R0/FS statement.
 */
[[nodiscard]] bool
ValidateCapturedEpisodeLeafInventoryV2(
    const recursive_hierarchy::ShardOrdinalManifestV1&
        manifest,
    const std::vector<
        episode_semantic_source_alg::LeafReceiptV1>&
        receipts,
    const std::vector<
        recursive_hierarchy::RetainedSplitRapHierarchyNodeV2>&
        nodes,
    std::string* why = nullptr);

/**
 * Build the canonical episode+coupled relation parent for one solved block.
 *
 * The downstream type is already executable: once this function returns
 * Built, BuildReceiptV1 proves, serializes, decodes and verifies the exact
 * product.  Built requires the live 14-role / 52-endpoint recursive semantic
 * audit to close and the NAV3 public inventory conversion to succeed.
 */
[[nodiscard]] ProductionParentBuildStatusV1
BuildForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why = nullptr);

/**
 * Build and audit the real block-derived fourteen-role parent candidate.
 *
 * This function is useful before authority closes: unlike BuildForSolvedBlockV1
 * it returns the executable local parent even when semantic child consumption
 * is incomplete.  Its status fields are derived from the actual products and
 * live role audit; callers must never treat `local_parent_valid` as authority.
 */
[[nodiscard]] bool BuildRelationParentCandidateForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    ProductionRelationParentCandidateV1& out,
    std::string* why = nullptr);

/**
 * Bounded executable canary for the exact direct-builder composition used by
 * the full production parent.  It contains the real four-endpoint builder
 * role plus both complete SHA/XOF children, shares one global R0 precommit,
 * and exposes the same ordinary-cell value/root aliases.  The caller supplies
 * path-bounded manifests so this relation can be proved in routine tests.
 */
[[nodiscard]] bool BuildDirectBuilderStreamParentCanaryV1(
    const std::array<
        RCStage3StreamEndpointManifest, 2>& manifests,
    const uint256& public_fs_seed,
    ProductionRelationParentCandidateV1& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_production_parent_builder

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H
