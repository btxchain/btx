// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_STATUS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_STATUS_H

#include <matmul/matmul_v4_rc_stage3_coupled_semantic.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

struct RCStage3SemanticEndpointStatus {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    bool canonical_memory{false};
    bool local_relation_engine{false};
    bool exact_instance_aggregation{false};
    bool canonical_root_chain{false};
    /** The endpoint's own relation executes over its complete local input. */
    bool local_relation_complete{false};
    /** Its input/root is equality-linked to the executed producer graph. */
    bool producer_provenance_complete{false};
    /** local_relation_complete && producer_provenance_complete. */
    bool semantic_complete{false};
    bool recursively_consumed{false};
    std::string source;
    std::string remaining;

    bool operator==(const RCStage3SemanticEndpointStatus&) const = default;
};

struct RCStage3SemanticStatus {
    bool registry_exact{false};
    uint16_t registered_endpoints{0};
    uint16_t canonical_memory_endpoints{0};
    uint16_t local_relation_engines{0};
    uint16_t exact_instance_aggregations{0};
    uint16_t canonical_root_chains{0};
    uint16_t local_relation_complete_endpoints{0};
    uint16_t producer_provenance_endpoints{0};
    uint16_t semantic_complete_endpoints{0};
    uint16_t recursively_consumed_endpoints{0};
    uint16_t complete_roles{0};
    std::vector<RCStage3SemanticEndpointStatus> endpoints;
};

inline constexpr uint16_t kRCStage3SemanticClosureInventoryVersionV1 = 1;

enum RCStage3SemanticClosureBlockerV1 : uint32_t {
    kRCStage3SemanticClosureMissingLocalRelationV1 = 1U << 0,
    kRCStage3SemanticClosureMissingProducerProvenanceV1 = 1U << 1,
    kRCStage3SemanticClosureMissingProductionEqualityV1 = 1U << 2,
    kRCStage3SemanticClosureMissingNormalizedEqualityV1 = 1U << 3,
    kRCStage3SemanticClosureMissingRecursiveConsumptionV1 = 1U << 4,
};

/**
 * One verifier-declared immediate producer obligation.
 *
 * `normalized_row_tagged_equality` is deliberately stronger than a host root
 * comparison or a bounded native composition: it is true only after the
 * normalized recursive parent equality-constrains the producer and consumer
 * proof cells under the canonical role/endpoint/ordinal route.
 */
struct RCStage3SemanticClosureEdgeStatusV1 {
    RCStage3RelationEndpoint producer{};
    RCStage3RelationRole producer_role{};
    RCStage3RelationEndpoint consumer{};
    RCStage3RelationRole consumer_role{};
    bool value_equality_executable{false};
    bool bounded_composition_executable{false};
    bool production_composition_executable{false};
    bool normalized_row_tagged_equality{false};
    bool producer_strictly_complete{false};
    bool consumer_local_relation_complete{false};
    uint32_t blocker_mask{0};
    std::string construction;
    std::string remaining;

    bool operator==(
        const RCStage3SemanticClosureEdgeStatusV1&) const = default;
};

/**
 * Canonical fail-closed inventory for the complete 52-endpoint/81-edge cut.
 *
 * This object is an executable blocker report, not a proof receipt.  Its
 * validator rebuilds every endpoint, role and edge from verifier code, so a
 * caller cannot promote readiness by omitting an edge, duplicating a closed
 * edge, swapping roles, transplanting a construction label, or setting a
 * capability bit.  `authority_ready` additionally requires 52 strict
 * endpoints, 81 production equalities, 81 normalized row-tagged equalities,
 * 52 recursively consumed endpoints and 14 complete roles.
 */
struct RCStage3SemanticClosureInventoryV1 {
    uint16_t version{kRCStage3SemanticClosureInventoryVersionV1};
    bool production_mode{true};
    bool exact_registry{false};
    uint16_t registered_endpoints{0};
    uint16_t local_relation_complete_endpoints{0};
    uint16_t strict_transitive_complete_endpoints{0};
    uint16_t recursively_consumed_endpoints{0};
    uint16_t complete_roles{0};
    uint32_t registered_edges{0};
    uint32_t value_equality_edges{0};
    uint32_t bounded_composition_edges{0};
    uint32_t production_composition_edges{0};
    uint32_t normalized_row_tagged_equality_edges{0};
    std::vector<RCStage3SemanticEndpointStatus> endpoints;
    std::vector<RCStage3SemanticClosureEdgeStatusV1> edges;
    bool authority_ready{false};
    uint256 inventory_commitment{};

    bool operator==(
        const RCStage3SemanticClosureInventoryV1&) const = default;
};

/**
 * Consolidated, deterministic 52-endpoint audit. The caller supplies the
 * consensus-resolved coupled shape/challenges so no toy or maximum-budget
 * shape is silently substituted. `production_mode` also disables bounded
 * flat episode products whose audit explicitly says their streaming form is
 * incomplete.
 */
[[nodiscard]] RCStage3SemanticStatus CurrentRCStage3SemanticStatus(
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e = 0,
    bool production_mode = false);

[[nodiscard]] uint256 ComputeRCStage3SemanticClosureInventoryCommitmentV1(
    const RCStage3SemanticClosureInventoryV1& inventory);

[[nodiscard]] RCStage3SemanticClosureInventoryV1
BuildRCStage3SemanticClosureInventoryV1(
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e = 0,
    bool production_mode = true);

[[nodiscard]] bool ValidateRCStage3SemanticClosureInventoryV1(
    const RCStage3SemanticClosureInventoryV1& inventory,
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e = 0,
    bool production_mode = true,
    std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_STATUS_H
