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

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_STATUS_H
