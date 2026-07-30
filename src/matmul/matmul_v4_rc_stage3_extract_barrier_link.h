// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_BARRIER_LINK_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_BARRIER_LINK_H

#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3ExtractBarrierLinkVersion = 1;

/**
 * Exact producer pin for relation endpoint 47.
 *
 * `extract_output_block_roots[i]` is the proof-owned kColOut root of the
 * ordered CoupledExtractOutput shard i.  The verifier independently embeds
 * the corresponding 32 raw two's-complement bytes from the typed barrier
 * manifest as signed Fp3 values and recomputes that root.  Thus this is a
 * vector equality product, not equality between two claimed aggregate roots.
 */
struct RCStage3ExtractBarrierLinkPin {
    uint16_t version{kRCStage3ExtractBarrierLinkVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint64_t extract_instances{0};
    uint64_t barriers{0};
    uint64_t state_bytes_per_barrier{0};
    uint64_t total_state_bytes{0};
    uint32_t extract_relation_rows{0};
    uint32_t extract_n_coeffs{0};
    uint256 extract_bundle_commitment{};
    std::vector<uint256> barrier_manifest_commitments;
    std::vector<uint256> barrier_input_memory_roots;
    std::vector<uint256> extract_output_block_roots;
    uint256 link_commitment{};

    bool operator==(const RCStage3ExtractBarrierLinkPin&) const = default;
};

struct RCStage3ExtractBarrierLinkExecution {
    RCStage3CoupledSemanticFlatBundle extract_outputs;
    std::vector<RCStage3CoupledBarrierEndpointExecution> barriers;
    RCStage3ExtractBarrierLinkPin pin;
};

struct RCStage3ExtractBarrierLinkAudit {
    uint64_t expected_extract_instances{0};
    uint64_t expected_barriers{0};
    uint64_t expected_total_state_bytes{0};
    bool consensus_shape_resolved{false};
    bool exact_extract_order_enforced{false};
    bool exact_barrier_order_enforced{false};
    bool signed_byte_embedding_bound{false};
    bool all_instance_proof_product_executable{false};
    bool recursive_child_consumption_complete{false};
    bool strict_semantic_complete{false};
    std::string remaining;
};

[[nodiscard]] uint256 CommitRCStage3ExtractBarrierLinkPin(
    const RCStage3ExtractBarrierLinkPin& pin);

/**
 * Structural prover helper.  It derives the complete link pin from typed
 * manifests and proof-owned column roots.  It does not accept or execute
 * native Extract/SHA replay.
 */
[[nodiscard]] bool BuildRCStage3ExtractBarrierLinkPin(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledSemanticFlatBundle& extract_outputs,
    const std::vector<RCStage3CoupledBarrierEndpointExecution>& barriers,
    RCStage3ExtractBarrierLinkPin& out,
    std::string* why = nullptr);

/**
 * Execute every ordered Extract quotient and every barrier SHA proof after
 * checking the exact per-block equality product.
 */
[[nodiscard]] bool VerifyRCStage3ExtractBarrierLinkExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3ExtractBarrierLinkExecution& execution,
    std::string* why = nullptr);

[[nodiscard]] RCStage3ExtractBarrierLinkAudit
CurrentRCStage3ExtractBarrierLinkAudit(
    const RCStage3CoupledShape& shape);

inline constexpr bool
    kRCStage3ExtractBarrierLinkProductExecutable = true;
inline constexpr bool
    kRCStage3ExtractBarrierLinkRecursiveAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_BARRIER_LINK_H
