// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_PROVENANCE_GRAPH_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_PROVENANCE_GRAPH_H

#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <primitives/block.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Deterministic audit-only producer graph.
 *
 * This registry records the value-level cut between every registered
 * endpoint and its immediate semantic producers. Capability flags describe
 * concrete verifier constructions that exist today. The graph audit checks
 * declaration shape, ordering, capability monotonicity, and construction
 * names; it does not invoke the heterogeneously typed construction functions.
 * Their proof execution is covered by the corresponding product/link test
 * suites. These flags are not proof inputs and this module is deliberately
 * not called by consensus, relation closure, or the normalized recursive
 * verifier.
 */
struct RCStage3ProvenanceEdge {
    RCStage3RelationEndpoint producer{};
    bool value_equality_executable{false};
    bool bounded_composition_executable{false};
    bool production_composition_executable{false};
    bool normalized_recursive_executable{false};
    std::string construction;
    std::string remaining;
};

struct RCStage3ProvenanceNode {
    RCStage3RelationEndpoint endpoint{};
    bool public_root{false};
    std::vector<RCStage3ProvenanceEdge> producers;
};

struct RCStage3ProvenanceGraphAudit {
    std::vector<RCStage3ProvenanceNode> nodes;
    uint32_t edges{0};
    uint32_t value_equality_edges{0};
    uint32_t bounded_composition_edges{0};
    uint32_t production_composition_edges{0};
    uint32_t normalized_recursive_edges{0};
    bool exact_52_order{false};
    bool exact_public_roots_1_and_25{false};
    bool every_non_public_node_has_a_producer{false};
    bool no_missing_out_of_range_self_or_duplicate_producer{false};
    bool capability_flags_fail_closed{false};
};

[[nodiscard]] RCStage3ProvenanceGraphAudit
CurrentRCStage3ProvenanceGraphAudit();

/**
 * Execute the bounded value/root joins which connect endpoint 4 to the
 * episode GEMM inputs and endpoints 7/14 to Extract and wiring consumers.
 *
 * This is deliberately only a producer-link verifier. Callers must separately
 * verify the BuilderTrace, GEMM and Extract local proof products. The copy and
 * endpoint-16..18 wiring proofs are executed here because their equality
 * relations are the joins being claimed.
 */
[[nodiscard]] bool VerifyRCStage3BoundedEpisodeProducerLinks(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderTraceProduct& builder_trace,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeWiringProduct& wiring,
    std::string* why = nullptr);

inline constexpr uint32_t
    kRCStage3BoundedEpisodeProducerLinkEdges = 14;

/**
 * Execute the endpoint-2 -> endpoint-12 PRF derivation and the endpoint-12 ->
 * endpoint-13 scale-hash ancestry.
 *
 * The header, proved seed/round-root product, verifier-derived canonical layer
 * provenance and every manifest Extract PRF must agree. The full Extract
 * verifier then executes every scale SHA proof whose preimage contains that
 * same PRF, row and block. This does not natively replay Extract or scale.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeExtractPrfDerivation(
    const CBlockHeader& header,
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeExtractDerivationLinks(
    const CBlockHeader& header,
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why = nullptr);

inline constexpr uint32_t
    kRCStage3EpisodeExtractDerivationLinkEdges = 2;

inline constexpr bool
    kRCStage3ProvenanceGraphIsConsensusProof = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_PROVENANCE_GRAPH_H
