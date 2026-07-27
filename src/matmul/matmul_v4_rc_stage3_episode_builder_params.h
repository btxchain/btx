// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_PARAMS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_PARAMS_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeBuilderParamsVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeBuilderParamsCells = 9;

/**
 * Proof-owned public-parameter product for endpoint 1.
 *
 * `expected_params` is resolved by consensus from (height, chain params).
 * The verifier regenerates this exact nine-cell vector and its committed
 * column root; no parameter values are accepted from the manifest.  The
 * existing semantic-memory quotient then proves the identical ordered vector
 * in endpoint-1's VALUE/EXPORT columns.
 */
struct RCStage3EpisodeBuilderParamsProduct {
    uint16_t version{kRCStage3EpisodeBuilderParamsVersion};
    RCStage3EpisodeSemanticMemoryManifest memory_manifest;
    RCStage3EpisodeSemanticMemoryProof memory_proof;
};

[[nodiscard]] std::vector<gkr_field::Fp3>
CanonicalRCStage3EpisodeBuilderParamValues(
    const RCEpisodeParams& params);

[[nodiscard]] bool ProveRCStage3EpisodeBuilderParamsProduct(
    const uint256& statement_commitment,
    const RCEpisodeParams& params,
    RCStage3EpisodeBuilderParamsProduct& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeBuilderParamsProduct(
    const uint256& expected_statement_commitment,
    const RCEpisodeParams& expected_params,
    const RCStage3EpisodeBuilderParamsProduct& product,
    std::string* why = nullptr);

struct RCStage3EpisodeBuilderParamsAudit {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderParams};
    bool consensus_values_regenerated{false};
    bool exact_ordered_vector_root{false};
    bool proof_owned_value_column{false};
    bool statement_bound{false};
    bool local_relation_complete{false};
    bool producer_provenance_complete{false};
    bool semantic_complete{false};
    bool recursively_consumed{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeBuilderParamsAudit
CurrentRCStage3EpisodeBuilderParamsAudit();

inline constexpr bool
    kRCStage3EpisodeBuilderParamsSemanticProductExecutable = true;
inline constexpr bool
    kRCStage3EpisodeBuilderParamsRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_PARAMS_H
