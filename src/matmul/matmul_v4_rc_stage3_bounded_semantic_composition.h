// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_COMPOSITION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_COMPOSITION_H

#include <matmul/matmul_v4_rc_stage3_coupled_chain_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_initial_state_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>
#include <matmul/matmul_v4_rc_stage3_tile_tree_hash_ctl.h>

#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Product families needed to construct one genuinely accepting bounded
 * composition.  This registry is deliberately about prover orchestration,
 * not verifier capability: several families have executable low-level proof
 * primitives but still lack a public product-wide honest builder.
 */
enum class RCStage3BoundedSemanticBuildFamily : uint8_t {
    EpisodeHeaderTarget = 0,
    EpisodeSeedChain,
    EpisodeOperandXof,
    EpisodeBuilderTrace,
    EpisodeGemm,
    EpisodeSignedRange,
    EpisodeExtract,
    EpisodeTileStream,
    EpisodeWiring,
    EpisodeRoundRoots,
    EpisodeDigestRootChain,
    EpisodePow,
    CoupledBank,
    CoupledInitialState,
    CoupledGemm,
    CoupledSignedRange,
    CoupledExchangePermutation,
    CoupledMix,
    CoupledExtract,
    CoupledBankRoot,
    CoupledRootChain,
    CrossProductJoins,
    BoundedAggregateVerifier,
};

struct RCStage3BoundedSemanticBuildFamilyPlan {
    RCStage3BoundedSemanticBuildFamily family{};
    bool honest_product_orchestration_available{false};
    std::string blocker;
};

/**
 * Exact, allocation-bounded schedule inventory for a future positive fixture.
 *
 * `positive_fixture_buildable` is true only when every required family has a
 * public honest product-wide builder.  A false value is diagnostic and never
 * authorizes a placeholder proof or a bypass in the aggregate verifier.
 */
struct RCStage3BoundedSemanticBuildPlan {
    uint32_t episode_layers{0};
    uint64_t episode_gemm_tiles{0};
    uint64_t episode_extract_tiles{0};
    uint64_t episode_stream_tiles{0};
    uint64_t episode_wiring_edges{0};
    uint32_t episode_signed_range_shards{0};

    uint32_t coupled_bank_pages{0};
    uint32_t coupled_initial_lobes{0};
    uint32_t coupled_gemms{0};
    uint32_t coupled_signed_range_shards{0};
    uint32_t coupled_exchange_stages{0};
    uint32_t coupled_permutation_stages{0};
    uint32_t coupled_mix_barriers{0};
    uint32_t coupled_extract_tiles{0};
    uint32_t coupled_root_barriers{0};

    std::vector<RCStage3BoundedSemanticBuildFamilyPlan> families;
    std::vector<std::string> missing_product_orchestrators;
    bool positive_fixture_buildable{false};
};

[[nodiscard]] const char* RCStage3BoundedSemanticBuildFamilyName(
    RCStage3BoundedSemanticBuildFamily family);

/**
 * Build the exact positive-fixture prover plan without producing any proof.
 *
 * The outer statement must already be a valid composed envelope bound to
 * `header`.  Schedules are derived from the same public constructors used by
 * verification.  Missing product-wide prover families are returned explicitly
 * in `out.missing_product_orchestrators`; the function still succeeds because
 * constructing a fail-closed plan is distinct from constructing a proof.
 */
[[nodiscard]] bool BuildRCStage3BoundedSemanticProverPlan(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    const RCStage3CoupledShape& shape,
    RCStage3BoundedSemanticBuildPlan& out,
    std::string* why = nullptr);

/**
 * Complete bounded V1 episode branch.
 *
 * These are the actual typed child proofs and proof-owned openings.  There is
 * no caller-supplied completion bitmap or receipt.  In particular, signed
 * range proofs are kept beside the GEMM product so the aggregate verifier can
 * equality-bind their VALUE columns to the already proved GEMM Y openings.
 */
struct RCStage3BoundedEpisodeSemanticComposition {
    RCStage3EpisodeBuilderSeedChainProduct seed_chain;
    RCStage3EpisodeBuilderOperandXofProduct operand_xof;
    RCStage3EpisodeBuilderTraceProduct builder_trace;
    RCStage3GemmExtractManifest gemm_extract_manifest;
    RCStage3EpisodeGemmProduct gemm;
    std::vector<RCStage3SignedRangeShardProof> signed_range;
    RCStage3EpisodeExtractProduct extract;
    RCStage3EpisodeTileStreamProduct tile_stream;
    RCStage3ExtractStreamCtlProof extract_stream_ctl;
    RCStage3EpisodeTileStreamLeafCtlProof
        tile_stream_leaf_ctl;
    RCStage3TileTreeHashCtlProof tile_tree_hash_ctl;
    RCStage3EpisodeWiringProduct wiring;
    RCStage3EpisodeDigestRootChainProof root_chain;
    RCStage3EpisodeRoundRootProducerProduct round_root_producers;
    RCStage3EpisodeHeaderTargetProduct header_target;
    RCStage3EpisodePowPin pow_pin;
    RCStage3EpisodePowProof pow_proof;
};

/** Complete bounded V1 coupled branch. */
struct RCStage3BoundedCoupledSemanticComposition {
    RCStage3CoupledBankProduct bank;
    RCStage3CoupledBankRootExecution bank_root;
    RCStage3CoupledInitialStateProduct initial_state;
    RCStage3CoupledGemmProduct gemm;
    RCStage3CoupledSignedRangeExecution signed_range;
    RCStage3CoupledExchangePermutationProduct exchange_permutation;
    RCStage3CoupledMixProduct mix;
    RCStage3CoupledExtractProduct extract;
    RCStage3CoupledRootChainProof root_chain;
};

struct RCStage3BoundedSemanticComposition {
    RCStage3BoundedEpisodeSemanticComposition episode;
    RCStage3BoundedCoupledSemanticComposition coupled;
};

/** Honest streaming all-shard prover for endpoint 9 from proof-owned GEMM Y. */
[[nodiscard]] bool ProveRCStage3EpisodeSignedRangeGemmLink(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    std::vector<RCStage3SignedRangeShardProof>& out,
    std::string* why = nullptr);

/**
 * Execute the endpoint-7 -> endpoint-9 value equality.
 *
 * Verification executes every range proof and then recomputes each range
 * VALUE-column commitment from the canonical slice of the proof-owned GEMM Y
 * opening.  It performs no native GEMM replay.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeSignedRangeGemmLink(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const std::vector<RCStage3SignedRangeShardProof>& range,
    std::string* why = nullptr);

/** Structural value-root half used by the fail-closed combined verifier. */
[[nodiscard]] bool ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const std::vector<RCStage3SignedRangeShardProof>& range,
    std::string* why = nullptr);

/** Honest streaming all-shard prover for endpoint 33 from proof-owned GEMM Y. */
[[nodiscard]] bool ProveRCStage3CoupledSignedRangeGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& gemm,
    RCStage3CoupledSignedRangeExecution& out,
    std::string* why = nullptr);

/** Coupled analogue of the endpoint-7 -> endpoint-9 link (32 -> 33). */
[[nodiscard]] bool VerifyRCStage3CoupledSignedRangeGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledSignedRangeExecution& range,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateRCStage3CoupledSignedRangeGemmValueEquality(
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledSignedRangeExecution& range,
    std::string* why = nullptr);

/**
 * Execute one composed, bounded verification schedule for all 52 registered
 * semantic endpoints and cover all 81 guarded immediate producer-edge
 * obligations. Shape-inactive edges have a verifier-derived empty schedule;
 * they are covered, not claimed to have executed a non-empty instance.
 *
 * `params`, `shape`, and `header` are verifier-resolved public inputs.  A
 * successful result means bounded typed-proof execution and immediate-edge
 * closure only. The outer RCStage3SuccinctProof composition/transcript link is
 * checked, but the typed sidecars in this object do not yet have a canonical
 * durable serialization into its relation sections. It deliberately does not
 * alter production, recursive, consensus-authority, or activation flags.
 */
[[nodiscard]] bool VerifyRCStage3BoundedSemanticComposition(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    const RCStage3CoupledShape& shape,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why = nullptr);

/**
 * Finalize one already-proved 23-family composition.
 *
 * This is the single positive-aggregate seam: it attaches the canonical
 * typed-sidecar binding to the CompositionLink section, refreshes the outer
 * transcript, and immediately executes the complete 52-endpoint/81-edge
 * verifier. On failure the caller receives the exact first integration gate.
 * Child proof construction remains explicit so production provers can stream
 * or parallelize the heterogeneous families.
 */
[[nodiscard]] bool FinalizeRCStage3BoundedSemanticComposition(
    RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    const RCStage3CoupledShape& shape,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why = nullptr);

inline constexpr bool
    kRCStage3BoundedSemanticCompositionExecutable = true;
inline constexpr bool
    kRCStage3BoundedSemanticCompositionProductionExecutable = false;
inline constexpr bool
    kRCStage3BoundedSemanticCompositionRecursivelyConsumed = false;
inline constexpr bool
    kRCStage3BoundedSemanticCompositionDurablySerialized = false;
inline constexpr bool
    kRCStage3BoundedSemanticCompositionAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_COMPOSITION_H
