// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_PRODUCT_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeGemmProductVersion = 1;

enum RCStage3EpisodeGemmDotColumn : uint32_t {
    kRCStage3GemmDotActive = 0,
    kRCStage3GemmDotStart,
    kRCStage3GemmDotEnd,
    kRCStage3GemmDotA,
    kRCStage3GemmDotB,
    kRCStage3GemmDotY,
    kRCStage3GemmDotResidual,
    kRCStage3GemmDotExtractInput,
    kRCStage3GemmDotProduct,
    kRCStage3GemmDotAccumulatorBefore,
    kRCStage3GemmDotAccumulatorAfter,
    kRCStage3GemmDotColumns,
};

struct RCStage3EpisodeGemmDotPin {
    uint16_t version{kRCStage3EpisodeGemmProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint32_t layer_ordinal{0};
    uint64_t layer_tile_index{0};
    uint32_t contraction_size{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3EpisodeGemmTileProof {
    uint64_t layer_tile_index{0};
    RCStage3EpisodeGemmDotPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

/**
 * Exact V1 flat openings for one Λ layer.
 *
 * A is m×k row-major. B is stored in its underlying committed order:
 * k×n when b.transpose=false, n×k otherwise. `gemm_y` is the pure m×n
 * product; `residual` is empty except fused DOWN and is added only at the
 * Extract-input boundary.
 */
struct RCStage3EpisodeGemmLayerProduct {
    uint32_t layer_ordinal{0};
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    std::vector<int64_t> gemm_y;
    std::vector<int8_t> residual;
    std::vector<RCStage3EpisodeGemmTileProof> tiles;
    uint256 layer_receipt_commitment{};
};

struct RCStage3EpisodeGemmProduct {
    uint16_t version{kRCStage3EpisodeGemmProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    std::vector<RCStage3EpisodeGemmLayerProduct> layers;
    /** Executes every registered non-transposed A/B equality edge. */
    RCStage3EpisodeWiringCopyClosure wiring;
    uint256 collection_commitment{};
};

struct RCStage3EpisodeGemmLayerWitness {
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    /**
     * Optional pure A*B output captured from the mining computation.
     *
     * Production supplies this field through RCEpisodeProofWitnessSink so the
     * prover does not replay a datacenter GEMM merely to reconstruct witness
     * cells.  It is not trusted: every output is still constrained by the
     * dot-product AIR and by the Extract-input equality.  Empty retains the
     * legacy test/R&D path which computes Y locally.
     */
    std::vector<int64_t> gemm_y;
    /** Required only for Λ layers with residual_first_column >= 0. */
    std::vector<int8_t> residual;
};

/**
 * Canonical all-instance witness collector attached to the real v4.6-3 miner.
 *
 * The collector accepts callbacks only in Λ(params) order and materializes the
 * exact A/B/Y/residual vectors and Extract input tiles consumed by the Stage-3
 * all-instance provers.  It never computes a GEMM.  Any missing, duplicate,
 * reordered or shape-inconsistent callback leaves the collector fail-closed.
 *
 * This V1 collector is intentionally a flat correctness bridge.  Production
 * recursion can replace its backing vectors with shard writers without
 * changing the callback/order contract.
 */
class RCStage3EpisodeWitnessCapture final
    : public RCEpisodeProofWitnessSink {
public:
    explicit RCStage3EpisodeWitnessCapture(
        const RCEpisodeParams& params);

    void OnPhase1Operands(
        const RCPhase1OperandsWitnessView& view) override;
    void OnPhase1QKtTile(
        const RCPhase1QKtTileWitnessView& view) override;
    void OnPhase1SVRow(
        const RCPhase1SVRowWitnessView& view) override;
    void OnFfnGemm(
        const RCFfnGemmWitnessView& view) override;
    void OnFfnExtract(
        const RCFfnExtractWitnessView& view) override;
    void OnRoundRoot(
        uint32_t round_ordinal,
        const uint256& round_root) override;
    void OnEpisodeDigest(
        const uint256& episode_digest) override;

    [[nodiscard]] bool Complete(std::string* why = nullptr) const;
    [[nodiscard]] bool ValidateManifest(
        const RCStage3GemmExtractManifest& manifest,
        std::string* why = nullptr) const;
    [[nodiscard]] bool ValidateExtractProductOutputs(
        const RCStage3EpisodeExtractProduct& extract,
        std::string* why = nullptr) const;

    [[nodiscard]] const std::vector<
        RCStage3EpisodeGemmLayerWitness>&
    LayerWitnesses() const
    {
        return m_layers;
    }
    [[nodiscard]] const std::vector<
        std::array<int64_t, kRCMxBlockLen>>&
    ExtractInputs() const
    {
        FlattenExtractTiles();
        return m_extract_inputs;
    }
    [[nodiscard]] const std::vector<uint256>&
    ExtractPrfs() const
    {
        return m_extract_prfs;
    }
    [[nodiscard]] const std::vector<uint256>&
    RoundRoots() const
    {
        return m_round_roots;
    }
    [[nodiscard]] const uint256&
    EpisodeDigest() const
    {
        return m_episode_digest;
    }
    /**
     * Reconstruct the exact committed R.4.1 stream from outputs already
     * retained for the all-instance Extract proof.  No second transcript copy
     * is stored in the winner capture.
     */
    [[nodiscard]] bool BuildRoundStream(
        uint32_t round_ordinal,
        std::vector<int8_t>& out,
        std::string* why = nullptr) const;

private:
    void Reject(const char* why);
    [[nodiscard]] uint32_t RoundBase(uint32_t round) const;
    [[nodiscard]] uint32_t FfnOrdinal(
        uint32_t round, uint32_t layer,
        RCFfnProjection projection) const;
    void AppendExtractTiles(
        uint32_t ordinal, const int64_t* input,
        const int8_t* output, uint64_t cells,
        const uint256& prf);
    void FlattenExtractTiles() const;

    RCEpisodeParams m_params{};
    RCGkrLayout m_layout{};
    std::vector<RCStage3EpisodeGemmLayerWitness> m_layers;
    std::vector<std::vector<
        std::array<int64_t, kRCMxBlockLen>>>
        m_layer_extract_inputs;
    std::vector<std::vector<
        std::array<int8_t, kRCMxBlockLen>>>
        m_layer_extract_outputs;
    mutable std::vector<std::array<int64_t, kRCMxBlockLen>>
        m_extract_inputs;
    mutable std::vector<std::array<int8_t, kRCMxBlockLen>>
        m_extract_outputs;
    mutable bool m_extract_flattened{false};
    std::vector<uint64_t> m_layer_tile_begin;
    std::vector<uint64_t> m_next_layer_tile;
    std::vector<uint256> m_extract_prfs;
    std::vector<bool> m_operands_seen;
    std::vector<bool> m_gemm_seen;
    std::vector<bool> m_extract_seen;
    std::vector<uint256> m_round_roots;
    uint256 m_episode_digest{};
    bool m_episode_digest_seen{false};
    mutable bool m_complete_checked{false};
    mutable bool m_complete_ok{false};
    mutable std::string m_complete_error;
    std::string m_error;
};

/**
 * Winner-only handoff from the solver's existing CPU reseal to the normalized
 * proof producer. The store is process-local and retains at most one completed
 * capture, so losing nonce traces are never persisted and a stale winner
 * cannot be selected for a different header.
 */
[[nodiscard]] bool RCStage3EpisodeWitnessStorePut(
    const uint256& final_header_hash,
    std::shared_ptr<const RCStage3EpisodeWitnessCapture> capture,
    std::string* why = nullptr);
[[nodiscard]] std::shared_ptr<
    const RCStage3EpisodeWitnessCapture>
RCStage3EpisodeWitnessStoreGet(
    const uint256& final_header_hash);
void RCStage3EpisodeWitnessStoreErase(
    const uint256& final_header_hash);
void RCStage3EpisodeWitnessStoreClearForTest();

/**
 * Consume one completed miner capture into the exact all-instance relation
 * products.  This is the first direct solve -> proof bridge: no episode or
 * GEMM is replayed here.  Extract is proved from the captured accumulator
 * tiles, its proved output roots are checked against the bytes emitted by the
 * solver, and every captured Y is then proved against captured A/B.
 */
[[nodiscard]] bool ProveRCStage3EpisodeProductsFromCapture(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWitnessCapture& capture,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeGemmProduct& gemm,
    std::string* why = nullptr);

/**
 * Honest bounded all-layer/all-output-tile GEMM prover.
 *
 * Production callers provide every Y cell captured from the mining
 * computation.  Legacy/R&D callers may leave Y empty and have it reconstructed
 * locally.  In both cases the function requires Y+residual to equal the
 * already proved Extract input tiles, updates the three GEMM-owned manifest
 * roots, refreshes the dependent Extract/tile-stream manifest commitments,
 * proves every dot-product AIR, and proves the exact wiring-copy closure.  A
 * supplied Y is therefore a witness, never an assertion: the dot-product AIR
 * still binds it to A*B. All three products are self-verified before return.
 */
[[nodiscard]] bool ProveRCStage3EpisodeGemmProduct(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3EpisodeGemmLayerWitness>& witnesses,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeGemmProduct& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmDotPinCommitment(
    const RCStage3EpisodeGemmDotPin& pin);
[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmDotSeed(
    const RCStage3EpisodeGemmDotPin& pin);
[[nodiscard]] bool BuildRCStage3EpisodeGemmDotConstraintSystem(
    const RCStage3EpisodeGemmDotPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeGemmDotProof(
    const RCStage3EpisodeGemmDotPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
    const RCStage3EpisodeGemmLayerProduct& layer);
[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmCollectionCommitment(
    const RCStage3EpisodeGemmProduct& product);

/**
 * Populate the four per-layer Poseidon VectorRootAlg authority fields owned by
 * the flat GEMM/Extract value products (A, B, Y and Extract input). The scale
 * schedule is owned by the hash/Extract relation and remains separate. This
 * is a prover-side helper only: callers
 * must use ValidateRCStage3EpisodeGemmAlgAuthorityRoots (or the complete GEMM
 * verifier, which calls it) before trusting the fields.
 */
[[nodiscard]] bool BindRCStage3EpisodeGemmAlgAuthorityRoots(
    RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why = nullptr);

/**
 * Recompute every operand-A, operand-B, GEMM-Y and Extract-input
 * VectorRootAlg from the owning product values and require exact equality to
 * the corresponding RCStage3GemmExtractLayerBindings fields.  This prevents
 * the serialized *_root_alg fields from being free caller-selected metadata.
 *
 * This check is deliberately linear in the flat product.  It hardens and
 * validates the current R&D product but is not the normalized recursive
 * source-provenance proof required for production authority.
 */
[[nodiscard]] bool ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why = nullptr);

/**
 * Validate Λ coverage and every proof-owned opening/root alias. This performs
 * indexing and commitment computation only; it never multiplies matrices.
 */
[[nodiscard]] bool ValidateRCStage3EpisodeGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why = nullptr);

/** Execute every dot-product AIR, Extract-input equality and wiring proof. */
[[nodiscard]] bool VerifyRCStage3EpisodeGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why = nullptr);

struct RCStage3EpisodeGemmProductAudit {
    bool immutable_full_lambda_schedule{false};
    bool all_operand_openings_bound{false};
    bool every_dot_product_air_executed{false};
    bool complete_signed_arithmetic_identity{false};
    bool y_root_bound{false};
    bool y_residual_to_extract_input_equality{false};
    bool internal_extract_and_wiring_producers_linked{false};
    bool endpoints_5_through_8_locally_complete{false};
    bool external_builder_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeGemmProductAudit
CurrentRCStage3EpisodeGemmProductAudit();

inline constexpr bool kRCStage3EpisodeGemmLocalRelationExecutable = true;
inline constexpr bool kRCStage3EpisodeGemmTransitivelyComplete = false;

} // namespace matmul::v4::rc

#endif
