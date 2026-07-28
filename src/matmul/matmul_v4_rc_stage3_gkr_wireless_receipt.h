// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_GKR_WIRELESS_RECEIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_GKR_WIRELESS_RECEIPT_H

#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_gkr_wireless_receipt {

namespace gf = gkr_field;
namespace ah = alg_hash;

inline constexpr uint16_t kDescriptorVersionV1 = 1;
inline constexpr uint16_t kReceiptVersionV1 = 1;
/**
 * Absolute Q192 wire cap from terms which grow with width:
 *   column_len: 4 bytes
 *   dual OOD evaluations: 2 * 24 bytes
 *   Q192 row cells: 192 * 24 bytes.
 * Domain/path terms reduce this further and are checked by the exact
 * shape-aware estimator.
 */
inline constexpr uint64_t kQ192BytesPerOracleColumnV1 =
    4U + 2U * 24U + kRCFri3AlgNumQueries * 24U;
inline constexpr uint32_t kMaxOracleColumnsPerReceiptV1 =
    static_cast<uint32_t>(
        (kRCFriMaxProofBytesHard - 4096U) /
        kQ192BytesPerOracleColumnV1);
static_assert(kMaxOracleColumnsPerReceiptV1 > 0);

/**
 * Public, verifier-reconstructed identity of one polynomial in the canonical
 * episode layout Lambda(params).  This is deliberately not a prover manifest.
 */
struct ColumnDescriptorV1 {
    uint32_t id{0};
    RCGkrTensor tensor{RCGkrTensor::Q};
    uint32_t round{0};
    uint32_t layer{0};
    uint32_t rows{0};
    uint32_t cols{0};
    uint32_t chunk{0};
    uint32_t n_chunks{0};
    uint64_t chunk_offset{0};
    uint64_t logical_len{0};
    bool int64_cells{false};

    friend bool operator==(
        const ColumnDescriptorV1&,
        const ColumnDescriptorV1&) = default;
};

/**
 * Complete public statement for the authenticated-oracle boundary.
 *
 * `columns` is rebuilt from RCGkrTraceLayout(params), including every
 * kappa-bounded tensor chunk.  `fri_fs_seed` is a public input selected by the
 * outer episode statement; this adapter never accepts a proof-carried seed.
 */
struct PublicDescriptorV1 {
    uint16_t version{kDescriptorVersionV1};
    RCEpisodeParams params{};
    int32_t height{0};
    uint256 claimed_digest{};
    uint256 pow_bind{};
    uint256 episode_sigma{};
    std::vector<uint256> round_roots;
    uint256 fri_fs_seed{};
    uint64_t trace_cells{0};
    uint64_t operand_cells{0};
    uint64_t total_cells{0};
    std::vector<ColumnDescriptorV1> columns;
    ah::Digest descriptor_root{};
};

struct ChunkRangeV1 {
    uint32_t first_column{0};
    uint32_t column_count{0};

    friend bool operator==(
        const ChunkRangeV1&,
        const ChunkRangeV1&) = default;
};

/** One proof-owned, FRI-authenticated pair of dual-OOD evaluations. */
struct AuthenticatedOodEvaluationV1 {
    uint32_t global_column_id{0};
    uint32_t logical_len{0};
    gf::Fp3 at_z1{};
    gf::Fp3 at_z2{};
};

/**
 * Wire-free authenticated-oracle receipt.
 *
 * The serialized object contains the V13 FRI proof, never the coefficient
 * vectors A/B/Y/Extract.  `evaluations` is a normalized copy of the exact
 * evals_z1/evals_z2 cells already authenticated by that proof.  The verifier
 * rejects if either copy differs.
 */
struct ReceiptV1 {
    uint16_t version{kReceiptVersionV1};
    ah::Digest descriptor_root{};
    ChunkRangeV1 range{};
    /** Derived from descriptor_root, outer fri_fs_seed and range. */
    uint256 chunk_fs_seed{};
    Fri3AlgBatchProof fri_proof{};
    std::vector<AuthenticatedOodEvaluationV1> evaluations;
    /**
     * SAFE root of the authenticated FRI statement: all oracle/fold roots,
     * OOD claims, transcript scalars and query/fold coordinates. Merkle path
     * values are verified against those roots and are not redundantly hashed.
     */
    ah::Digest proof_statement_root{};
    ah::Digest evaluation_root{};
    ah::Digest receipt_root{};
};

/**
 * Fixed-size public export suitable for an outer normalized verifier.  This
 * module computes the cells but does not claim that the current parent AIR
 * consumes them.
 */
struct NormalizedPublicInputV1 {
    uint16_t version{kReceiptVersionV1};
    ah::Digest descriptor_root{};
    ah::Digest proof_statement_root{};
    ah::Digest evaluation_root{};
    ah::Digest receipt_root{};
    ah::Digest row_root{};
    uint256 chunk_fs_seed{};
    uint32_t first_column{0};
    uint32_t column_count{0};
    uint32_t n_coeffs{0};
    uint32_t blowup{0};
};

struct AuditV1 {
    bool valid{false};
    bool public_descriptor_reconstructed{false};
    bool canonical_chunk_range{false};
    bool exact_column_order_and_lengths{false};
    bool canonical_codec_round_trip{false};
    bool v13_fri_verified{false};
    bool dual_ood_evaluations_proof_owned{false};
    bool authenticated_proof_statement_bound{false};
    bool normalized_public_input_exported{false};
    /** No Extract/tile-tree/content-to-round-root relation is in this seam. */
    bool episode_content_to_round_roots_verified{false};
    /** This boundary proves OOD openings, not arbitrary MLE claims. */
    bool arbitrary_gkr_mle_claims_verified{false};
    /** False until the normalized parent executes the exported verifier. */
    bool recursively_consumed{false};
    std::string note;
};

struct ReceiptSetV1 {
    uint16_t version{kReceiptVersionV1};
    ah::Digest descriptor_root{};
    std::vector<ReceiptV1> receipts;
    ah::Digest ordered_set_root{};
};

struct ReceiptSetAuditV1 {
    bool valid{false};
    bool exact_disjoint_partition{false};
    bool every_receipt_verified{false};
    bool ordered_set_root_bound{false};
    bool coefficient_wires_serialized{false};
    bool episode_content_to_round_roots_verified{false};
    bool arbitrary_gkr_mle_claims_verified{false};
    bool recursively_consumed{false};
    std::string note;
};

[[nodiscard]] bool BuildPublicDescriptorV1(
    const RCEpisodeParams& params,
    int32_t height,
    const uint256& claimed_digest,
    const uint256& pow_bind,
    const uint256& episode_sigma,
    const std::vector<uint256>& round_roots,
    const uint256& fri_fs_seed,
    PublicDescriptorV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidatePublicDescriptorV1(
    const PublicDescriptorV1& descriptor,
    std::string* why = nullptr);

[[nodiscard]] ah::Digest ComputePublicDescriptorRootV1(
    const PublicDescriptorV1& descriptor);

[[nodiscard]] std::vector<ChunkRangeV1> BuildChunkPlanV1(
    const PublicDescriptorV1& descriptor,
    uint32_t max_columns_per_receipt =
        kMaxOracleColumnsPerReceiptV1);

/** Exact canonical single-lane Q192 envelope size for this shape. */
[[nodiscard]] std::optional<size_t>
EstimateQ192V13ProofBytesV1(
    uint32_t batch_columns,
    uint32_t n_coeffs);

/**
 * Per-chunk transcript seed.  Binding the canonical descriptor and range here
 * prevents a valid oracle proof from being transplanted to another episode or
 * to another position in the ordered chunk set.
 */
[[nodiscard]] uint256 DeriveChunkFsSeedV1(
    const PublicDescriptorV1& descriptor,
    const ChunkRangeV1& range);

/**
 * Verify the real V13 proof first, then materialize a normalized receipt.
 * Input columns are absent by construction.
 */
[[nodiscard]] AuditV1 BuildReceiptV1(
    const PublicDescriptorV1& descriptor,
    const ChunkRangeV1& range,
    const Fri3AlgBatchProof& fri_proof,
    ReceiptV1& out);

/**
 * Verifier API: public descriptor plus receipt only.  No coefficient/wire
 * vectors or prover-authored layout are accepted.
 */
[[nodiscard]] AuditV1 VerifyReceiptV1(
    const PublicDescriptorV1& expected_descriptor,
    const ReceiptV1& receipt);

[[nodiscard]] bool ExportNormalizedPublicInputV1(
    const PublicDescriptorV1& expected_descriptor,
    const ReceiptV1& receipt,
    NormalizedPublicInputV1& out,
    std::string* why = nullptr);

[[nodiscard]] ah::Digest ComputeProofStatementRootV1(
    const Fri3AlgBatchProof& proof);

[[nodiscard]] ah::Digest ComputeEvaluationRootV1(
    const ReceiptV1& receipt);

[[nodiscard]] ah::Digest ComputeReceiptRootV1(
    const ReceiptV1& receipt);

[[nodiscard]] ah::Digest ComputeOrderedSetRootV1(
    const ReceiptSetV1& set);

[[nodiscard]] ReceiptSetAuditV1 VerifyReceiptSetV1(
    const PublicDescriptorV1& expected_descriptor,
    const ReceiptSetV1& set);

inline constexpr bool kAuthenticatedOracleBoundaryExecutableV1 = true;
inline constexpr bool kArbitraryGkrMleAdapterExecutableV1 = false;
inline constexpr bool kNormalizedRecursiveConsumptionExecutableV1 = false;
inline constexpr bool kProductionAuthorityReadyV1 =
    kAuthenticatedOracleBoundaryExecutableV1 &&
    kArbitraryGkrMleAdapterExecutableV1 &&
    kNormalizedRecursiveConsumptionExecutableV1;

static_assert(kAuthenticatedOracleBoundaryExecutableV1);
static_assert(!kProductionAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_gkr_wireless_receipt

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_GKR_WIRELESS_RECEIPT_H
