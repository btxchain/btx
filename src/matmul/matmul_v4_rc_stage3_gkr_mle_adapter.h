// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_GKR_MLE_ADAPTER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_GKR_MLE_ADAPTER_H

#include <matmul/matmul_v4_rc_gkr_eval.h>
#include <matmul/matmul_v4_rc_stage3_gkr_wireless_receipt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_gkr_mle_adapter {

namespace gf = gkr_field;
namespace ah = alg_hash;
namespace wireless = stage3_gkr_wireless_receipt;

inline constexpr uint16_t kProofVersionV1 = 1;
inline constexpr uint32_t kProofMagicV1 =
    UINT32_C(0x31414d47); // "GMA1", little endian.
inline constexpr uint32_t kMaxClaimsV1 =
    kRCGkrEvalArgMaxClaims;
inline constexpr size_t kMaxProofBytesV1 =
    kRCFriMaxProofBytesHard;
inline constexpr uint32_t kMaxReceiptColumnsPerProofV1 =
    wireless::kMaxOracleColumnsPerReceiptV1 <
            kRCFri3AlgBatchMaxColumns - 4U
        ? wireless::kMaxOracleColumnsPerReceiptV1
        : kRCFri3AlgBatchMaxColumns - 4U;

/**
 * Public claim against one column in the canonical wireless-receipt range.
 *
 * `global_column_id` is the Lambda(params) id, not a proof-local index.
 * `point` has exactly log2(receipt.fri_proof.n_coeffs) Fp3 coordinates and
 * the value is the MLE of the zero-extended logical coefficient vector.
 */
struct OpeningClaimV1 {
    uint32_t global_column_id{0};
    std::vector<gf::Fp3> point;
    gf::Fp3 value{};

};

/**
 * Two independent SAFE-derived Aurora/Lemma-1.2 identities over Fp3.
 *
 * The witness columns are position-pinned:
 *   MainTrace      [0,W)     canonical receipt columns
 *   AuxiliaryTrace [W,W+2)   family-0 f,g
 *   Quotient        [W+2,W+4) family-1 f,g
 */
struct DualEvaluationArgumentV1 {
    std::array<gf::Fp3, 2> sigma{};
    std::array<uint32_t, 2> f_column{};
    std::array<uint32_t, 2> g_column{};
};

/**
 * Wire object for arbitrary MLE claims. Coefficient vectors are never
 * serialized. The V13 multi-row proof reopens the already authenticated main
 * row root together with the four claim-dependent quotient columns.
 */
struct ProofV1 {
    uint16_t version{kProofVersionV1};
    ah::Digest descriptor_root{};
    ah::Digest receipt_root{};
    ah::Digest claim_root{};
    ah::Digest main_row_root{};
    DualEvaluationArgumentV1 evaluation_argument{};
    Fri3AlgMultiRowBatchProof batch{};
};

struct AuditV1 {
    bool valid{false};
    bool receipt_verified{false};
    bool canonical_claims{false};
    bool claim_transcript_bound{false};
    bool receipt_row_root_reused{false};
    bool dual_safe_challenges_replayed{false};
    bool v13_multirow_fri_verified{false};
    bool dual_evaluation_identities_verified{false};
    bool canonical_codec_round_trip{false};
    bool proof_within_wire_cap{false};
    bool arbitrary_mle_claims_verified{false};
    /** MLE openings alone do not prove GEMM/Extract/hash relation semantics. */
    bool episode_relation_semantics_verified{false};
    /** False until the normalized recursive parent executes this verifier. */
    bool recursively_consumed{false};
    std::string note;
};

struct ProveResultV1 {
    ProofV1 proof;
    AuditV1 audit;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

struct WitnessDifferentialAuditV1 {
    uint32_t n_coeffs{0};
    uint32_t claims{0};
    bool ntt_path_executed{false};
    bool dual_sigma_matches{false};
    bool all_witness_coefficients_match{false};
    bool both_families_hold_at_both_points{false};
    bool valid{false};
    std::string note;
};

/** Exact canonical wrapper + V13 multi-row proof bytes for W+4 columns. */
[[nodiscard]] std::optional<size_t> EstimateProofBytesV1(
    uint32_t receipt_columns,
    uint32_t n_coeffs);

/**
 * Adapter-aware partition. Every returned range fits both its wireless
 * receipt proof and the downstream W+4 MLE multi-row proof under 16 MiB.
 */
[[nodiscard]] std::vector<wireless::ChunkRangeV1>
BuildChunkPlanV1(
    const wireless::PublicDescriptorV1& descriptor,
    uint32_t max_columns_per_receipt =
        kMaxReceiptColumnsPerProofV1);

/** Deterministic N=128, three-claim NTT-vs-direct algebra audit. */
[[nodiscard]] WitnessDifferentialAuditV1
AuditNttWitnessConstructionV1();

/**
 * Canonical SAFE claim commitment. Returns the all-zero digest for a malformed
 * claim list (noncanonical Fp limb, wrong point dimension/order/range, etc.).
 */
[[nodiscard]] ah::Digest ComputeClaimRootV1(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims);

/**
 * Two-epoch prover:
 *   R0(receipt columns) -> SAFE mu[0],mu[1] -> Rf0g0,Rf1g1 -> V13 FRI.
 *
 * `receipt_columns` is a prover-only coefficient source in exact receipt order.
 * Its recomputed row root must equal the proof-owned wireless receipt row root.
 */
[[nodiscard]] ProveResultV1 ProveV1(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<std::vector<gf::Fp3>>& receipt_columns,
    const std::vector<OpeningClaimV1>& claims);

/**
 * Public verifier. Inputs are descriptor, wireless receipt, public claims and
 * proof only; no canonical tensor coefficient vector is accepted.
 */
[[nodiscard]] AuditV1 VerifyV1(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims,
    const ProofV1& proof);

[[nodiscard]] size_t SerializeProofV1(
    const ProofV1& proof,
    std::vector<unsigned char>& out);

[[nodiscard]] std::optional<ProofV1> DeserializeProofV1(
    const std::vector<unsigned char>& bytes);

inline constexpr bool kDualSafeFp3EvaluationArgumentExecutableV1 =
    true;
inline constexpr bool kArbitraryMleAdapterExecutableV1 =
    true;
inline constexpr bool kEpisodeRelationSemanticsExecutableV1 =
    false;
inline constexpr bool kNormalizedRecursiveConsumptionExecutableV1 =
    false;
inline constexpr bool kProductionAuthorityReadyV1 =
    kDualSafeFp3EvaluationArgumentExecutableV1 &&
    kArbitraryMleAdapterExecutableV1 &&
    kEpisodeRelationSemanticsExecutableV1 &&
    kNormalizedRecursiveConsumptionExecutableV1;

static_assert(kDualSafeFp3EvaluationArgumentExecutableV1);
static_assert(kArbitraryMleAdapterExecutableV1);
static_assert(!kProductionAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_gkr_mle_adapter

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_GKR_MLE_ADAPTER_H
