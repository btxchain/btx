// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_ALG_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::episode_semantic_alg {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;

/**
 * Additive, recursion-native semantic-memory proof.
 *
 * V1 is the frozen SHA/per-column proof in episode_semantic.{h,cpp}.  V2
 * reuses the same canonical seven-column ProgramTable, but proves it with the
 * SAFE Split-RAP row-wise AlgHash backend:
 *
 *   R0   = ACTIVE, ADDRESS, REMAINING, ENDPOINT, ROLE, VALUE
 *   Rdep = EXPORT
 *   Rq   = quotient
 *
 * The complete ordered R0 root is supplied by the owning-value adapter and
 * pinned by `preprocessed_row_group_roots`.  It is not confused with
 * VectorRootAlg: the latter hashes LeafHash(value,index), while R0 hashes the
 * complete typed row with LeafHashRow.  Until a normalized parent proves the
 * equality between the owning producer cells and this R0 VALUE column,
 * `normalized_recursive_source` and `recursively_consumed` remain false.
 */
inline constexpr uint16_t kVersionV2 = 2;
inline constexpr uint32_t kMagicV2 = 0x32415345U; // "ESA2"
inline constexpr uint32_t kMaxRowsV2 =
    kRCStage3EpisodeSemanticMaxRows;
inline constexpr uint32_t kBaseColumnCountV2 = 6;

struct LeafManifestV2 {
    uint32_t magic{kMagicV2};
    uint16_t version{kVersionV2};
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t layer_ordinal{0};
    uint32_t shard_ordinal{0};
    uint32_t shard_count{0};
    uint64_t total_instance_count{0};
    uint64_t value_begin{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint64_t address_begin{0};
    uint64_t address_stride{1};
    uint256 statement_commitment{};
    uint256 producer_vector_root_alg{};
    uint256 program_table_sha256d{};
    uint256 program_table_alg{};
    uint256 schedule_commitment{};
    uint256 authority_r0_root{};
    uint256 expected_cs_commitment{};
    uint256 manifest_commitment{};

    bool operator==(const LeafManifestV2&) const = default;
};

/**
 * Generic g2-facing leaf tuple.  `expected_cs` is reconstructed by the
 * verifier and is deliberately not serialized in the receipt.
 */
struct LeafReceiptV2 {
    uint16_t version{kVersionV2};
    LeafManifestV2 manifest;
    std::vector<uint32_t> base_column_indices;
    uint256 public_fs_seed{};
    aq::AirQuotientSplitRapRowsProof proof;
    uint256 proof_commitment{};
    uint64_t proof_bytes{0};
    bool normalized_recursive_source{false};
    bool recursively_consumed{false};
};

struct BundleV2 {
    uint16_t version{kVersionV2};
    RCStage3RelationEndpoint endpoint{};
    uint32_t layer_ordinal{0};
    uint64_t total_instance_count{0};
    uint256 statement_commitment{};
    uint256 producer_vector_root_alg{};
    std::vector<LeafReceiptV2> leaves;
    uint256 exact_all_instance_commitment{};
    uint256 bundle_commitment{};
    bool host_owning_values_bound{false};
    bool normalized_recursive_source{false};
    bool recursively_consumed{false};
};

struct VerificationInputV2 {
    aq::AirConstraintSystem<gf::Fp3> expected_cs;
    std::vector<uint32_t> expected_base_column_indices;
    const aq::AirQuotientSplitRapRowsProof* proof{nullptr};
    uint256 public_fs_seed{};
    uint256 expected_cs_commitment{};
    bool valid{false};
    std::string note;
};

struct VerificationAuditV2 {
    uint32_t verified_leaves{0};
    uint64_t covered_instances{0};
    bool canonical_program_table{false};
    bool exact_partition{false};
    bool exact_addresses{false};
    bool all_safe_split_rap_proofs_verified{false};
    bool host_owning_values_bound{false};
    bool normalized_recursive_source{false};
    bool recursively_consumed{false};
    bool accepted{false};
    std::string note;
};

[[nodiscard]] bool IsSupportedEndpointV2(
    RCStage3RelationEndpoint endpoint);

[[nodiscard]] std::vector<uint32_t>
CanonicalBaseColumnsV2();

[[nodiscard]] uint64_t CanonicalAddressV2(
    RCStage3RelationEndpoint endpoint,
    uint32_t layer_ordinal,
    uint64_t value_ordinal);

[[nodiscard]] bool BuildCanonicalProgramTableV2(
    RCStage3RelationEndpoint endpoint,
    cb::ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateLeafManifestV2(
    const LeafManifestV2& manifest,
    std::string* why = nullptr);

[[nodiscard]] bool BuildExpectedConstraintSystemV2(
    const LeafManifestV2& manifest,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildWitnessV2(
    const LeafManifestV2& manifest,
    const std::vector<gf::Fp3>& values,
    std::vector<std::vector<gf::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] VerificationInputV2
BuildVerificationInputV2(
    const LeafReceiptV2& receipt);

/**
 * Honest flat adapter.  It recomputes the existing producer VectorRootAlg and
 * every ordered R0 root from `values`, then emits SAFE Split-RAP leaves.
 * This exact adapter is intentionally labelled host-linear.
 */
[[nodiscard]] bool ProveBundleWithOwningValuesV2(
    RCStage3RelationEndpoint endpoint,
    uint32_t layer_ordinal,
    const uint256& statement_commitment,
    const uint256& expected_producer_vector_root_alg,
    const std::vector<gf::Fp3>& values,
    BundleV2& out,
    std::string* why = nullptr);

/**
 * Succinct receipt verification.  This verifies canonical identity,
 * all-instance coverage and every native proof, but cannot by itself prove
 * that the producer's VectorRootAlg and the row-wise R0 root contain the same
 * values.
 */
[[nodiscard]] VerificationAuditV2 VerifyBundleV2(
    RCStage3RelationEndpoint expected_endpoint,
    uint32_t expected_layer_ordinal,
    const uint256& expected_statement_commitment,
    uint64_t expected_total_instance_count,
    const uint256& expected_producer_vector_root_alg,
    const BundleV2& bundle);

/**
 * Exact current-code source adapter.  Recomputes both commitment domains from
 * the owning values in addition to VerifyBundleV2.  It does not claim
 * sublinear or normalized recursive source closure.
 */
[[nodiscard]] VerificationAuditV2
VerifyBundleWithOwningValuesV2(
    RCStage3RelationEndpoint expected_endpoint,
    uint32_t expected_layer_ordinal,
    const uint256& expected_statement_commitment,
    const uint256& expected_producer_vector_root_alg,
    const std::vector<gf::Fp3>& values,
    const BundleV2& bundle);

[[nodiscard]] uint256 ComputeBundleCommitmentV2(
    const BundleV2& bundle);

inline constexpr bool kNativeSafeLeafExecutableV2 = true;
inline constexpr bool kNormalizedRecursiveSourceV2 = false;
inline constexpr bool kRecursiveConsumptionReadyV2 = false;
static_assert(kNativeSafeLeafExecutableV2);
static_assert(!kNormalizedRecursiveSourceV2);
static_assert(!kRecursiveConsumptionReadyV2);

} // namespace matmul::v4::rc::episode_semantic_alg

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_ALG_H
