// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_ALG_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic_alg.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::episode_semantic_source_alg {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;

using AlgAirProof =
    aq::AirQuotientProof<gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint16_t kUnifiedCtlVersionV2 = 2;
inline constexpr uint32_t kMagicV1 = 0x31425345U; // "ESB1"
inline constexpr uint32_t kEndpointCountV1 = 3;
inline constexpr uint32_t kMetadataColumnsPerEndpointV1 = 7;
inline constexpr uint32_t kMetadataColumnBaseV1 =
    kRCStage3GemmDotColumns;
inline constexpr uint32_t kTotalColumnsV1 =
    kMetadataColumnBaseV1 +
    kEndpointCountV1 * kMetadataColumnsPerEndpointV1;
inline constexpr uint32_t kMaxTraceRowsPerShardV1 = 1U << 20;

enum SourceEndpointSlotV1 : uint32_t {
    kOperandASlotV1 = 0,
    kOperandBSlotV1 = 1,
    kOutputYSlotV1 = 2,
};

struct SourceProjectionV1 {
    RCStage3RelationEndpoint endpoint{};
    uint32_t active_column{0};
    uint32_t address_column{0};
    uint32_t remaining_column{0};
    uint32_t endpoint_column{0};
    uint32_t role_column{0};
    /** Literal producer column. There is no copied VALUE witness. */
    uint32_t value_column{0};
    /** ACTIVE * producer VALUE, constrained in the same relation. */
    uint32_t semantic_value_column{0};
    uint32_t export_column{0};

    bool operator==(const SourceProjectionV1&) const = default;
};

[[nodiscard]] const std::array<
    SourceProjectionV1, kEndpointCountV1>&
CanonicalSourceProjectionsV1();

struct LayerShapeV1 {
    uint32_t magic{kMagicV1};
    uint16_t version{kVersionV1};
    uint256 statement_commitment{};
    uint256 gemm_manifest_commitment{};
    uint32_t layer_ordinal{0};
    uint32_t m{0};
    uint32_t n{0};
    uint32_t k{0};
    bool b_transpose{false};
    uint64_t tile_count{0};
    uint256 shape_commitment{};

    bool operator==(const LayerShapeV1&) const = default;
};

struct LeafManifestV1 {
    uint32_t magic{kMagicV1};
    uint16_t version{kVersionV1};
    LayerShapeV1 shape;
    uint64_t tile_begin{0};
    uint32_t tile_count{0};
    uint32_t tile_rows{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 program_table_sha256d{};
    uint256 program_table_alg{};
    uint256 schedule_commitment{};
    uint256 expected_cs_commitment{};
    uint256 manifest_commitment{};

    bool operator==(const LeafManifestV1&) const = default;
};

struct SameParentCtlJoinV1 {
    uint16_t version{kVersionV1};
    RCStage3RelationEndpoint endpoint{};
    uint32_t projection_slot{0};
    RCStage3CtlChallenges challenges;
    RCStage3CtlTerminal source_terminal;
    RCStage3CtlTerminal receiver_terminal;
    uint256 public_fs_seed{};
    uint256 base_row_commitment{};
    std::vector<uint32_t> base_column_indices;
    aq::AirQuotientSplitRapRowsProof proof;
    uint256 proof_commitment{};
    uint256 join_commitment{};
    bool source_value_same_trace_constrained{false};
    bool receiver_semantic_memory_executed{false};
    bool proof_owned_dual_alpha_terminal{false};
    bool same_parent_terminal_cancellation{false};
};

struct SameParentCtlVerificationInputV1 {
    aq::AirConstraintSystem<gf::Fp3> expected_cs;
    const aq::AirQuotientSplitRapRowsProof* proof{nullptr};
    std::vector<uint32_t> expected_base_column_indices;
    uint256 public_fs_seed{};
    bool valid{false};
    std::string note;
};

/**
 * Sound replacement for the three independent V1 CTL joins.
 *
 * One Split-RAP proof contains the GEMM source relation exactly once and all
 * three A/B/Y semantic-memory receivers.  Consequently A, B and Y cannot be
 * selected from different otherwise-valid GEMM witnesses.  All six CTL
 * sides are committed in one R0 before any of the three dual-alpha challenge
 * sets are derived.
 */
struct UnifiedSameParentCtlJoinV2 {
    uint16_t version{kUnifiedCtlVersionV2};
    std::array<RCStage3CtlChallenges, kEndpointCountV1>
        challenges;
    std::array<RCStage3CtlTerminal, kEndpointCountV1>
        source_terminals;
    std::array<RCStage3CtlTerminal, kEndpointCountV1>
        receiver_terminals;
    uint256 public_fs_seed{};
    /**
     * Exact row-tree commitment of the canonical source columns.  The
     * unified Split-RAP places precisely those columns in R0, so this root
     * must equal both proof.batch.groups[0].row_commit.root and the ordinary
     * Alg proof's trace_commit retained by the recursive hierarchy.
     */
    uint256 source_trace_commitment{};
    uint256 base_row_commitment{};
    std::vector<uint32_t> base_column_indices;
    aq::AirQuotientSplitRapRowsProof proof;
    uint256 proof_commitment{};
    uint256 join_commitment{};
    bool single_source_relation{false};
    bool all_receivers_executed{false};
    bool all_dual_alpha_terminals{false};
    bool all_terminal_cancellations{false};
};

struct UnifiedSameParentCtlVerificationInputV2 {
    aq::AirConstraintSystem<gf::Fp3> expected_cs;
    const aq::AirQuotientSplitRapRowsProof* proof{nullptr};
    std::vector<uint32_t> expected_base_column_indices;
    uint256 public_fs_seed{};
    bool valid{false};
    std::string note;
};

/**
 * Canonical ordinary AlgAir verifier leaf consumed by the retained recursive
 * parent.  `proof` owns the GEMM A/B/Y trace cells.  Each semantic VALUE is
 * the literal A, B or Y column in that same proof; only the public selector,
 * address, remaining, endpoint and role schedule is preprocessing.
 */
struct LeafReceiptV1 {
    uint16_t version{kVersionV1};
    LeafManifestV1 manifest;
    uint256 public_fs_seed{};
    AlgAirProof proof;
    std::array<SameParentCtlJoinV1, kEndpointCountV1>
        same_parent_ctl_joins;
    UnifiedSameParentCtlJoinV2 unified_same_parent_ctl_join;
    std::vector<unsigned char> canonical_proof_bytes;
    uint256 node_root{};
    uint256 program_root{};
    uint256 proof_context_root{};
    uint256 proof_commitment{};
    uint256 receipt_commitment{};
    uint32_t active_rows{0};
    uint32_t n_lde{0};
    bool quotient_division_exact{false};
    bool locally_verified{false};
};

struct LayerBundleV1 {
    uint16_t version{kVersionV1};
    LayerShapeV1 shape;
    std::vector<LeafReceiptV1> leaves;
    uint256 exact_coverage_commitment{};
    uint256 bundle_commitment{};
};

struct VerificationInputV1 {
    aq::AirConstraintSystem<gf::Fp3> expected_cs;
    const AlgAirProof* proof{nullptr};
    uint256 public_fs_seed{};
    uint256 node_root{};
    uint256 program_root{};
    uint256 proof_context_root{};
    uint256 statement_commitment{};
    uint256 expected_cs_commitment{};
    uint256 proof_commitment{};
    std::vector<unsigned char> canonical_proof_bytes;
    uint32_t active_rows{0};
    uint32_t n_lde{0};
    bool valid{false};
    std::string note;
};

struct BundleAuditV1 {
    uint64_t verified_tiles{0};
    uint64_t covered_operand_a{0};
    uint64_t covered_operand_b{0};
    uint64_t covered_output_y{0};
    bool exact_tile_order{false};
    bool canonical_program{false};
    bool direct_physical_value_aliases{false};
    bool exact_address_partition{false};
    bool every_alg_air_proof_verified{false};
    bool ordinary_recursive_leaf_compatible{false};
    bool source_owned{false};
    bool receiver_owned{false};
    bool dual_alpha_ctl_terminal{false};
    bool terminal_join{false};
    /** The source terminal is constrained by the same proof as the literal
     * A/B/Y cells and can be consumed by a recursive parent. */
    bool source_terminal_proof_owned{false};
    /** False until the normalized parent verifies the actual upstream
     * builder/previous-Extract receipt and cancels its producer terminal
     * against this source terminal.  The local semantic-memory receiver in
     * this leaf is not a substitute for that transitive edge. */
    bool external_producer_terminal_joined{false};
    bool strict_transitive_provenance{false};
    bool production_source_closed{false};
    bool accepted{false};
    std::string note;
};

inline constexpr uint16_t kExternalProducerClosureVersionV3 = 3;
inline constexpr uint32_t kExternalProducerClosureBusIdV3 =
    0x45585033U; // "EXP3"

/**
 * One post-R0 CTL child in the external producer -> semantic leaf bridge.
 *
 * The base group is not a copied VALUE witness.  For producer children it is
 * the exact R0 group of an episode_semantic_alg::LeafReceiptV2; for consumer
 * children it is the exact row commitment of LeafReceiptV1::proof.  The
 * challenge-dependent suffix contains only inverse/term/running columns.
 */
struct ExternalProducerCtlChildV3 {
    uint32_t child_ordinal{0};
    uint64_t active_rows{0};
    uint256 schedule_commitment{};
    uint256 owning_r0_root{};
    RCStage3CtlTerminal terminal{};
    aq::AirQuotientSplitRapRowsProof proof;
    uint256 proof_commitment{};
};

/**
 * Executable all-shard rational-identity bridge for one A, B or Y endpoint.
 *
 * `producer_bundle` proves the complete canonical flat producer vector under
 * its manifest-owned Poseidon VectorRootAlg. `consumer_children` extend the
 * actual GEMM semantic leaf relations.  One challenge is derived only after
 * the ordered aggregate of every producer and consumer R0 root is fixed.
 * Exact address coverage plus dual-Fp3 terminal cancellation therefore proves
 * that the two proof-owned multisets are equal without consulting host values
 * during verification.
 */
struct ExternalProducerClosureV3 {
    uint16_t version{kExternalProducerClosureVersionV3};
    RCStage3RelationEndpoint endpoint{};
    uint32_t projection_slot{0};
    LayerShapeV1 shape;
    episode_semantic_alg::BundleV2 producer_bundle;
    RCStage3CtlManifest manifest;
    RCStage3CtlChallenges challenges;
    std::vector<ExternalProducerCtlChildV3> consumer_children;
    std::vector<ExternalProducerCtlChildV3> producer_children;
    uint256 closure_commitment{};
    bool all_r0_before_challenge{false};
    bool exact_producer_coverage{false};
    bool exact_consumer_coverage{false};
    bool proof_owned_terminal_cancellation{false};
};

/**
 * Honest prover for the exact shared-epoch bridge. `layer` and `extract` are
 * prover witnesses only; verification below consumes no native values.
 */
[[nodiscard]] bool ProveExternalProducerClosureV3(
    const LayerShapeV1& shape,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    const LayerBundleV1& consumer_bundle,
    uint32_t projection_slot,
    const uint256& expected_producer_vector_root_alg,
    ExternalProducerClosureV3& out,
    std::string* why = nullptr);

/**
 * Proof-only verifier.  The expected producer root is supplied by the
 * verifier-owned production GEMM/wiring manifest; no host vector is accepted.
 */
[[nodiscard]] bool VerifyExternalProducerClosureV3(
    const LayerShapeV1& expected_shape,
    const LayerBundleV1& expected_consumer_bundle,
    uint32_t expected_projection_slot,
    const uint256& expected_producer_vector_root_alg,
    const ExternalProducerClosureV3& closure,
    std::string* why = nullptr);

inline constexpr uint16_t
    kGemmDotExternalClosureVersionV4 = 4;

/**
 * SAFE Alg migration of the actual GEMM-dot relation into the semantic CTL
 * epoch.  Each producer child keeps the canonical GEMM input group
 * [ACTIVE,START,END,A,B,Y,RESIDUAL,EXTRACT_INPUT] as R0 and places only
 * PRODUCT/ACCUMULATOR plus CTL columns in Rdep.  The legacy SHA column roots
 * are neither asserted equal nor used as authority.
 */
struct GemmDotExternalClosureV4 {
    uint16_t version{
        kGemmDotExternalClosureVersionV4};
    RCStage3RelationEndpoint endpoint{};
    uint32_t projection_slot{0};
    LayerShapeV1 shape;
    uint256 producer_authority_commitment{};
    RCStage3CtlManifest manifest;
    RCStage3CtlChallenges challenges;
    std::vector<ExternalProducerCtlChildV3>
        consumer_children;
    std::vector<ExternalProducerCtlChildV3>
        producer_children;
    uint256 closure_commitment{};
    bool all_r0_before_challenge{false};
    bool exact_producer_coverage{false};
    bool exact_consumer_coverage{false};
    bool proof_owned_terminal_cancellation{false};
};

/**
 * Prover witness is reconstructed from the captured GEMM product, but the
 * resulting verifier consumes only the migrated SAFE proof objects and the
 * public layer shape. Legacy SHA roots are absent from both the V4 witness
 * construction and its authority statement.
 */
[[nodiscard]] bool ProveGemmDotExternalClosureV4(
    const LayerShapeV1& shape,
    const RCStage3GemmExtractLayerManifest& spec,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    const LayerBundleV1& consumer_bundle,
    uint32_t projection_slot,
    GemmDotExternalClosureV4& out,
    std::string* why = nullptr);

/** Proof-only verifier for the migrated GEMM-input -> semantic-leaf edge. */
[[nodiscard]] bool VerifyGemmDotExternalClosureV4(
    const LayerShapeV1& expected_shape,
    const LayerBundleV1& expected_consumer_bundle,
    uint32_t expected_projection_slot,
    const GemmDotExternalClosureV4& closure,
    std::string* why = nullptr);

[[nodiscard]] bool BuildLayerShapeV1(
    const uint256& statement_commitment,
    const uint256& gemm_manifest_commitment,
    const RCStage3GemmExtractLayerManifest& spec,
    LayerShapeV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeLayerShapeCommitmentV1(
    const LayerShapeV1& shape);

[[nodiscard]] bool BuildCanonicalProgramTableV1(
    cb::ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildLeafManifestV1(
    const LayerShapeV1& shape,
    uint64_t tile_begin,
    uint32_t tile_count,
    LeafManifestV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildExpectedConstraintSystemV1(
    const LeafManifestV1& manifest,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildLeafWitnessV1(
    const LeafManifestV1& manifest,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    std::vector<std::vector<gf::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] bool ProveLeafV1(
    const LeafManifestV1& manifest,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    LeafReceiptV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifySameParentCtlJoinV1(
    const LeafManifestV1& manifest,
    const SameParentCtlJoinV1& join,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyUnifiedSameParentCtlJoinV2(
    const LeafManifestV1& manifest,
    const UnifiedSameParentCtlJoinV2& join,
    std::string* why = nullptr);

[[nodiscard]] UnifiedSameParentCtlVerificationInputV2
BuildUnifiedSameParentCtlVerificationInputV2(
    const LeafManifestV1& manifest,
    const UnifiedSameParentCtlJoinV2& join);

[[nodiscard]] SameParentCtlVerificationInputV1
BuildSameParentCtlVerificationInputV1(
    const LeafManifestV1& manifest,
    const SameParentCtlJoinV1& join);

[[nodiscard]] bool VerifyLeafV1(
    const LayerShapeV1& expected_shape,
    uint64_t expected_tile_begin,
    uint32_t expected_tile_count,
    const LeafReceiptV1& receipt,
    std::string* why = nullptr);

[[nodiscard]] VerificationInputV1 BuildVerificationInputV1(
    const LeafReceiptV1& receipt);

[[nodiscard]] bool ProveLayerBundleV1(
    const LayerShapeV1& shape,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    LayerBundleV1& out,
    std::string* why = nullptr);

[[nodiscard]] BundleAuditV1 VerifyLayerBundleV1(
    const LayerShapeV1& expected_shape,
    const LayerBundleV1& bundle);

[[nodiscard]] uint256 ComputeLeafReceiptCommitmentV1(
    const LeafReceiptV1& receipt);
[[nodiscard]] uint256 ComputeLayerBundleCommitmentV1(
    const LayerBundleV1& bundle);

inline constexpr bool kDirectPhysicalSourceAliasesV1 = true;
inline constexpr bool kOrdinaryAlgLeafExecutableV1 = true;
/** g2 must still consume every canonical leaf before authority can turn on. */
inline constexpr bool kRecursiveConsumptionReadyV1 = false;
static_assert(kDirectPhysicalSourceAliasesV1);
static_assert(kOrdinaryAlgLeafExecutableV1);
static_assert(!kRecursiveConsumptionReadyV1);

} // namespace matmul::v4::rc::episode_semantic_source_alg

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_SOURCE_ALG_H
