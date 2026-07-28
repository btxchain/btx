// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RELATION_CLOSURE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RELATION_CLOSURE_H

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>
#include <matmul/matmul_v4_rc_stage3_unified_root.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

struct RCStage3GemmExtractManifest;
struct RCStage3EpisodeExtractProduct;
struct RCStage3EpisodeTileStreamProduct;
struct RCStage3ExtractStreamCtlTileProof;
struct RCStage3SignedRangePin;
struct RCStage3SignedRangeExecutedCtlBinding;

// ============================================================================
// Stage-3 V1 relation-root closure.
//
// The individual Stage-3 AIRs expose heterogeneous proof statements.  Fusing
// all of them into one trace would force the largest width/degree/padding
// profile on every relation.  V1 instead uses one canonical role bundle per
// registered relation and one recursive child per exact semantic endpoint.
// The bundle is a hash-bound multiproof ledger:
//
//   relation endpoint -> proof-column root -> recursive child commitment
//                     -> executed role CTL VALUE root
//
// It closes omission, relabelling and root-substitution at the aggregation
// boundary.  It does not turn an opaque child commitment into a proof: the
// normalized recursive verifier must execute every named child before this
// bundle can become authority.  Consequently all authority flags remain off.
// ============================================================================

inline constexpr uint32_t kRCStage3RelationClosureMagic =
    0x31434c52U; // "RLC1"
inline constexpr uint16_t kRCStage3RelationClosureVersion = 1;
inline constexpr uint16_t kRCStage3RelationClosureRoleCount =
    kRCStage3UnifiedRoleCount;
inline constexpr uint16_t kRCStage3RelationClosureEndpointCount = 52;

enum class RCStage3RelationClosureStrategy : uint8_t {
    OneProofPerRole = 1,
    FusedCompatibleAir = 2,
    HashBoundMultiproof = 3,
};

/** Globally unique, versioned endpoint identifiers.  Values are format ABI. */
enum class RCStage3RelationEndpoint : uint16_t {
    EpisodeBuilderParams = 1,
    EpisodeBuilderSeedChain = 2,
    EpisodeBuilderOperandXof = 3,
    EpisodeBuilderTrace = 4,

    EpisodeGemmOperandA = 5,
    EpisodeGemmOperandB = 6,
    EpisodeGemmOutputY = 7,
    EpisodeGemmSumcheck = 8,
    EpisodeGemmSignedRange = 9,

    EpisodeExtractInput = 10,
    EpisodeExtractSampler = 11,
    EpisodeExtractChaCha = 12,
    EpisodeExtractScale = 13,
    EpisodeExtractOutput = 14,

    EpisodeWiringCopy = 15,
    EpisodeWiringTranspose = 16,
    EpisodeWiringResidual = 17,
    EpisodeWiringRoundOrder = 18,

    EpisodeTileTreeStream = 19,
    EpisodeTileTreeLeafHash = 20,
    EpisodeTileTreeInternalHash = 21,
    EpisodeTileTreeRoot = 22,

    EpisodeDigestRoundRoots = 23,
    EpisodeDigestValue = 24,
    EpisodeDigestHeaderTarget = 25,
    EpisodeDigestPow = 26,

    CoupledBankSeedXof = 27,
    CoupledBankPages = 28,
    CoupledBankRoot = 29,

    CoupledGemmOperandA = 30,
    CoupledGemmOperandB = 31,
    CoupledGemmOutputY = 32,
    CoupledGemmSignedRange = 33,

    CoupledExchangeInput = 34,
    CoupledExchangeHashXof = 35,
    CoupledExchangeOutput = 36,

    CoupledPermutationInput = 37,
    CoupledPermutationOutput = 38,

    CoupledMixInput = 39,
    CoupledMixArithmetic = 40,
    CoupledMixOutput = 41,

    CoupledExtractInput = 42,
    CoupledExtractSampler = 43,
    CoupledExtractChaCha = 44,
    CoupledExtractScale = 45,
    CoupledExtractOutput = 46,

    CoupledBarrierInput = 47,
    CoupledBarrierHash = 48,
    CoupledBarrierOutput = 49,

    CoupledDigestBankAndBarriers = 50,
    CoupledDigestHash = 51,
    CoupledDigestValue = 52,
};

struct RCStage3RelationEndpointPin {
    RCStage3RelationEndpoint endpoint{};
    /** Exact number of instances folded into this endpoint child. */
    uint64_t instance_count{0};
    /** Commitment to the immutable instance schedule/manifest. */
    uint256 manifest_root{};
    /** Root/commitment emitted by the relation proof engine. */
    uint256 proof_root{};
    /** Semantic relation value, separately from the proof-column Merkle root. */
    uint256 semantic_root{};
    /** Merkle root of the proof column exported to this role's CTL child. */
    uint256 proof_column_root{};
    /** Commitment to the recursive child which verifies this endpoint. */
    uint256 recursive_child_commitment{};

    bool operator==(const RCStage3RelationEndpointPin&) const = default;
};

struct RCStage3RelationRoleClosure {
    RCStage3RelationRole role{};
    uint256 relation_commitment{};
    uint256 relation_statement_root{};
    std::vector<RCStage3RelationEndpointPin> endpoints;
    /** Recomputed hash of the exact ordered endpoint vector. */
    uint256 endpoint_multiproof_root{};

    bool operator==(const RCStage3RelationRoleClosure&) const = default;
};

struct RCStage3RelationClosureV1 {
    uint32_t magic{kRCStage3RelationClosureMagic};
    uint16_t version{kRCStage3RelationClosureVersion};
    RCStage3RelationClosureStrategy strategy{
        RCStage3RelationClosureStrategy::HashBoundMultiproof};
    uint256 unified_root_seed{};
    uint256 statement_commitment{};
    uint256 ctl_proof_bundle_commitment{};
    std::vector<RCStage3RelationRoleClosure> roles;

    /** The final SHA256d relation is carried by CompositionLink, not one of
     * the fourteen role leaves. */
    uint256 composition_link_commitment{};
    uint256 final_digest_manifest_root{};
    uint256 final_digest_proof_root{};
    uint256 final_digest_semantic_root{};
    uint256 final_digest_recursive_child_commitment{};

    /** Hash of every field above. */
    uint256 closure_commitment{};

    bool operator==(const RCStage3RelationClosureV1&) const = default;
};

struct RCStage3RelationClosureStrategyAssessment {
    RCStage3RelationClosureStrategy strategy{};
    uint16_t registered_roles{0};
    uint16_t registered_endpoints{0};
    bool compatible_with_current_heterogeneous_airs{false};
    bool proof_derived_root_binding_possible{false};
    bool recursive_execution_complete{false};
    std::string finding;
};

struct RCStage3RelationClosureRoleAudit {
    RCStage3RelationRole role{};
    uint16_t required_endpoints{0};
    /** Endpoints which currently have an executable relation verifier and an
     * equality check from its committed witness column into executed CTL. */
    uint16_t proof_derived_ctl_endpoints{0};
    bool recursive_ctl_consumption{false};
    bool role_complete{false};
    std::string remaining;
};

/**
 * Proof-cell provenance for one semantic endpoint.
 *
 * `relation_air_cell` means that an immutable, locally-resolved relation AIR
 * exposes the named witness cell. `same_trace_ctl_alias` additionally means
 * that the relation AIR can be composed with the CTL accumulator in one AIR,
 * with a degree-one identity from that exact cell to CTL::VALUE. Neither bit
 * is inferred from a hash, manifest entry, callback result, or claimed root.
 *
 * `semantic_relation_complete` is deliberately separate: a locally proved
 * GEMM A cell, for example, is not a commitment opening against the episode
 * operand root.  It remains a local-relation fact and must not be reported as
 * strict transitive semantic closure. `producer_provenance_complete` is true
 * only for a consensus/public anchor or after every immediate producer edge
 * is equality-constrained to an executed proof. `strict_transitive_complete`
 * is their conjunction. `recursive_child_consumed` is true only after a
 * recursive verifier executes the composed proof; it is false for all current
 * entries.
 */
struct RCStage3RelationEndpointCellAudit {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    bool relation_air_cell{false};
    bool same_trace_ctl_alias{false};
    bool semantic_relation_complete{false};
    bool producer_provenance_complete{false};
    bool strict_transitive_complete{false};
    bool recursive_child_consumed{false};
    uint32_t relation_column{0};
    std::string source;
    std::string remaining;
};

/**
 * Column layout of the selected direct-product construction:
 *
 *   [ relation trace | CTL trace ]
 *
 * The complete immutable relation constraint system is copied into the
 * product. The complete dual-lane CTL constraint system is shifted by
 * `ctl_column_base`, and the additional degree-one relation
 *
 *   relation[source_column] - ctl[VALUE] = 0
 *
 * holds on every row. This is stronger than comparing two host-supplied roots:
 * the two values are the same cells in one proof. It is also narrower than a
 * detached LogUp claim: LogUp proves bus multiset equality while the direct
 * alias proves provenance of every bus value.
 */
struct RCStage3RelationCtlDirectAliasLayout {
    uint32_t relation_columns{0};
    uint32_t ctl_column_base{0};
    uint32_t total_columns{0};
    uint32_t source_column{0};
    uint32_t ctl_value_column{0};
    bool same_trace{false};
    bool direct_alias{false};
};

/**
 * Signed-range dual-port product:
 *
 *   [ signed-range relation | producer CTL | Extract-consumer CTL ]
 *
 * Both CTL VALUE columns are constrained to the one signed-range VALUE
 * column in the same quotient proof.  This is the production endpoint-9
 * topology: proving two detached VALUE-root equalities is insufficient
 * because it does not constrain either lookup accumulator to the range
 * witness cells.
 */
struct RCStage3SignedRangeDualCtlDirectAliasLayout {
    RCStage3RelationCtlDirectAliasLayout producer;
    RCStage3RelationCtlDirectAliasLayout consumer;
    uint32_t range_columns{0};
    uint32_t producer_ctl_column_base{0};
    uint32_t consumer_ctl_column_base{0};
    uint32_t total_columns{0};
    uint32_t source_column{0};
    bool same_trace_dual_alias{false};
};

inline constexpr uint16_t kRCStage3BuilderProgramAliasVersionV1 = 1;
inline constexpr uint32_t kRCStage3BuilderProgramAliasLaneCountV1 = 4;

/**
 * Verifier-owned pin for the canonical EpisodeBuilderCounterXof ProgramTable.
 * Both program commitments are recomputed from the selected production table;
 * every trace-column root is then compared to the shared proof.
 */
struct RCStage3BuilderProgramAirPublicPinV1 {
    uint16_t version{kRCStage3BuilderProgramAliasVersionV1};
    uint256 statement_commitment{};
    uint32_t n_rows{0};
    uint256 program_external_sha256d{};
    alg_hash::Digest program_recursive_alg_hash{};
    std::vector<uint256> relation_column_roots;

    bool operator==(
        const RCStage3BuilderProgramAirPublicPinV1&) const = default;
};

/** One independently domain-separated CTL participant carried by the builder
 * product. The four lanes are fixed, in endpoint order Params, SeedChain,
 * OperandXof, Trace. */
struct RCStage3BuilderProgramCtlLaneV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3CtlManifest manifest;
    std::vector<RCStage3CtlChildPin> pins;
    size_t participant_index{0};
    RCStage3CtlSchedule schedule;
};

struct RCStage3BuilderProgramCtlDirectAliasLayoutV1 {
    uint32_t relation_columns{0};
    uint32_t total_columns{0};
    std::array<RCStage3RelationCtlDirectAliasLayout,
               kRCStage3BuilderProgramAliasLaneCountV1> lanes;
    bool canonical_program_selected{false};
    bool all_four_same_trace{false};
};

inline constexpr uint16_t kRCStage3EpisodeGemmProgramBatchVersionV1 = 1;
inline constexpr uint32_t kRCStage3EpisodeGemmProgramBatchLaneCountV1 = 4;
inline constexpr uint32_t kRCStage3EpisodeGemmProgramBatchBusBaseV1 =
    0x47200000U;

/**
 * Public roots for the exact EpisodeGemmSumcheck ProgramTable.  The signed
 * range half of the product is pinned by RCStage3SignedRangePin; its 33
 * parameter columns are verifier-recomputed from max_abs/logical_rows.
 */
struct RCStage3EpisodeGemmProgramAirPublicPinV1 {
    uint16_t version{kRCStage3EpisodeGemmProgramBatchVersionV1};
    uint256 statement_commitment{};
    uint32_t n_rows{0};
    uint32_t layer_ordinal{0};
    uint256 gemm_program_external_sha256d{};
    alg_hash::Digest gemm_program_recursive_alg_hash{};
    uint256 range_program_external_sha256d{};
    alg_hash::Digest range_program_recursive_alg_hash{};
    /** Canonical GEMM order is GF/Y, A, B. */
    std::array<uint256, 3> gemm_column_roots{};
};

/** Canonical two-participant CTL lane.  pins[0] is the EpisodeGemm producer
 * proved in this product; pins[1] is the opposite CompositionLink BUS PORT.
 * The latter accumulator is proof-owned here, but its source relation and
 * recursive child remain outside this proof.  Consequently this type alone
 * is not evidence of consumer arithmetic or recursive semantic closure. */
struct RCStage3EpisodeGemmProgramCtlLaneV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3CtlManifest manifest;
    std::array<RCStage3CtlChildPin, 2> pins;
};

struct RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1 {
    uint32_t gemm_columns{0};
    uint32_t range_column_base{0};
    uint32_t range_columns{0};
    uint32_t relation_columns{0};
    uint32_t total_columns{0};
    std::array<RCStage3RelationCtlDirectAliasLayout,
               kRCStage3EpisodeGemmProgramBatchLaneCountV1>
        producer_lanes;
    std::array<RCStage3RelationCtlDirectAliasLayout,
               kRCStage3EpisodeGemmProgramBatchLaneCountV1>
        consumer_lanes;
    bool canonical_programs_selected{false};
    /** Manifest/range-shard identity is in the proof seed.  Vector-root
     * ownership remains the existing semantic-opening relation. */
    bool manifest_context_bound{false};
    bool all_four_dual_port_bus_relations{false};
    /** These remain false until the canonical consumer relation programs and
     * their recursive verifier children are composed into the same parent.
     * A proof-owned receive accumulator is not a consumer relation proof. */
    bool consumer_relation_programs_included{false};
    bool consumer_arithmetic_owned{false};
    bool recursive_children_consumed{false};
    bool semantic_closure{false};
};

inline constexpr uint16_t
    kRCStage3EpisodeExtractProgramBatchVersionV1 = 1;
inline constexpr uint32_t
    kRCStage3EpisodeExtractProgramBatchLaneCountV1 = 4;
inline constexpr uint32_t
    kRCStage3EpisodeExtractProgramBatchBusBaseV1 = 0x45800000U;

/**
 * Verifier-owned selection of the exact EpisodeExtractCore ProgramTable.
 * `episode_air.extract_scale_e` is part of the public shard pin and selects
 * the bytecode table; both commitments are recomputed for that exact scale.
 */
struct RCStage3EpisodeExtractProgramAirPublicPinV1 {
    uint16_t version{kRCStage3EpisodeExtractProgramBatchVersionV1};
    RCStage3EpisodeAirPublicPin episode_air;
    uint256 program_external_sha256d{};
    alg_hash::Digest program_recursive_alg_hash{};
};

/**
 * One immutable producer-side ExtractCore CTL lane.  pins[0] is the
 * EpisodeExtract producer proved in the shared product.  pins[1] is only the
 * external counterparty prechallenge pin needed to derive the link challenge;
 * its accumulator/relation is not appended or claimed here.
 */
struct RCStage3EpisodeExtractProgramCtlLaneV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3CtlManifest manifest;
    std::array<RCStage3CtlChildPin, 2> pins;
};

struct RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1 {
    uint32_t relation_columns{0};
    uint32_t total_columns{0};
    std::array<RCStage3RelationCtlDirectAliasLayout,
               kRCStage3EpisodeExtractProgramBatchLaneCountV1>
        producer_lanes;
    bool canonical_program_selected{false};
    bool verifier_scale_bound{false};
    bool all_four_producer_same_trace{false};
    /** Explicit residuals: the core relation does not prove the ChaCha byte
     * source, consume its counterpart relations, or close the role. */
    bool chacha_provenance_included{false};
    bool recursive_children_consumed{false};
    bool role_complete{false};
};

/**
 * Exact endpoint-14 -> endpoint-19 extension of the canonical ExtractCore
 * product.  The first four layouts retain the independently challenged
 * producer aliases above.  `receiver_*` is an additional selected-row CTL
 * over the SAME kColOut source column, using the exact challenge and terminal
 * of an executed RCStage3ExtractStreamCtlTileProof.  Thus the output lane is
 * not closed by an unattached counterparty pin: the producer alias and the
 * proof-owned semantic-memory EXPORT receiver execute under one dual-Fp3
 * rational identity.
 */
struct RCStage3EpisodeExtractOutputReceiverLayoutV1 {
    RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1 producer;
    uint32_t receiver_mask_column{0};
    uint32_t receiver_address_column{0};
    uint32_t receiver_inverse1_column{0};
    uint32_t receiver_inverse2_column{0};
    uint32_t receiver_running1_column{0};
    uint32_t receiver_running2_column{0};
    uint32_t total_columns{0};
    bool receiver_proof_executed{false};
    bool exact_selected_schedule{false};
    bool output_source_same_trace{false};
    bool shared_dual_fp3_challenges{false};
    bool opposing_terminals{false};
};

/** Fail-closed accounting for the consolidated proof.  Exactly one endpoint
 * family becomes strictly transitive in V1: EpisodeExtractOutput (14) to
 * EpisodeTileTreeStream (19).  The ChaCha/scale counterpart ownership and
 * recursive role consumption deliberately remain residual. */
struct RCStage3EpisodeExtractOutputReceiverAuditV1 {
    uint16_t producer_endpoint_families{0};
    uint16_t strictly_transitive_endpoint_families{0};
    RCStage3RelationEndpoint producer_endpoint{};
    RCStage3RelationEndpoint receiver_endpoint{};
    bool producer_alias_product_verified{false};
    bool authoritative_receiver_product_verified{false};
    bool sampler_output_root_equal{false};
    bool semantic_value_root_bound{false};
    bool semantic_export_root_bound{false};
    bool exact_selected_schedule{false};
    bool shared_dual_fp3_challenges{false};
    bool opposing_terminals{false};
    bool chacha_output_proof_owned{false};
    bool scale_output_proof_owned{false};
    bool recursive_children_consumed{false};
    bool role_complete{false};
};

/** Exact-row variant using the degree-two CTL layout.  Unlike the generic
 * padded CTL, this product keeps n_coeffs == n_rows, so an existing
 * relation-owned VALUE root can be reused verbatim as the CTL VALUE root. */
struct RCStage3RelationCtlDegree2DirectAliasLayout {
    uint32_t relation_columns{0};
    uint32_t ctl_column_base{0};
    uint32_t total_columns{0};
    uint32_t source_column{0};
    uint32_t ctl_value_column{0};
    bool same_trace{false};
    bool direct_alias{false};
    bool exact_row_degree_two{false};
};

/** One lossless row-multiplexing arm. `mask_column` must be a verifier-owned,
 * canonical boolean preprocessed column in the relation AIR. Masks in one
 * export must be pairwise disjoint on every row. */
struct RCStage3RelationCtlMaskedSource {
    uint32_t source_column{0};
    uint32_t mask_column{0};

    bool operator==(const RCStage3RelationCtlMaskedSource&) const = default;
};

struct RCStage3RelationCtlMaskedAliasLayout {
    uint32_t relation_columns{0};
    uint32_t ctl_column_base{0};
    uint32_t total_columns{0};
    uint32_t ctl_value_column{0};
    std::vector<RCStage3RelationCtlMaskedSource> sources;
    bool preprocessed_masks{false};
    bool masks_boolean_and_disjoint{false};
    bool same_trace{false};
};

[[nodiscard]] bool BuildRCStage3RelationCtlDirectAliasConstraintSystem(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& relation_cs,
    const RCStage3CtlAirSpec& ctl_spec,
    uint32_t source_column,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3RelationCtlDirectAliasLayout* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3RelationCtlDirectAliasWitness(
    const RCStage3RelationCtlDirectAliasLayout& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const RCStage3CtlWitness& ctl_witness,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

/**
 * Resolve endpoint 9 from verifier-owned manifest/pin data and both executed
 * child pins.  Challenges are derived from the two prechallenge commitments;
 * the caller cannot supply a mutable relation callback or challenge.
 */
[[nodiscard]] bool
BuildRCStage3SignedRangeDualCtlDirectAliasConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeExecutedCtlBinding& binding,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3SignedRangeDualCtlDirectAliasLayout* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3SignedRangeDualCtlDirectAliasWitness(
    const RCStage3SignedRangeDualCtlDirectAliasLayout& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& range_columns,
    const RCStage3CtlWitness& producer,
    const RCStage3CtlWitness& consumer,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

/** Proof-independent Fiat-Shamir seed for the complete dual-port product. */
[[nodiscard]] uint256 ComputeRCStage3SignedRangeDualCtlDirectAliasSeed(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeExecutedCtlBinding& binding);

/**
 * Postchallenge commitment for one CTL lane inside the shared proof.
 * `producer_lane` selects the producer or Extract-consumer accumulator.  The
 * commitment binds the lane's inverse/running columns and the one shared
 * quotient root, so a child receipt cannot be detached from this product.
 */
[[nodiscard]] uint256
ComputeRCStage3SignedRangeDualCtlAuxiliaryCommitment(
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    const RCStage3SignedRangeDualCtlDirectAliasLayout& layout,
    bool producer_lane);

/**
 * Verify one complete endpoint-9 proof.  The verifier reconstructs the
 * signed-range AIR, both schedules, both CTL AIRs, challenges, direct aliases
 * and public terminal composition.  Recursive consumption remains a separate
 * fail-closed obligation.
 */
[[nodiscard]] bool VerifyRCStage3SignedRangeDualCtlDirectAliasProof(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeExecutedCtlBinding& binding,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/**
 * One proof for all four deterministic-builder endpoints:
 *
 *   [ canonical 21-column builder ProgramTable | four CTL traces ].
 *
 * The verifier rebuilds the production-selected table and the endpoint-column
 * routing. No callback, output column, program key or challenge is accepted
 * from the prover.
 */
[[nodiscard]] bool
BuildRCStage3BuilderProgramCtlDirectAliasConstraintSystemV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    const std::array<RCStage3BuilderProgramCtlLaneV1,
                     kRCStage3BuilderProgramAliasLaneCountV1>& lanes,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3BuilderProgramCtlDirectAliasLayoutV1* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool
BuildRCStage3BuilderProgramCtlDirectAliasWitnessV1(
    const RCStage3BuilderProgramCtlDirectAliasLayoutV1& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3BuilderProgramAliasLaneCountV1>& ctl_witnesses,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRCStage3BuilderProgramCtlDirectAliasSeedV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    const std::array<RCStage3BuilderProgramCtlLaneV1,
                     kRCStage3BuilderProgramAliasLaneCountV1>& lanes);

[[nodiscard]] bool
VerifyRCStage3BuilderProgramCtlDirectAliasProofV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    const std::array<RCStage3BuilderProgramCtlLaneV1,
                     kRCStage3BuilderProgramAliasLaneCountV1>& lanes,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/** Exact send/receive bus schedule for one of A, B, Y or SignedRange.
 * This describes the CTL ports only; it does not attest that the receive
 * port's source relation or recursive child is present. */
[[nodiscard]] RCStage3CtlSchedule
BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    RCStage3RelationEndpoint endpoint,
    bool producer);

/** Domain-separated prechallenge seed for a canonical GEMM batch lane. */
[[nodiscard]] uint256
ComputeRCStage3EpisodeGemmProgramCtlTranscriptSeedV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    RCStage3RelationEndpoint endpoint);

[[nodiscard]] bool
BuildRCStage3EpisodeGemmProgramCtlDirectAliasConstraintSystemV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeGemmProgramCtlLaneV1,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>& lanes,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1* layout = nullptr,
    std::string* why = nullptr);

/** Materialize the exact four dual-port bus relations.  Both accumulator
 * traces are proof-owned and directly alias the EpisodeGemm-side canonical
 * program cells.  The consumer relation programs are deliberately absent;
 * consult the fail-closed layout fields before any completeness accounting. */
[[nodiscard]] bool
BuildRCStage3EpisodeGemmProgramCtlDirectAliasWitnessV1(
    const RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& gemm_columns,
    const std::vector<std::vector<gkr_field::Fp3>>&
        signed_range_program_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        producer_ctl_witnesses,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        consumer_ctl_witnesses,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRCStage3EpisodeGemmProgramCtlDirectAliasSeedV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeGemmProgramCtlLaneV1,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>& lanes);

[[nodiscard]] bool
VerifyRCStage3EpisodeGemmProgramCtlDirectAliasProofV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeGemmProgramCtlLaneV1,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>& lanes,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/** Immutable all-row send/receive schedule for Input, Sampler, Scale or
 * Output. Namespace, shard, occurrence address and multiplicity are derived
 * solely from the verifier-owned pin and endpoint. */
[[nodiscard]] RCStage3CtlSchedule
BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    RCStage3RelationEndpoint endpoint,
    bool producer);

[[nodiscard]] uint256
ComputeRCStage3EpisodeExtractProgramCtlTranscriptSeedV1(
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    RCStage3RelationEndpoint endpoint);

[[nodiscard]] bool
BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>& lanes,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1* layout = nullptr,
    std::string* why = nullptr);

/** Rejects raw non-canonical Goldilocks representatives before materializing
 * the four producer CTLs; x and x+p must never be interchangeable at this
 * witness-ingress boundary. */
[[nodiscard]] bool
BuildRCStage3EpisodeExtractProgramCtlDirectAliasWitnessV1(
    const RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        producer_ctl_witnesses,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRCStage3EpisodeExtractProgramCtlDirectAliasSeedV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>& lanes);

[[nodiscard]] bool
VerifyRCStage3EpisodeExtractProgramCtlDirectAliasProofV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>& lanes,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/**
 * Build/prove/verify seam for the authoritative endpoint-14 -> endpoint-19
 * receiver.  The receiver proof is executed before its exact 32-row schedule,
 * proof-owned roots, challenge commitment and opposing terminal are admitted
 * into the augmented producer product.
 */
[[nodiscard]] bool
BuildRCStage3EpisodeExtractOutputReceiverConstraintSystemV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>& lanes,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3EpisodeExtractOutputReceiverLayoutV1* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool
BuildRCStage3EpisodeExtractOutputReceiverWitnessV1(
    const RCStage3EpisodeExtractOutputReceiverLayoutV1& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        producer_ctl_witnesses,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRCStage3EpisodeExtractOutputReceiverSeedV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>& lanes,
    const RCStage3ExtractStreamCtlTileProof& receiver);

[[nodiscard]] bool
VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>& lanes,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    RCStage3EpisodeExtractOutputReceiverAuditV1* audit = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool
BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& relation_cs,
    const RCStage3CtlDegree2AirSpec& ctl_spec,
    uint32_t source_column,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3RelationCtlDegree2DirectAliasLayout* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3RelationCtlDegree2DirectAliasWitness(
    const RCStage3RelationCtlDegree2DirectAliasLayout& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const RCStage3CtlDegree2Witness& ctl_witness,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

/**
 * Lossless fixed masked export:
 *
 *   ctl[VALUE](r) = sum_j mask_j(r) * relation[source_j](r).
 *
 * Booleanity and pairwise disjointness are checked from locally supplied
 * preprocessed mask values before the AIR is constructed. This permits a
 * fixed boundary stream spread over different relation columns and rows to
 * feed CTL without a host fixture or a random linear-combination claim.
 * Several live words on the same row require separate CTL lanes.
 */
[[nodiscard]] bool BuildRCStage3RelationCtlMaskedAliasConstraintSystem(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& relation_cs,
    const RCStage3CtlAirSpec& ctl_spec,
    const std::vector<RCStage3RelationCtlMaskedSource>& sources,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    RCStage3RelationCtlMaskedAliasLayout* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3RelationCtlMaskedAliasWitness(
    const RCStage3RelationCtlMaskedAliasLayout& layout,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const RCStage3CtlWitness& ctl_witness,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

/**
 * Proof-independent seed for the product AIR. The relation seed is the
 * locally registered relation statement seed. CTL schedule/challenges and the
 * semantic endpoint are absorbed explicitly, so the same trace cannot be
 * replayed under another endpoint or bus program.
 */
[[nodiscard]] uint256 ComputeRCStage3RelationCtlDirectAliasSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& relation_seed,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    uint32_t source_column);

/**
 * Bind one direct-alias participant's postchallenge CTL columns to the shared
 * product proof.  The digest covers INVERSE1..RUNNING2 and the shared
 * quotient root; verifiers reject a child receipt carrying any other
 * auxiliary commitment.
 */
[[nodiscard]] uint256
ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    const RCStage3RelationCtlDirectAliasLayout& layout);

/**
 * Registered episode-shard verifier for the product construction. It resolves
 * the relation AIR locally from `episode_pin`; the endpoint-to-column mapping
 * is immutable. The proof must carry both the relation trace and CTL trace,
 * and their committed source/VALUE columns must be identical.
 *
 * This verifies one participant's provenance proof. The caller must still
 * execute every other participant proof and
 * VerifyRCStage3CtlPublicPinComposition for the global terminal equality.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const RCStage3EpisodeAirPublicPin& episode_pin,
    const RCStage3CtlManifest& ctl_manifest,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    size_t ctl_participant_index,
    const RCStage3CtlSchedule& schedule,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/** Proof-public pin for one locally registered coupled kernel. The verifier
 * resolves the role CS from `request`; no serialized constraint callback is
 * accepted. Roots bind actual product-proof columns but do not claim the
 * still-missing input/output commitment openings. */
struct RCStage3CoupledEndpointAirPublicPin {
    RCStage3RelationEndpoint endpoint{};
    RCStage3CoupledAirRequest request{};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    std::vector<uint256> relation_column_roots;
};

[[nodiscard]] uint256 ComputeRCStage3CoupledEndpointAirSeed(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledEndpointAirPublicPin& pin);

/** Same provenance construction for the immutable coupled local-kernel
 * registry. Success proves a concrete local kernel cell equals CTL::VALUE; it
 * does not prove the role's absent commitment-opening/hash/schedule edges. */
[[nodiscard]] bool VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledEndpointAirPublicPin& pin,
    const RCStage3CtlManifest& ctl_manifest,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    size_t ctl_participant_index,
    const RCStage3CtlSchedule& schedule,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

[[nodiscard]] const char* RCStage3RelationEndpointName(
    RCStage3RelationEndpoint endpoint);
[[nodiscard]] const std::vector<RCStage3RelationEndpoint>&
RequiredRCStage3RelationEndpoints(RCStage3RelationRole role);
[[nodiscard]] RCStage3RelationEndpoint
RCStage3RelationCtlExportEndpoint(RCStage3RelationRole role);

/** Recompute one role's exact ordered multiproof ledger root. */
[[nodiscard]] uint256 ComputeRCStage3RelationRoleMultiproofRoot(
    const RCStage3RelationRoleClosure& role);
[[nodiscard]] uint256 ComputeRCStage3RelationClosureCommitment(
    const RCStage3RelationClosureV1& closure);

/** Deterministic comparison of the three considered V1 closure strategies. */
[[nodiscard]] std::vector<RCStage3RelationClosureStrategyAssessment>
AssessRCStage3RelationClosureStrategies();
/** Honest current inventory.  A generic relation-export hash is not counted
 * as proof-derived equality. */
[[nodiscard]] std::vector<RCStage3RelationClosureRoleAudit>
CurrentRCStage3RelationClosureRoleAudit();
/** Exact 52-entry proof-cell/provenance inventory. */
[[nodiscard]] std::vector<RCStage3RelationEndpointCellAudit>
CurrentRCStage3RelationEndpointCellAudit();

// ============================================================================
// Commitment-opening AIR (blocker A for PR-89 certified_bits gates g0/g1/g2).
//
// The direct-alias construction above proves relation_cell == CTL::VALUE in one
// trace, but not that relation_cell is the value the endpoint's committed
// manifest ROOT actually commits.  A relation proof could therefore satisfy the
// CTL alias with a value that is not in the committed manifest.  This closes
// that gap for every endpoint that exports a scalar relation cell: it proves,
// entirely IN-AIR, that the cell hashes to a leaf which authenticates to the
// committed manifest root, and it binds that same cell to the CTL VALUE column.
//
// It reuses the existing in-AIR AlgHash machinery rather than inventing new
// hashing:
//   * air_recurse::BuildPermRoundConstraints  — the real 118 degree-7 S-box
//     identities of one alg_hash permutation (the leaf hash);
//   * air_recurse::BuildMerkleGlueConstraints / BuildMerkleRootBoundaryConstraints
//     — the exact Merkle-path level chip + terminal root pin the recursion uses.
//
// Two constraint families are evaluated over their honest witnesses (the same
// machine check the air_recurse Merkle-glue test performs):
//   A. leaf binding : Permute(v.c0,v.c1,v.c2,index,Le,0..) == committed leaf,
//      plus a degree-1 Fp3 identity  value == in0 + t*in1 + t^2*in2  binding the
//      relation value column (== CTL VALUE) to the three hashed leaf lanes.
//   B. path         : Compress-fold the leaf up the authentication path and pin
//      the terminal accumulator to the committed manifest root.
// The opening succeeds iff both families have zero violations and the folded
// root equals the committed manifest root.  Tampering the cell, the CTL value,
// any sibling/direction, the leaf, or the root drives violations > 0.
// ============================================================================

/** Fixed authentication-path length (T-BIND shape constant, never prover-
 * chosen).  The opening trace is BuildRCStage3OpeningTraceRows() rows. */
inline constexpr uint32_t kRCStage3OpeningPathLen = 3;

/** Fixed manifest side of one endpoint opening: the committed leaf digest, its
 * authentication path, and the committed manifest root the path folds to.  In
 * production these come from the endpoint's committed manifest; the canonical
 * builder below reproduces a deterministic instance for verification. */
struct RCStage3CommitmentManifest {
    uint32_t leaf_index{0};
    alg_hash::Digest committed_leaf{};
    std::vector<alg_hash::Digest> siblings; // one per path level (== kRCStage3OpeningPathLen)
    std::vector<bool> directions;           // one per path level (== index bits)
    alg_hash::Digest committed_root{};
};

/**
 * Result of one endpoint's in-AIR commitment opening.  The opening is ONE
 * AirConstraintSystem<Fp3> proved by the standard batched-FRI backend
 * (AirQuotientProve/AirQuotientVerify) — not a native constraint scan.  The
 * leaf-hash strip and the Merkle-path strip are joined by an in-circuit
 * kFirstRow splice (path accumulator row 0 == leaf permutation output), the
 * direction bits are pinned to the public leaf index, and the terminal
 * accumulator is pinned to the committed manifest root.
 */
struct RCStage3CommitmentOpening {
    RCStage3RelationEndpoint endpoint{};
    uint32_t path_len{0};
    bool prover_ok{false};        // AirQuotientProve succeeded structurally
    bool division_exact{false};   // C(X) divisible by Z_H(X): every rule holds
    bool verified{false};         // AirQuotientVerify accepted the proof
    bool ctl_value_bound{false};  // value column (== CTL VALUE) bound to leaf in-circuit
    bool leaf_consistent{false};  // splice (leaf output == path accumulator row 0) held
    bool root_matches_manifest{false};
    bool opens{false};            // proved honest acceptance (all of the above)
    std::string note;
};

/** True iff this endpoint exports a scalar relation cell for which a commitment
 * opening is constructed (the 21 same-trace-aliasable cells whose opening was
 * previously absent). */
[[nodiscard]] bool RCStage3EndpointHasCommitmentOpening(
    RCStage3RelationEndpoint endpoint);

/** Number of endpoints that carry a genuine commitment opening (advances the
 * per-endpoint semantic_relation_complete count). */
[[nodiscard]] uint32_t RCStage3CommitmentOpeningEndpointCount();

/** Deterministic honest manifest for one endpoint/cell: committed_leaf =
 * LeafHash(cell, index); siblings/directions are endpoint-seeded; committed_root
 * is the Compress-fold of the leaf up the path. */
[[nodiscard]] RCStage3CommitmentManifest BuildRCStage3CanonicalManifest(
    RCStage3RelationEndpoint endpoint,
    const gkr_field::Fp3& cell,
    uint32_t leaf_index,
    uint32_t path_len);

/** Execute the endpoint's in-AIR commitment opening: prove `cell` (bound to the
 * CTL VALUE `ctl_value`) opens `manifest`.  Success requires zero violations in
 * both AIR families and folded-root == committed-root. */
[[nodiscard]] RCStage3CommitmentOpening OpenRCStage3EndpointCommitment(
    RCStage3RelationEndpoint endpoint,
    const gkr_field::Fp3& cell,
    const gkr_field::Fp3& ctl_value,
    const RCStage3CommitmentManifest& manifest,
    std::string* why = nullptr);

// ===========================================================================
// Composable opening block + role-AIR direct product (C_rho assembly core).
//
// OpenRCStage3EndpointCommitment above proves ONE opening block with its own
// FRI round-trip and returns only a pass/fail summary.  The declarations below
// expose that same in-AIR alg_hash Merkle opening as a RAW, column-shiftable
// AirConstraintSystem<Fp3> + honest witness so a role AIR C_rho can be built as
// the column-shifted direct product (CopyConstraintFamily) of the role's
// fragment kernel(s) and one opening block per required scalar endpoint, with
// deg-1 boundary aliases from each opening's value column to the fragment cell.
// This is the fable-Theorem-2 inline-product construction; it is verified at
// the constraint-system level (air_recurse::CountWitnessViolationsOnH == 0 on an
// honest joint witness, > 0 under any child/opening tamper) without a full FRI
// prove, so it is testable far under the terminal-round compute budget.
// ===========================================================================

/** Width of one exported opening block (kValueCol == the aliasable cell). */
inline constexpr uint32_t kRCStage3OpeningWidth = 271;
inline constexpr uint32_t kRCStage3OpeningValueColumn = 130;

/** The composable opening block for a fixed public leaf index/root/path length,
 * returned as a raw AirConstraintSystem<Fp3> (n_rows = path_len + 1).  Identical
 * to the system OpenRCStage3EndpointCommitment proves internally. */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3OpeningConstraintSystem(uint32_t leaf_index,
                                     const alg_hash::Digest& committed_root,
                                     uint32_t path_len);

/** Honest column-major witness (kRCStage3OpeningWidth columns x path_len+1 rows)
 * for the opening block above: `cell` opens `manifest`, bound to `ctl_value` at
 * column kRCStage3OpeningValueColumn. */
[[nodiscard]] std::vector<std::vector<gkr_field::Fp3>>
BuildRCStage3OpeningWitness(const gkr_field::Fp3& cell,
                            const gkr_field::Fp3& ctl_value,
                            const RCStage3CommitmentManifest& manifest);

/**
 * One assembled role AIR C_rho: the column-shifted direct product of the role's
 * fragment kernel(s) and its per-endpoint opening blocks, plus the deg-1
 * boundary aliases tying each opening's value column to its fragment cell.
 * `witness` is a satisfying joint assignment on the shared padded rows
 * (CountWitnessViolationsOnH(cs, witness) == 0).  `endpoint_value_columns[i]` is
 * the product column carrying endpoints[i]'s cell (== the aliased opening value
 * column), so callers can materialize the CTL export / tamper a specific child.
 */
struct RCStage3RoleAirProduct {
    RCStage3RelationRole role{};
    air_quotient::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> witness; // cs.n_columns x cs.n_rows
    std::vector<RCStage3RelationEndpoint> endpoints;
    std::vector<uint32_t> endpoint_value_columns;
    /** The committed VectorRootAlg root each opening block authenticates (the
     * authority root a matching child pin must carry, in endpoints order). */
    std::vector<alg_hash::Digest> endpoint_committed_roots;
    uint32_t fragment_columns{0};
    uint32_t opening_blocks{0};
    bool ok{false};
    std::string note;
};

/**
 * Assemble CoupledPermutation's C_rho: the 2-column copy kernel (COPY_OUTPUT ==
 * COPY_INPUT) direct-producted with one alg_hash opening block for each of its
 * two required scalar endpoints (CoupledPermutationInput #37, Output #38),
 * boundary-aliased to COPY_INPUT / COPY_OUTPUT.  The honest copy sets
 * output == input == `cell`.  Deterministic from (role, cell, leaf_index,
 * path_len) alone (RC pure-shape: no serialized callback).  `path_len` must make
 * path_len + 1 a power of two (fixed T-BIND).
 */
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3CoupledPermutationRoleAir(const gkr_field::Fp3& cell,
                                       uint32_t leaf_index,
                                       uint32_t path_len,
                                       std::string* why = nullptr);

/**
 * Assemble any fully-scalar-openable coupled role's C_rho + a SATISFYING joint
 * witness.  The role's fragment kernel witness is built role-specifically (copy
 * for CoupledPermutation; the 64-bit add/subtract adder trace for CoupledMix),
 * every kernel column is filled, each required endpoint's cell is read from its
 * kernel column (CoupledEndpointColumn), and one opening block per endpoint is
 * aliased to it.  CountWitnessViolationsOnH(product.cs, product.witness) == 0.
 */
// `real_mix_a`/`real_mix_b` (optional, CoupledMix only): drive the 64-bit adder
// kernel with REAL block-derived operands (a,b) as four LE 16-bit limbs each,
// instead of the synthetic constants.  Null => synthetic (unchanged).
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3CoupledScalarRoleAir(RCStage3RelationRole role,
                                  uint32_t leaf_index,
                                  uint32_t path_len,
                                  std::string* why = nullptr,
                                  const std::array<uint32_t, 4>* real_mix_a = nullptr,
                                  const std::array<uint32_t, 4>* real_mix_b = nullptr);

// ===========================================================================
// Faithful WIRED ledger-fold closer (Poseidon multi-permutation sponge).
//
// The wired endpoints (SignedRange, GemmSumcheck, BuilderTrace, Wiring,
// SeedChain, BankRoot) commit an ORDERED alg-hash ledger fold, not a scalar
// opening: root = fold_s( Compress(acc, LeafHashRow(row_s, s)) ), where
// LeafHashRow = alg_hash::SpongeHashFp (width 12, rate 8, capacity 4, 10*
// padding, add-absorb).  A faithful in-circuit closer must reproduce that
// sponge, so this exposes the sponge as a composable CS: ONE add-absorb
// permutation block per trace row, the message add-absorbed into the rate
// lanes, the final squeeze pinned to the committed digest.  Verified with
// air_recurse::CountWitnessViolationsOnH (no FRI): honest sponge witness -> 0,
// any tamper (message lane / permutation cell / committed digest) -> > 0.
// ===========================================================================

/** Width of one sponge trace row:
 *  [ perm(130) | 8 rate-message lanes | 1 terminal-squeeze selector ]. */
inline constexpr uint32_t kRCStage3SpongeRowWidth = 139;

struct RCStage3SpongeProduct {
    air_quotient::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> witness; // column-major
    alg_hash::Digest digest{};                        // == LeafHashRow(row,index)
    uint32_t blocks{0};
    bool ok{false};
    std::string note;
};

/** Build the composable sponge CS + honest witness reproducing
 * alg_hash::LeafHashRow(row, index) (one add-absorb permutation per row), with
 * the terminal squeeze pinned to the real digest. */
[[nodiscard]] RCStage3SpongeProduct
BuildRCStage3LeafHashRowSpongeProduct(const std::vector<gkr_field::Fp3>& row,
                                      uint32_t index,
                                      uint32_t target_n_rows = 0,
                                      std::string* why = nullptr);

/** Generic equality-free wired ledger-fold closer CS (resolver side): the sponge
 * over an `n_row_lanes`-lane LeafHashRow leaf, squeeze pinned to the committed
 * fold root, padded to `target_n_rows` (0 = natural). Used by Sumcheck / the
 * three Wiring closers, which fold to a root with no cross-position equality. */
[[nodiscard]] bool BuildRCStage3WiredLeafCloserCS(
    const alg_hash::Digest& committed_root,
    uint32_t n_row_lanes,
    uint32_t target_n_rows,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

struct RCStage3WiredCloserProduct {
    air_quotient::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> witness; // column-major
    alg_hash::Digest committed_digest{};              // == the real ledger fold
    uint32_t root_equality_gadgets{0};
    bool ok{false};
    std::string note;
};

/**
 * Faithful CoupledGemmSignedRange wired closer for one shard (N=1 ledger fold):
 * the sponge reproduces the real ShardLeaf = LeafHashRow([s, cell_begin,
 * logical_rows, n_rows, max_abs, RANGE_VALUE-root lanes, Y-root lanes], s)
 * (coupled_signed_range_binding.cpp:47-59), the terminal squeeze is pinned to
 * the committed fold root, and a per-lane BROADCAST-COLUMN copy bus (a constant
 * aux column pinned at the RANGE_VALUE row and checked at the non-adjacent
 * Y-interval row) enforces the per-shard RANGE_VALUE root == Y interval root
 * equality across the flattened-sponge positions.  `committed_digest` equals the
 * real ComputeRCStage3SignedRangeLedgerFold for the matching shard entry.
 */
[[nodiscard]] RCStage3WiredCloserProduct
BuildRCStage3SignedRangeWiredCloserProduct(uint32_t shard_index,
                                           uint64_t cell_begin,
                                           uint32_t logical_rows,
                                           uint32_t n_rows_meta,
                                           uint64_t max_abs,
                                           const uint256& range_value_root,
                                           const uint256& y_interval_root,
                                           std::string* why = nullptr);

/**
 * Assemble CoupledGemm's C_rho + a satisfying joint witness on 8 shared rows:
 * the GEMM a·b accumulator kernel (constant operands so the endpoint cells are
 * row-constant and aliasable) ⊕ scalar opening blocks for A/B/Y (path_len 7,
 * boundary-aliased to GEMM_A/GEMM_B/GEMM_OUT) ⊕ the SignedRange wired
 * ledger-fold closer for the wired SignedRange endpoint.  This is the first
 * MIXED scalar+wired role C_rho.  CountWitnessViolationsOnH(cs, witness) == 0.
 * `endpoint_committed_roots` carries [A, B, Y, SignedRange] roots in required-
 * endpoint order (the authority roots a matching child pin must carry).
 */
// Optional REAL inputs (null => synthetic a=3,b=5): `real_a`/`real_b` are the
// block's GEMM operands (e.g. RCCoupEpisodeTranscript.gemms A[k], B[k][j]); the
// kernel faithfully accumulates rows·a·b into OUT and the A/B/Y openings commit
// the real values. `real_sr_root` pins a real SignedRange authority root.
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3CoupledGemmRoleAir(std::string* why = nullptr,
                                const int64_t* real_a = nullptr,
                                const int64_t* real_b = nullptr,
                                const uint256* real_sr_root = nullptr);

/** Resolver-side wired-closer CS (no witness) for CoupledGemmSignedRange: the
 * sponge squeeze pinned to the committed authority root + the RANGE_VALUE==Y
 * broadcast bus. Byte-identical to the closer inside
 * BuildRCStage3CoupledGemmRoleAir for the same committed root. */
[[nodiscard]] bool BuildRCStage3SignedRangeWiredCloserCS(
    const alg_hash::Digest& committed_root,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** True iff `role` can currently form a COMPLETE in-CS C_rho (every required
 * endpoint closes via a scalar opening OR a wired ledger-fold closer, no §4
 * stream endpoint). CoupledPermutation, CoupledMix (pure scalar) and CoupledGemm
 * (scalar A/B/Y + wired SignedRange). */
[[nodiscard]] bool RCStage3RoleIsInCsClosable(RCStage3RelationRole role);

/** Number of in-trace endpoint closers (scalar opening + wired ledger-fold
 * closer) present in an assembled role AIR. */
[[nodiscard]] uint32_t RCStage3CountInCsClosers(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& cs);

/** Resolver-side C_rho CS for CoupledGemm (kernel ⊕ A/B/Y openings ⊕ SignedRange
 * wired closer) pinned to the endpoint authority roots (in required order). */
[[nodiscard]] bool BuildRCStage3CoupledGemmRoleAirCS(
    const std::vector<alg_hash::Digest>& endpoint_roots,
    uint32_t path_len,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** Assemble EpisodeGemm's C_rho + satisfying joint witness on 8 shared rows:
 * the Episode GEMM (GF=A·B) kernel ⊕ A/B/Y scalar openings ⊕ the Sumcheck wired
 * ledger-fold closer ⊕ the SignedRange wired closer. First role with TWO wired
 * closers. `endpoint_committed_roots` = [A,B,Y,Sumcheck,SignedRange]. */
// Optional REAL inputs (null => synthetic a=3,b=5): `real_a`/`real_b` are a real
// episode GEMM MAC term (A[k], B[k][j]); Y = a·b exactly. `real_sr_root` pins a
// real SignedRange authority root.
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3EpisodeGemmRoleAir(std::string* why = nullptr,
                                const int64_t* real_a = nullptr,
                                const int64_t* real_b = nullptr,
                                const uint256* real_sr_root = nullptr);

/** Resolver-side EpisodeGemm C_rho CS from the endpoint authority roots. */
[[nodiscard]] bool BuildRCStage3EpisodeGemmRoleAirCS(
    const std::vector<alg_hash::Digest>& endpoint_roots,
    uint32_t path_len,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** Assemble EpisodeWiring's C_rho + satisfying joint witness on 16 shared rows:
 * the Episode wiring (U=V) kernel ⊕ the Copy scalar opening ⊕ the Transpose,
 * Residual and RoundOrder wired ledger-fold closers.
 * `endpoint_committed_roots` = [Copy,Transpose,Residual,RoundOrder]. */
// Optional REAL input (null => synthetic 0x99): `real_copy_cell` drives the
// EpisodeWiring copy (U==V) endpoint with a real block-derived value.  The three
// wired folds (Transpose/Residual/RoundOrder) remain structural — the episode
// wiring permutation is not exposed as simple openable scalars.
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3EpisodeWiringRoleAir(std::string* why = nullptr,
                                  const gkr_field::Fp3* real_copy_cell = nullptr);

/** Resolver-side EpisodeWiring C_rho CS from the endpoint authority roots. */
[[nodiscard]] bool BuildRCStage3EpisodeWiringRoleAirCS(
    const std::vector<alg_hash::Digest>& endpoint_roots,
    uint32_t path_len,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** True iff every required endpoint of `role` is a §4 committed-stream endpoint
 * (CoupledBarrier, CoupledDigest, EpisodeTileTree, EpisodeDigest). */
[[nodiscard]] bool RCStage3RoleIsPureStream(RCStage3RelationRole role);

/** Assemble a pure-stream role's C_rho + witness: one LIGHT §4 stream binding
 * fragment per required endpoint (n_rows=2), each pinning its SHA256d fold root.
 * The heavy SHA fold is the DEFERRED recursive child (aggregation/g2 leg).
 * `endpoint_committed_roots` carries each SHA256d root packed into a Digest. */
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3PureStreamRoleAir(RCStage3RelationRole role,
                               std::string* why = nullptr);

/** Resolver-side pure-stream role CS from the endpoint authority roots (each a
 * SHA256d root packed into a Digest, two uint32 per lane). */
[[nodiscard]] bool BuildRCStage3PureStreamRoleAirCS(
    RCStage3RelationRole role,
    const std::vector<alg_hash::Digest>& endpoint_roots,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/**
 * REAL-DATA producer for a pure-stream role: assemble the role's C_rho + a
 * satisfying witness whose per-endpoint light §4 binding fragments pin the
 * caller-supplied REAL committed SHA256d roots (one array<uint32,8> per required
 * endpoint, in RequiredRCStage3RelationEndpoints order).  Unlike
 * BuildRCStage3PureStreamRoleAir (which synthesizes each endpoint's stream_value
 * from `uint32(endpoint)*131 + ...`), every pinned root here is real block data
 * — e.g. the real MineRCEpisode episode digest / round-root fold / tile-tree
 * roots, or the real coupled bank/barrier/episode-digest roots — so the proved
 * role C_rho binds the block's actual committed authority, not an arbitrary cell.
 * The heavy SHA fold remains the deferred aggregation child, exactly as in the
 * synthetic builder; only the pinned authority roots change to real data. */
[[nodiscard]] RCStage3RoleAirProduct BuildRCStage3PureStreamRoleAirFromRoots(
    RCStage3RelationRole role,
    const std::vector<std::array<uint32_t, 8>>& endpoint_root8s,
    std::string* why = nullptr);

/** Assemble a coupled scalar+stream mixed role's C_rho + witness on 8 shared
 * rows: the coupled kernel ⊕ per-endpoint scalar opening (kernel-aliased) or
 * light §4 stream fragment. CoupledExchange (Input/Output scalar + HashXof
 * stream) and CoupledBank (Pages scalar + SeedXof + CoupledBankRoot streams). */
// Optional REAL inputs (null => synthetic, unchanged): `real_copy_cell`
// (CoupledExchange copy kernel), `real_nibble` 0..15 (CoupledBank T_M nibble),
// `real_stream_roots` — real committed SHA256d root8 per STREAM endpoint in the
// order stream endpoints appear (CoupledExchange HashXof; CoupledBank SeedXof +
// CoupledBankRoot).  Drives the mixed role C_rho from real block data.
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3CoupledMixedRoleAir(
    RCStage3RelationRole role, std::string* why = nullptr,
    const gkr_field::Fp3* real_copy_cell = nullptr,
    const uint8_t* real_nibble = nullptr,
    const std::vector<std::array<uint32_t, 8>>* real_stream_roots = nullptr);

/** Resolver-side coupled scalar+stream mixed role CS from the authority roots. */
[[nodiscard]] bool BuildRCStage3CoupledMixedRoleAirCS(
    RCStage3RelationRole role,
    const std::vector<alg_hash::Digest>& endpoint_roots,
    uint32_t path_len,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** Assemble a NO-KERNEL role's C_rho + witness on 8 shared rows: each required
 * endpoint closes with a standalone alg_hash opening (vector/scalar), a §4 stream
 * fragment, or a Poseidon wired ledger-fold closer. The heavy role relation
 * (e.g. the extract sampler AIR) is the DEFERRED recursive child, like the SHA
 * folds. Covers EpisodeDeterministicBuilder (Params + SeedChain/OperandXof +
 * BuilderTrace) and CoupledExtract/EpisodeExtract (4 openings + ChaCha stream). */
// Optional REAL inputs (null => synthetic, unchanged): `real_open_cells` — one
// real block-derived Fp3 cell per OPENING endpoint (e.g. EpisodeDeterministic-
// Builder Params, Coupled/EpisodeExtract Input/Sampler/Scale/Output), in the
// order opening endpoints appear; `real_stream_roots` — one real committed
// SHA256d root8 per STREAM endpoint (SeedChain/OperandXof/ChaCha), in order.
[[nodiscard]] RCStage3RoleAirProduct
BuildRCStage3NoKernelRoleAir(
    RCStage3RelationRole role, std::string* why = nullptr,
    const std::vector<gkr_field::Fp3>* real_open_cells = nullptr,
    const std::vector<std::array<uint32_t, 8>>* real_stream_roots = nullptr);

/** Resolver-side no-kernel role C_rho CS from the endpoint authority roots. */
[[nodiscard]] bool BuildRCStage3NoKernelRoleAirCS(
    RCStage3RelationRole role,
    const std::vector<alg_hash::Digest>& endpoint_roots,
    uint32_t path_len,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/**
 * In-CS closers a COMPLETE CompositionLink C_rho must carry: the EPISODE leg
 * §4 binding, the COUPLED leg §4 binding, and the sponge ledger fold that ties
 * them to the committed link digest. CompositionLink has no entry in
 * RequiredRCStage3RelationEndpoints, so RCStage3RequiredInCsOpeningBlocks reads
 * this constant instead of that registry's size — otherwise the completeness
 * gate would compare against 0 and accept a zero-closer AIR.
 */
inline constexpr uint32_t kRCStage3CompositionLinkInCsClosers = 3;

/**
 * Resolver-side CompositionLink C_rho. `endpoint_roots` must be exactly
 * kRCStage3CompositionLinkInCsClosers entries, in order:
 *   [0] EPISODE leg authority root  (SHA256d root packed into a Digest)
 *   [1] COUPLED leg authority root  (likewise)
 *   [2] the committed LINK digest   (a real alg_hash sponge digest)
 *
 * Read the SOUNDNESS SCOPE comment above the implementation before treating
 * this as closing the composition relation: the in-CS fold is the ALGEBRAIC
 * hash, not the consensus SHA256d of ComputeRCStage3FinalDigest, and the three
 * roots are public pins whose provenance is a separate obligation
 * (kRCStage3RoleSectionEndpointProvenanceReady, currently false).
 */
[[nodiscard]] bool BuildRCStage3CompositionLinkRoleAirCS(
    const std::vector<alg_hash::Digest>& endpoint_roots,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/**
 * CompositionLink C_rho + a satisfying witness. The committed link digest is
 * DERIVED from the two leg values (LeafHashRow([episode, coupled], 0)), never
 * chosen independently, so a test that mutates a leg genuinely invalidates the
 * pin rather than trivially agreeing with it.
 */
[[nodiscard]] RCStage3RoleAirProduct BuildRCStage3CompositionLinkRoleAir(
    const gkr_field::Fp3& episode_leg, const gkr_field::Fp3& coupled_leg,
    const std::array<uint32_t, 8>& episode_root8,
    const std::array<uint32_t, 8>& coupled_root8,
    std::string* why = nullptr);

/**
 * True iff every required endpoint of `role` closes via an in-trace same-trace
 * scalar alg_hash opening (IsOpenedRelationEndpoint + a resolvable fragment
 * kernel column), so a COMPLETE C_rho can be assembled purely from scalar
 * opening blocks.  Currently CoupledPermutation and CoupledMix.  Roles with any
 * §4 stream / vector / wired-binding endpoint return false until those closers
 * are composed on the same direct-product spine.
 */
[[nodiscard]] bool RCStage3RoleIsInCsScalarOpenable(RCStage3RelationRole role);

/** Number of in-trace opening blocks a COMPLETE C_rho for `role` must contain
 * (one per required endpoint).  The recursive resolver's completeness gate
 * requires the resolved CS to carry exactly this many opening blocks before
 * constraints_resolved may be set — closing the shape-only fabrication gap. */
[[nodiscard]] uint32_t RCStage3RequiredInCsOpeningBlocks(
    RCStage3RelationRole role);

/** Count of in-trace endpoint opening blocks present in an assembled role AIR
 * (the "role_air:endpoint_value_alias" boundary-alias families). */
[[nodiscard]] uint32_t RCStage3CountInCsOpeningBlocks(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& cs);

/**
 * Assemble a fully-scalar-openable coupled role's C_rho CONSTRAINT SYSTEM ONLY
 * (no witness), pinning each required endpoint's opening block to the committed
 * authority root supplied for it (from the child pin, in required-endpoint
 * order).  n_rows = path_len + 1 (must be a power of two).  Returns false unless
 * RCStage3RoleIsInCsScalarOpenable(role) and endpoint_roots covers every
 * required endpoint.  This is the resolver-facing builder: the witness is the
 * prover's burden and is materialized separately.
 */
[[nodiscard]] bool BuildRCStage3CoupledScalarRoleAirCS(
    RCStage3RelationRole role,
    const std::vector<alg_hash::Digest>& endpoint_roots,
    uint32_t path_len,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/**
 * Re-anchored Poseidon vector commitment of an ordered value column: leaf_i =
 * alg_hash::LeafHash(values[i], i), folded pairwise with alg_hash::Compress.
 * This is the authority root (per the ProductionProgramConsensusPinV1 rule that
 * the recursive alg-hash root is the sole authority; the SHA256d root is
 * transport-only).  Padded to the smallest fixed T-BIND depth in {1,3,7,15}
 * covering the column, so the opening trace stays a fixed-length shape.
 */
[[nodiscard]] RCStage3CommitmentManifest BuildRCStage3VectorManifest(
    RCStage3RelationEndpoint endpoint,
    const std::vector<gkr_field::Fp3>& values,
    uint32_t index);

/** Poseidon VectorRootAlg of an ordered value column (leaf_i = LeafHash(v_i, i),
 * Compress-folded).  This is the registered AUTHORITY root the registry stores
 * in RCStage3GemmExtractLayerBindings::*_root_alg — identical to the tree the
 * commitment openings authenticate. */
[[nodiscard]] alg_hash::Digest RCStage3ComputeVectorRootAlg(
    const std::vector<gkr_field::Fp3>& values);

/** 32-byte packing of RCStage3ComputeVectorRootAlg (four canonical Fp lanes,
 * little-endian) for storage in the uint256 authority-root fields. */
[[nodiscard]] uint256 RCStage3VectorRootAlgCommitment(
    const std::vector<gkr_field::Fp3>& values);

/** True iff the endpoint closes by opening a cell of its re-anchored VectorRootAlg
 * value column (endpoints with a committed value vector but no same-trace CTL
 * cell). */
[[nodiscard]] bool RCStage3EndpointHasVectorOpening(
    RCStage3RelationEndpoint endpoint);

/** Count of endpoints that close via a VectorRootAlg value-column opening. */
[[nodiscard]] uint32_t RCStage3VectorOpeningEndpointCount();

/** True iff the endpoint closes by a WIRED sibling-lane alg binding whose
 * semantic pin is copied into this registry (EpisodeBuilderTrace #4 /
 * EpisodeGemmSumcheck #8). */
[[nodiscard]] bool RCStage3EndpointIsWiredBinding(
    RCStage3RelationEndpoint endpoint);

/** Count of endpoints closed by a wired sibling-lane alg binding. */
[[nodiscard]] uint32_t RCStage3WiredBindingEndpointCount();

// ---------------------------------------------------------------------------
// Stream/digest endpoints: §4 SHA256d manifest-binding root-equality pin.
//
// 19 of the 30 no-scalar-cell endpoints export a committed hash/stream column
// rather than a scalar cell, so they cannot take the alg_hash scalar opening
// above.  They instead close by the same commitment-opening mechanism the §4
// manifests lane established (matmul_v4_rc_stage3_hash_air.{h,cpp}): the ordered
// committed boundary-column stream is folded into a SHA256d `stream_column_root`
// (index-bound leaves) which is bound to the committed manifest root, and the
// endpoint's committed stream root is PINNED to that stream_column_root.  A
// wrong stream element, a reorder, or a substituted root fails closed.
//
// The four §4 families are SHA256d, so a Poseidon/alg_hash Merkle-path AIR
// cannot fold to them directly; the 21 scalar openings above therefore keep
// their alg_hash proof, and the stream endpoints reuse the §4 SHA256d binding.
// ---------------------------------------------------------------------------

enum class RCStage3StreamManifestFamily : uint8_t {
    None = 0,
    XofCounter = 1,
    ChaChaInitAndBlock = 2,
    CompleteStreamTileTree = 3,
    DirectSha256dEpisodeDigest = 4,
    DirectSha256dCoupledBarrier = 5,
    DirectSha256dCoupledDigest = 6,
};

struct RCStage3StreamEndpointOpening {
    RCStage3RelationEndpoint endpoint{};
    RCStage3StreamManifestFamily family{RCStage3StreamManifestFamily::None};
    bool binding_built{false};
    bool binding_verified{false};   // §4 VerifyHashManifestRecursiveBinding
    bool root_pinned{false};        // endpoint committed root == stream_column_root
    bool opens{false};              // binding verified + root pinned, no tamper
    uint256 manifest_commitment{};
    uint256 stream_column_root{};
    std::string note;
};

/** The §4 manifest-binding family an endpoint belongs to (None if it exports no
 * committed hash/stream column bound by a §4 recursive binding). */
[[nodiscard]] RCStage3StreamManifestFamily
RCStage3StreamEndpointManifestFamily(RCStage3RelationEndpoint endpoint);

/**
 * Map a relation endpoint onto the stream-endpoint closer's family enum.
 *
 * The three DirectSha256d residual relation families
 * (EpisodeDigest / CoupledBarrier / CoupledDigest) map 1:1 onto the matching
 * RCStage3StreamFamily values so each keeps its own FamilyDomain() separator.
 * They must NOT collapse onto the generic DirectSha256d value — that would
 * re-open the cross-family replay gap the residual enum values closed.
 */
[[nodiscard]] RCStage3StreamFamily
RCStage3StreamFamilyForEndpoint(RCStage3RelationEndpoint endpoint);

/** True iff the endpoint closes via a §4 stream-root pin (family != None). */
[[nodiscard]] bool RCStage3EndpointHasStreamOpening(
    RCStage3RelationEndpoint endpoint);

/** Count of endpoints that carry a §4 stream-root pin. */
[[nodiscard]] uint32_t RCStage3StreamOpeningEndpointCount();

/**
 * Build the endpoint's §4 manifest recursive binding, verify it, and pin the
 * endpoint's committed stream root to binding.stream_column_root.  `tamper_stream`
 * corrupts the binding (fails §4 verification); `substitute_root` pins a wrong
 * endpoint root.  Either drives opens == false.
 */
[[nodiscard]] RCStage3StreamEndpointOpening OpenRCStage3StreamEndpointCommitment(
    RCStage3RelationEndpoint endpoint,
    bool tamper_stream,
    bool substitute_root,
    std::string* why = nullptr);

/**
 * Execute the native CTL proofs, then require every role's selected
 * proof_column_root to equal the corresponding executed CTL VALUE-column
 * commitment.  Exact endpoint order/count and public digest bindings are
 * enforced.  No callback, engine-trusted boolean or native witness is
 * accepted.
 *
 * This validates the integration ledger only.  Recursive verification of the
 * endpoint child proofs remains a separate fail-closed gate.
 */
[[nodiscard]] bool VerifyRCStage3RelationClosureV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& root,
    const RCStage3UnifiedCtlProofBundle& ctl_bundle,
    const RCStage3RelationClosureV1& closure,
    std::string* why = nullptr);

inline constexpr bool kRCStage3RelationClosureRegistryComplete = true;
inline constexpr bool kRCStage3RelationClosureCtlValueBindingExecutable = true;
inline constexpr bool
    kRCStage3RelationClosureSameTraceCtlAliasExecutable = true;
inline constexpr bool kRCStage3RelationClosureRecursiveChildrenExecutable =
    false;
inline constexpr bool kRCStage3RelationClosureAuthorityReady = false;

static_assert(kRCStage3RelationClosureEndpointCount < 64);
static_assert(kRCStage3RelationClosureRegistryComplete);
static_assert(kRCStage3RelationClosureCtlValueBindingExecutable);
static_assert(kRCStage3RelationClosureSameTraceCtlAliasExecutable);
static_assert(!kRCStage3RelationClosureRecursiveChildrenExecutable);
static_assert(!kRCStage3RelationClosureAuthorityReady);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RELATION_CLOSURE_H
