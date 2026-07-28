// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_domain_registry.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_nirop_reduction.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Executable narrow bridge for the acyclic V12 transcript:
 *
 *   typed FRI terminal receipts
 *        -> post-FRI tax sigma + one g20 nonce
 *        -> two independently typed 384-lane SAFE query squeezes
 *        -> two first-distinct Q96 sampler inputs/outputs.
 *
 * The shape-derived five-channel domain-registry root is the only
 * preprocessed value. Every receipt, tax, nonce, query and sampler cell is an
 * ordinary proof-owned column. A verifier-rebuilt fixed row map gives every
 * equality an exact producer/consumer role, lane, ordinal and source offset.
 *
 * This is deliberately additive. It proves the bridge relation as a real
 * AirQuotient proof, but it does not claim recursive authority until the
 * normalized parent copies its actual child cells into this exact map. Until
 * that copy-in lands, the standalone proof has no public source-value
 * statement: its only external proof-instance binding is the caller-supplied
 * `fs_seed`. "Executable" below means executable foundation, never complete
 * statement or consensus authority.
 */
namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace domains = stage3_safe_v12_domain_registry;
namespace fsair = stage3_safe_v12_fs_air;
namespace gf = gkr_field;
namespace nirop = stage3_safe_v12_nirop_reduction;
namespace qsampler = stage3_safe_v12_query_sampler;

inline constexpr uint16_t kRecursiveBridgeVersionV12 = 1;
inline constexpr uint32_t kTraceRowsV12 = 1024;
inline constexpr uint32_t kFriTerminalReceiptRowsV12 = 8;
inline constexpr uint32_t kTaxSigmaRowsV12 = 8;
inline constexpr uint32_t kNonceRowsV12 = 4;
inline constexpr uint32_t kQueryCandidateRowsV12 =
    fsair::kFriLaneCountV12 *
    fsair::kQueryCandidatesPerLaneV12 * 3;
inline constexpr uint32_t kQueryOutputRowsV12 =
    fsair::kFriLaneCountV12 * fsair::kQueriesPerLaneV12;
inline constexpr uint32_t kActiveMapRowsV12 =
    kFriTerminalReceiptRowsV12 + kTaxSigmaRowsV12 +
    kNonceRowsV12 + kQueryCandidateRowsV12 +
    kQueryOutputRowsV12;
inline constexpr uint32_t kPaddingRowsV12 =
    kTraceRowsV12 - kActiveMapRowsV12;
inline constexpr uint32_t kTaxCoreLanesV12 = 55;
inline constexpr uint32_t kQueryAbsorbLanesV12 = 14;
inline constexpr uint32_t kQuerySqueezeLanesV12 =
    fsair::kQueryCandidatesPerLaneV12 * 3;
inline constexpr uint32_t kLimbBitsV12 = 64;
inline constexpr uint32_t kHighAndChunkV12 = 6;
inline constexpr uint32_t kHighAndStepsV12 = 6;

static_assert(kActiveMapRowsV12 == 980);
static_assert(kPaddingRowsV12 == 44);
static_assert(kQuerySqueezeLanesV12 == 384);

enum class CellKindV12 : uint8_t {
    FriTerminalReceipt = 1,
    TaxSigma = 2,
    SharedNonce = 3,
    QueryCandidate = 4,
    QueryOutput = 5,
    Padding = 6,
};

/**
 * Exact semantic meaning of one source==consumer row.
 *
 * `source_offset` and `consumer_offset` are offsets in the named producer and
 * consumer vectors, not prover-supplied witness values.
 */
struct CellMapEntryV12 {
    uint32_t row{0};
    CellKindV12 kind{CellKindV12::Padding};
    uint32_t lane{0};
    uint32_t ordinal{0};
    uint32_t source_offset{0};
    uint32_t consumer_offset{0};

    bool operator==(const CellMapEntryV12&) const = default;
};

struct LayoutV12 {
    uint32_t expected_registry_root_base{0};
    uint32_t proof_registry_root_base{
        expected_registry_root_base + 4};
    uint32_t fri_terminal_base{
        proof_registry_root_base + 4};
    uint32_t tax_core_base{
        fri_terminal_base + 8};
    uint32_t tax_sigma_base{
        tax_core_base + kTaxCoreLanesV12};
    uint32_t nonce_base{tax_sigma_base + 4};
    uint32_t query_absorb_base{nonce_base + 2};
    uint32_t source{
        query_absorb_base +
        fsair::kFriLaneCountV12 * kQueryAbsorbLanesV12};
    uint32_t consumer{source + 1};
    uint32_t bit_base{consumer + 1};
    uint32_t high_and_base{bit_base + kLimbBitsV12};
    uint32_t row_counter{high_and_base + kHighAndStepsV12};
    uint32_t end{row_counter + 1};

    [[nodiscard]] constexpr uint32_t ExpectedRegistryRoot(
        uint32_t lane) const
    {
        return expected_registry_root_base + lane;
    }
    [[nodiscard]] constexpr uint32_t ProofRegistryRoot(
        uint32_t lane) const
    {
        return proof_registry_root_base + lane;
    }
    [[nodiscard]] constexpr uint32_t FriTerminal(
        uint32_t lane, uint32_t limb) const
    {
        return fri_terminal_base + 4 * lane + limb;
    }
    [[nodiscard]] constexpr uint32_t TaxCore(uint32_t offset) const
    {
        return tax_core_base + offset;
    }
    [[nodiscard]] constexpr uint32_t TaxSigma(uint32_t limb) const
    {
        return tax_sigma_base + limb;
    }
    [[nodiscard]] constexpr uint32_t Nonce(uint32_t word) const
    {
        return nonce_base + word;
    }
    [[nodiscard]] constexpr uint32_t QueryAbsorb(
        uint32_t lane, uint32_t offset) const
    {
        return query_absorb_base +
            kQueryAbsorbLanesV12 * lane + offset;
    }
    [[nodiscard]] constexpr uint32_t Bit(uint32_t bit) const
    {
        return bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t HighAnd(uint32_t step) const
    {
        return high_and_base + step;
    }
};

inline constexpr uint32_t kAirColumnsV12 = LayoutV12{}.end;

struct RecursiveBridgeV12 {
    LayoutV12 layout{};
    fsair::ShapeV12 shape{};
    domains::TranscriptDomainRegistryV12 registry{};
    cb::ProgramTable program_table{};
    alg_hash::Digest program_root{};
    std::vector<CellMapEntryV12> cell_map;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t verifier_owned_preprocessed_columns{0};
    uint32_t proof_owned_preprocessed_columns{0};
    uint32_t equality_constraints{0};
    uint32_t canonical_encoding_constraints{0};
    uint32_t violations{0};
    bool exact_cell_map_rebuilt{false};
    bool domain_registry_root_pinned{false};
    bool typed_terminal_receipts_mapped{false};
    bool shared_tax_and_nonce_mapped{false};
    bool both_query_candidate_vectors_mapped{false};
    bool both_q96_outputs_mapped{false};
    bool proof_cells_are_ordinary_columns{false};
    bool canonical_bytecode_is_relation_source{false};
    bool normalized_parent_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

struct RecursiveBridgeProofV12 {
    uint16_t version{kRecursiveBridgeVersionV12};
    fsair::ShapeV12 shape{};
    alg_hash::Digest registry_root{};
    alg_hash::Digest program_root{};
    aq::AirQuotientRowsProof proof{};
    bool canonical_proof_encoding{false};
    bool verified{false};
    bool normalized_parent_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

/** Verifier-rebuilt exact producer/consumer inventory (980 active + 44 pad). */
[[nodiscard]] std::vector<CellMapEntryV12>
CanonicalCellMapV12();

/**
 * Shape-specific canonical bytecode. Shape constants and all five typed SAFE
 * tags are verifier-rebuilt from `registry`; no proof field changes the
 * program.
 */
[[nodiscard]] bool BuildRecursiveBridgeProgramTableV12(
    const fsair::ManifestV12& manifest,
    const domains::TranscriptDomainRegistryV12& registry,
    cb::ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRecursiveBridgeV12(
    const fsair::ManifestV12& manifest,
    const nirop::HybridInputsV12& inputs,
    const nirop::HybridReceiptV12& receipt,
    const alg_hash::Digest& proof_registry_root,
    RecursiveBridgeV12& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateRecursiveBridgeV12(
    const fsair::ManifestV12& manifest,
    const nirop::HybridInputsV12& inputs,
    const nirop::HybridReceiptV12& receipt,
    const alg_hash::Digest& proof_registry_root,
    const RecursiveBridgeV12& bridge,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolationsV12(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

[[nodiscard]] bool ProveRecursiveBridgeV12(
    const RecursiveBridgeV12& bridge,
    const uint256& fs_seed,
    RecursiveBridgeProofV12& out,
    std::string* why = nullptr);

/**
 * Rebuilds the shape/domain/program relation and verifies the real quotient
 * proof. It also rejects noncanonical in-memory Fp3 representatives before
 * invoking the backend; serialization canonicalization is not accepted as a
 * substitute for unique proof encoding.
 */
[[nodiscard]] bool VerifyRecursiveBridgeProofV12(
    const fsair::ManifestV12& manifest,
    const RecursiveBridgeProofV12& receipt,
    const uint256& fs_seed,
    std::string* why = nullptr);

inline constexpr bool kRecursiveBridgeExecutableV12 = true;
inline constexpr bool kRecursiveBridgePublicSourceStatementBoundV12 = false;
inline constexpr bool kRecursiveBridgeNormalizedParentConsumedV12 = false;
inline constexpr bool kRecursiveBridgeAuthorityReadyV12 = false;

static_assert(!kRecursiveBridgePublicSourceStatementBoundV12);
static_assert(!kRecursiveBridgeNormalizedParentConsumedV12);
static_assert(!kRecursiveBridgeAuthorityReadyV12);

// -------------------------------------------------------------------------
// V13 typed SAFE event parent.
//
// This is the generic recursive relation used by the additive single-lane
// Q192/K=2 SAFE backend.  It deliberately lives beside the V12 dual-lane
// bridge: V12 remains useful evidence, but V13 does not inherit its
// common-commitment/independent-lane obligations.
//
// One row is one SAFECore absorb permutation.  The row owns eight message
// cells and a fully decomposed Poseidon2 permutation.  A shape-derived
// schedule fixes reset/final rows, typed tags, constants and the unique
// query-seed feedback locations.  Ordinary proof columns carry every
// attacker-controlled transcript cell.
//
// A final ReceiptCommitment SAFECore event absorbs:
//
//   program_root || semantic_count ||
//   every proof-owned message cell || every event output digest.
//
// Two independently challenged Fp3 rational identities equality-bind that
// semantic stream into the receipt event.  Thus the receipt digest is a
// compact public binding to both the child transcript cells and every
// challenge result.  The relation is proved directly by the parent's own
// AirQuotient/FRI proof; no host boolean "child accepted" is admitted.
//
// The remaining authority seam is explicit: a normalized recursive verifier
// must equality-bind ProofOwned message cells to authenticated child-proof
// cells and bind event outputs to the verifier consumers.  Until that happens
// this is an executable parent relation, not a consensus readiness flip.
// -------------------------------------------------------------------------

inline constexpr uint16_t kTypedSafeEventParentVersionV13 = 13;
inline constexpr uint32_t kTypedSafeEventRateV13 =
    safe_v12::kSafeRateV12;
inline constexpr uint32_t kTypedSafeEventDigestLanesV13 =
    alg_hash::kAlgHashDigestLen;
inline constexpr uint32_t kTypedSafeEventSourceSlotsV13 =
    kTypedSafeEventRateV13 + kTypedSafeEventDigestLanesV13;
inline constexpr uint32_t kTypedSafeEventCtlLanesV13 = 2;
inline constexpr uint32_t kTypedSafeEventHighAndStepsV13 = 6;
inline constexpr uint32_t kTypedSafeEventRequiredKindsV13 = 8;
inline constexpr uint32_t kTypedSafeEventAuxQuerySeedKindV13 = 8;

enum class TypedSafeChallengeKindV13 : uint8_t {
    AirLambda = 0,
    BatchCoefficient = 1,
    OodZ1 = 2,
    OodZ2 = 3,
    DeepWeight1 = 4,
    DeepWeight2 = 5,
    FoldBeta = 6,
    QueryCandidate = 7,
    QuerySeed = kTypedSafeEventAuxQuerySeedKindV13,
};

enum class TypedSafeMessageBindingV13 : uint8_t {
    /** Ordinary proof column; included exactly once in the receipt CTL. */
    ProofOwned = 0,
    /** Verifier-rebuilt canonical field constant. */
    Constant = 1,
    /** One of the four outputs of the unique QuerySeed event. */
    QuerySeedLane = 2,
};

struct TypedSafeMessageCellProgramV13 {
    TypedSafeMessageBindingV13 binding{
        TypedSafeMessageBindingV13::ProofOwned};
    gf::Fp constant{0};
    uint32_t query_seed_lane{0};

    friend bool operator==(
        const TypedSafeMessageCellProgramV13&,
        const TypedSafeMessageCellProgramV13&) = default;
};

struct TypedSafeEventProgramV13 {
    TypedSafeChallengeKindV13 kind{
        TypedSafeChallengeKindV13::AirLambda};
    alg_hash_typed::RoleV12 role{
        alg_hash_typed::RoleV12::TranscriptAirLambda};
    std::vector<uint8_t> application_domain;
    std::vector<TypedSafeMessageCellProgramV13> message;

    friend bool operator==(
        const TypedSafeEventProgramV13&,
        const TypedSafeEventProgramV13&) = default;
};

struct TypedSafeEventWitnessV13 {
    /**
     * One lane per program message cell.  Constant and QuerySeedLane entries
     * are ignored and rebuilt; ProofOwned entries must be canonical.
     */
    std::vector<gf::Fp> message;
};

/**
 * Exact native-V13 event materialization audit.
 *
 * `program` and `witness` are suitable for direct insertion into the typed
 * parent above. `safe_digest` is computed from those exact cells, while
 * `native_output` is obtained from the shipping V13 native helper.  Parity
 * means all three Fp3 output coordinates agree; the fourth SAFE receipt lane
 * remains available to the parent relation.
 */
struct NativeTypedSafeEventAuditV13 {
    TypedSafeEventProgramV13 program;
    TypedSafeEventWitnessV13 witness;
    alg_hash::Digest safe_digest{};
    gf::Fp3 native_output{};
    bool exact_message_materialized{false};
    bool native_air_output_parity{false};
    bool query_seed_source{false};
    bool query_candidate_consumes_seed{false};
    std::string note;
};

/**
 * Materialize one native Fri3Alg V13 full-transcript SAFE call. Supported
 * labels are fra3_lambda, fra3_z, fra3_w, fra3_fold and fra3_query. The query
 * label materializes the unique QuerySeed event; query candidates use the
 * separate function below.
 */
[[nodiscard]] bool BuildNativeFri3AlgSafeEventV13(
    const std::vector<unsigned char>& transcript,
    const char* label,
    uint32_t index,
    NativeTypedSafeEventAuditV13& out,
    std::string* why = nullptr);

/**
 * Materialize a native Fri3Alg V13 query-candidate call. The four seed lanes
 * are represented as QuerySeedLane bindings, never caller-owned witness
 * values. `query_seed` is used only to execute the native/AIR parity audit.
 */
[[nodiscard]] bool BuildNativeFri3AlgSafeQueryCandidateEventV13(
    const alg_hash::Digest& query_seed,
    uint32_t index,
    NativeTypedSafeEventAuditV13& out,
    std::string* why = nullptr);

struct TypedSafeEventOutputLocationV13 {
    uint32_t event{0};
    TypedSafeChallengeKindV13 kind{
        TypedSafeChallengeKindV13::AirLambda};
    uint32_t row{0};
    uint32_t column{0};
    uint32_t lane{0};

    friend bool operator==(
        const TypedSafeEventOutputLocationV13&,
        const TypedSafeEventOutputLocationV13&) = default;
};

struct TypedSafeEventMessageLocationV13 {
    uint32_t event{0};
    uint32_t ordinal{0};
    uint32_t row{0};
    uint32_t column{0};

    friend bool operator==(
        const TypedSafeEventMessageLocationV13&,
        const TypedSafeEventMessageLocationV13&) = default;
};

struct TypedSafeEventParentLayoutV13 {
    // Keep the layout a constant expression. CanonicalLayout() performs the
    // same arithmetic but is intentionally a runtime validation helper.
    stage3_poseidon_air::Layout poseidon{
        air_recurse::PermLayout{0},
        air_recurse::kPermCellsPerPerm,
        air_recurse::kPermCellsPerPerm +
            air_recurse::kPermSboxCells,
        air_recurse::kPermCellsPerPerm +
            2 * air_recurse::kPermSboxCells};
    uint32_t message_base{
        air_recurse::kPermCellsPerPerm +
        3 * air_recurse::kPermSboxCells};
    uint32_t output_base{message_base + kTypedSafeEventRateV13};
    uint32_t bit_base{
        output_base + kTypedSafeEventDigestLanesV13};
    uint32_t high_and_base{
        bit_base + kTypedSafeEventRateV13 * 64};
    uint32_t query_seed_base{
        high_and_base +
        kTypedSafeEventRateV13 *
            kTypedSafeEventHighAndStepsV13};
    uint32_t ctl_acc_base{
        query_seed_base + kTypedSafeEventDigestLanesV13};
    uint32_t ctl_inverse_base{
        ctl_acc_base + kTypedSafeEventCtlLanesV13};
    uint32_t active{ctl_inverse_base + kTypedSafeEventCtlLanesV13};
    uint32_t reset{active + 1};
    uint32_t final{reset + 1};
    uint32_t commitment_final{final + 1};
    uint32_t query_seed_final{commitment_final + 1};
    uint32_t message_mask_base{query_seed_final + 1};
    uint32_t tag_base{
        message_mask_base + kTypedSafeEventRateV13};
    uint32_t constant_mask_base{
        tag_base + safe_v12::kSafeCapacityV12};
    uint32_t constant_value_base{
        constant_mask_base + kTypedSafeEventRateV13};
    uint32_t query_seed_mask_base{
        constant_value_base + kTypedSafeEventRateV13};
    uint32_t query_seed_lane_base{
        query_seed_mask_base + kTypedSafeEventRateV13};
    uint32_t source_mask_base{
        query_seed_lane_base + kTypedSafeEventRateV13};
    uint32_t source_id_base{
        source_mask_base + kTypedSafeEventSourceSlotsV13};
    uint32_t consumer_mask_base{
        source_id_base + kTypedSafeEventSourceSlotsV13};
    uint32_t consumer_id_base{
        consumer_mask_base + kTypedSafeEventRateV13};
    uint32_t expected_commitment_base{
        consumer_id_base + kTypedSafeEventRateV13};
    uint32_t end{
        expected_commitment_base +
        kTypedSafeEventDigestLanesV13};

    [[nodiscard]] constexpr uint32_t Message(
        uint32_t lane) const
    {
        return message_base + lane;
    }
    [[nodiscard]] constexpr uint32_t Output(
        uint32_t lane) const
    {
        return output_base + lane;
    }
    [[nodiscard]] constexpr uint32_t Bit(
        uint32_t lane, uint32_t bit) const
    {
        return bit_base + lane * 64 + bit;
    }
    [[nodiscard]] constexpr uint32_t HighAnd(
        uint32_t lane, uint32_t step) const
    {
        return high_and_base +
            lane * kTypedSafeEventHighAndStepsV13 + step;
    }
    [[nodiscard]] constexpr uint32_t QuerySeed(
        uint32_t lane) const
    {
        return query_seed_base + lane;
    }
};

inline constexpr uint32_t kTypedSafeEventParentColumnsV13 =
    TypedSafeEventParentLayoutV13{}.end;

struct TypedSafeEventParentProductV13 {
    TypedSafeEventParentLayoutV13 layout{};
    std::vector<TypedSafeEventProgramV13> program;
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    std::vector<alg_hash::Digest> event_output;
    std::vector<TypedSafeEventMessageLocationV13>
        proof_owned_message_locations;
    std::vector<TypedSafeEventOutputLocationV13>
        output_locations;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t trace_rows{0};
    uint32_t active_permutation_rows{0};
    uint32_t proof_owned_message_cells{0};
    uint32_t semantic_receipt_cells{0};
    uint32_t challenge_kinds_covered{0};
    uint32_t verifier_owned_preprocessed_columns{0};
    uint32_t proof_owned_preprocessed_columns{0};
    uint32_t max_algebraic_degree{0};
    uint32_t violations{0};
    bool unique_query_seed_event{false};
    bool every_query_uses_seed_output{false};
    bool complete_challenge_kind_coverage{false};
    bool poseidon_relations_executable{false};
    bool dual_fp3_receipt_ctl_terminal{false};
    bool proof_cells_are_ordinary_columns{false};
    bool parent_owns_real_fri_relation{false};
    bool normalized_child_cells_bound{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

struct TypedSafeEventParentProofV13 {
    uint16_t version{kTypedSafeEventParentVersionV13};
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    aq::AirQuotientRowsProof proof{};
    uint32_t trace_rows{0};
    uint32_t event_count{0};
    bool canonical_proof_encoding{false};
    bool verified{false};
    bool normalized_child_cells_bound{false};
    bool recursive_authority_ready{false};
    std::string note;
};

/** Canonical program commitment; values of ProofOwned cells are excluded. */
[[nodiscard]] alg_hash::Digest
CommitTypedSafeEventProgramV13(
    const std::vector<TypedSafeEventProgramV13>& program);

/**
 * Build the direct parent relation and witness.  The relation seed derives
 * the two Fp3 LogUp challenges and is replayed by the verifier.
 */
[[nodiscard]] bool BuildTypedSafeEventParentV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    const std::vector<TypedSafeEventWitnessV13>& witness,
    const uint256& relation_seed,
    TypedSafeEventParentProductV13& out,
    std::string* why = nullptr);

[[nodiscard]] bool ProveTypedSafeEventParentV13(
    const TypedSafeEventParentProductV13& product,
    const uint256& relation_seed,
    TypedSafeEventParentProofV13& out,
    std::string* why = nullptr);

/**
 * Rebuilds the entire schedule, tags, program root and receipt-commitment
 * boundary from public program metadata plus the claimed compact commitment.
 */
[[nodiscard]] bool VerifyTypedSafeEventParentProofV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    const TypedSafeEventParentProofV13& proof,
    const uint256& relation_seed,
    std::string* why = nullptr);

inline constexpr bool kTypedSafeEventParentExecutableV13 = true;
inline constexpr bool
    kTypedSafeEventNormalizedChildCellsBoundV13 = false;
inline constexpr bool kTypedSafeEventRecursiveAuthorityReadyV13 = false;

static_assert(!kTypedSafeEventNormalizedChildCellsBoundV13);
static_assert(!kTypedSafeEventRecursiveAuthorityReadyV13);

} // namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H
