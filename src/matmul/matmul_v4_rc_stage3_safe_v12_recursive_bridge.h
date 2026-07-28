// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>
#include <matmul/matmul_v4_rc_stage3_p2_prefix_source_air.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_domain_registry.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_nirop_reduction.h>

#include <array>
#include <cstdint>
#include <limits>
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
namespace abi = stage3_multirow_v11_proof_abi;
namespace cb = constraint_bytecode;
namespace domains = stage3_safe_v12_domain_registry;
namespace fsair = stage3_safe_v12_fs_air;
namespace gf = gkr_field;
namespace nirop = stage3_safe_v12_nirop_reduction;
namespace p2source = stage3_p2_prefix_source_air;
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
inline constexpr uint32_t kTypedSafeEventAuxFriSeedKindV13 = 9;

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
    FriSeed = kTypedSafeEventAuxFriSeedKindV13,
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

/**
 * Canonical typed-event schedule extracted from one genuinely accepted V13
 * child FRI proof.
 *
 * This constructor does not accept a caller-authored replay table. It invokes
 * Fri3AlgSafeQ192K2V13BatchVerifyReplay itself, then materializes every SAFE
 * event from the exact verifier-owned transcript snapshot. Consequently a
 * forged challenge/output pair cannot enter the parent schedule merely by
 * setting a host boolean.
 *
 * The outer AirQuotient `airq_lambda` event is intentionally absent: it has a
 * different transcript and is supplied by the outer Split-RAP layer. The
 * returned seven-kind FRI schedule therefore is a complete child-FRI adapter,
 * but is not by itself the eight-kind recursive parent or an authority gate.
 */
struct NativeFri3AlgTypedSafeScheduleV13 {
    enum class TranscriptSourceKind : uint8_t {
        ProtocolConstant = 1,
        PublicFsSeed = 2,
        ProofPowGrindNonce = 3,
        PublicShape = 4,
        ShapeCommitDigest = 5,
        RowRootDigest = 6,
        ChallengeOutput = 7,
        OodEvaluationCommitDigest = 8,
        FoldRootDigest = 9,
    };
    struct TranscriptSourceByte {
        TranscriptSourceKind kind{
            TranscriptSourceKind::ProtocolConstant};
        /** Fold/event/coordinate ordinal, depending on `kind`. */
        uint32_t item_index{0};
        /** Byte within the named scalar/digest/statement object. */
        uint32_t byte_offset{0};
        bool normalized_source_available{false};
        bool hash_relation_required{false};
        /** Exact canonical V13 proof-ABI cell when this is a raw source. */
        abi::SourceKeyV1 abi_key{};
        uint32_t abi_source_address{
            std::numeric_limits<uint32_t>::max()};
        uint8_t byte_in_abi_word{0};
        uint32_t producer_event{
            std::numeric_limits<uint32_t>::max()};
        uint8_t producer_output_lane{0};
        bool canonical_abi_source{false};
        bool prior_event_output_source{false};

        friend bool operator==(
            const TranscriptSourceByte&,
            const TranscriptSourceByte&) = default;
    };
    struct TranscriptWordBinding {
        uint32_t event{0};
        uint32_t message_ordinal{0};
        uint32_t transcript_byte_offset{0};
        gf::Fp packed_le32{0};
        std::array<TranscriptSourceByte, 4> source_bytes{};
        uint32_t bytes_present{0};
        bool every_byte_typed{false};

        friend bool operator==(
            const TranscriptWordBinding&,
            const TranscriptWordBinding&) = default;
    };

    Fri3AlgSafeV13Replay replay;
    std::vector<TypedSafeEventProgramV13> program;
    std::vector<TypedSafeEventWitnessV13> witness;
    std::vector<TranscriptWordBinding> transcript_word_bindings;
    uint32_t events_materialized{0};
    uint32_t proof_owned_message_cells{0};
    uint64_t transcript_byte_occurrences{0};
    uint64_t transcript_bytes_with_normalized_source{0};
    uint64_t transcript_bytes_requiring_hash_relation{0};
    uint64_t transcript_bytes_missing_normalized_source{0};
    uint32_t query_candidate_events{0};
    bool native_proof_verified{false};
    bool exact_event_order{false};
    bool every_snapshot_exactly_materialized{false};
    bool every_safe_output_matches_native_consumer{false};
    bool unique_query_seed_then_q192{false};
    bool every_transcript_byte_typed{false};
    bool pow_grind_nonce_exported_by_normalized_parent{false};
    bool shape_and_ood_commit_hashes_bound_in_parent{false};
    bool outer_air_lambda_present{false};
    bool normalized_child_cells_bound{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildNativeFri3AlgTypedSafeScheduleV13(
    const Fri3AlgBatchProof& proof,
    const uint256& child_fs_seed,
    NativeFri3AlgTypedSafeScheduleV13& out,
    std::string* why = nullptr);

/**
 * Typed parent adapter for the ordered three-oracle multi-row SAFE V13
 * verifier. This is intentionally a distinct type from the single-batch
 * schedule: multi-row V13 samples OOD before its post-claim batching
 * challenge and has a different transcript initializer.
 *
 * The adapter materializes every native replay message as ordinary
 * proof-owned cells, except the fixed query-seed feedback lanes. It does not
 * yet claim normalized proof-codec aliases or recursive consumption.
 */
struct NativeFri3AlgMultiRowTypedSafeScheduleV13 {
    using TranscriptSourceKind =
        NativeFri3AlgTypedSafeScheduleV13::
            TranscriptSourceKind;
    using TranscriptSourceByte =
        NativeFri3AlgTypedSafeScheduleV13::
            TranscriptSourceByte;
    using TranscriptWordBinding =
        NativeFri3AlgTypedSafeScheduleV13::
            TranscriptWordBinding;

    Fri3AlgSafeV13Replay replay;
    std::vector<TypedSafeEventProgramV13> program;
    std::vector<TypedSafeEventWitnessV13> witness;
    std::vector<TranscriptWordBinding> transcript_word_bindings;
    uint32_t events_materialized{0};
    uint32_t proof_owned_message_cells{0};
    uint64_t transcript_byte_occurrences{0};
    uint64_t canonical_abi_byte_occurrences{0};
    uint64_t prior_event_output_byte_occurrences{0};
    uint64_t derived_hash_byte_occurrences{0};
    uint64_t protocol_constant_byte_occurrences{0};
    uint32_t query_candidate_events{0};
    bool native_proof_verified{false};
    bool canonical_multi_row_event_order{false};
    bool every_snapshot_exactly_materialized{false};
    bool every_safe_output_matches_native_consumer{false};
    bool unique_query_seed_then_q192{false};
    bool every_transcript_byte_typed{false};
    bool canonical_v13_source_keys_complete{false};
    bool normalized_child_cells_bound{false};
    bool outer_split_rap_events_bound{false};
    bool recursively_consumed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool
BuildNativeFri3AlgMultiRowTypedSafeScheduleV13(
    const Fri3AlgMultiRowBatchProof& proof,
    const uint256& child_fs_seed,
    NativeFri3AlgMultiRowTypedSafeScheduleV13& out,
    std::string* why = nullptr);

/**
 * Exact outer Split-RAP SAFE V2 replay adapter. Both `airq_lambda` and the
 * final child-FRI seed are exported only after the complete native outer
 * verifier (including its nested multi-row V13 proof) accepts.
 */
struct NativeSplitRapSafeEventsV2 {
    aq::AirQuotientSplitRapSafeReplayV2 replay;
    std::array<TypedSafeEventProgramV13, 2> program;
    std::array<TypedSafeEventWitnessV13, 2> witness;
    bool native_outer_verified{false};
    bool air_lambda_exactly_materialized{false};
    bool fri_seed_exactly_materialized{false};
    bool outputs_match_native_consumers{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildNativeSplitRapSafeEventsV2(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>&
        expected_base_column_indices,
    const uint256& public_fs_seed,
    NativeSplitRapSafeEventsV2& out,
    std::string* why = nullptr);

/**
 * Honest composition audit for the outer SAFE V2 events and its exact
 * nested multi-row SAFE V13 transcript. The child seed is derived from the
 * native outer replay and passed directly into the child verifier adapter.
 *
 * This closes native event materialization, not the final in-parent copy
 * relation: normalized proof-cell aliases and the outer-digest -> child-seed
 * equality chip remain explicit false flags.
 */
struct NativeSplitRapMultiRowTypedSafeScheduleV2 {
    NativeSplitRapSafeEventsV2 outer;
    NativeFri3AlgMultiRowTypedSafeScheduleV13 child;
    std::vector<TypedSafeEventProgramV13> program;
    std::vector<TypedSafeEventWitnessV13> witness;
    std::vector<uint32_t> canonical_v13_abi_words;
    std::vector<abi::SourceCellV1> canonical_v13_sources;
    uint64_t canonical_v13_source_byte_occurrences{0};
    uint64_t canonical_v13_source_byte_occurrences_resolved{0};
    bool child_seed_derived_from_outer_replay{false};
    bool complete_challenge_kind_coverage{false};
    bool canonical_v13_proof_decoded{false};
    bool every_child_transcript_abi_source_resolved{false};
    bool normalized_child_cells_bound{false};
    bool same_parent_child_seed_feedback{false};
    bool recursively_consumed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool
BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>&
        expected_base_column_indices,
    const uint256& public_fs_seed,
    NativeSplitRapMultiRowTypedSafeScheduleV2& out,
    std::string* why = nullptr);

/**
 * Same-parent proof-source attachment for the three residual V13 prefix
 * families found by NativeFri3AlgTypedSafeScheduleV13:
 *
 *  - the exact eight pow_grind_nonce bytes are direct aliases to the
 *    canonical batch-proof decoder;
 *  - ShapeCommit and OodEvalCommit are recomputed by the sparse Poseidon2
 *    source AIR from decoder-owned proof fields; and
 *  - each resulting digest byte is canonical and exported at a fixed cell.
 *
 * This closes those local source relations only. Row/fold roots, prior SAFE
 * outputs and the outer airq event still require the final normalized join.
 */
struct NativeV13NormalizedPrefixAttachment {
    p2source::AttachmentV1 hash_sources;
    std::array<
        stage3_p2_same_parent_join::CellRefV1, 8>
        pow_grind_nonce_bytes{};
    uint32_t nonce_source_occurrences{0};
    uint32_t shape_hash_source_occurrences{0};
    uint32_t ood_hash_source_occurrences{0};
    bool exact_schedule_rebuilt{false};
    bool nonce_from_canonical_proof_decoder{false};
    bool shape_hash_from_proof_decoder_air{false};
    bool ood_hash_from_proof_decoder_air{false};
    bool source_values_preprocessed{true};
    bool complete_child_verifier_same_parent{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool AttachNativeV13NormalizedPrefixSources(
    recursive_fixedpoint::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& child_fs_seed,
    const recursive_fixedpoint::
        NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const recursive_fixedpoint::
        NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const p2source::ReceiptSeedSourceRefsV1& seed_source,
    const NativeFri3AlgTypedSafeScheduleV13& schedule,
    NativeV13NormalizedPrefixAttachment& out,
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
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    uint256 r0_row_group_root{};
    std::array<gf::Fp3, 4> receipt_ctl_challenges{};
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
    bool receipt_ctl_challenges_after_r0{false};
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
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 r0_row_group_root{};
    uint32_t trace_rows{0};
    uint32_t event_count{0};
    bool canonical_proof_encoding{false};
    bool receipt_ctl_challenges_after_r0{false};
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
 * Build the direct parent relation and witness. Every challenge-independent
 * cell is first committed in R0. The public relation seed, authenticated R0
 * root, program root and transcript commitment then derive two independent
 * Fp3 LogUp challenge pairs; only accumulators/inverses live in Rdep. The
 * verifier repeats this exact two-epoch derivation from the Split-RAP proof.
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

// -------------------------------------------------------------------------
// V14 ordinary-AIR typed SAFE transcript leaf.
//
// V13 proves the ordered semantic receipt with a post-R0 LogUp and therefore
// necessarily emits a Split-RAP proof.  V14 removes that recursion type seam:
// one Poseidon2 chip is time-multiplexed between the native SAFE event rows
// and the receipt sponge.  Each event row is followed by a receipt-message
// row whose message cells are adjacent-row direct aliases of the event's
// ProofOwned cells; a final receipt-output row aliases the event digest.  A
// twelve-lane alternating carry preserves the inactive sponge state.  No
// random permutation/lookup challenge exists in this construction.
//
// The layout is intentionally the normalized fixed-point width (575).  It is
// an ordinary AirQuotientRowsProof and can therefore be retained by the
// existing narrow receipt machinery.  Canonical child-proof decoder copy-in
// is still a separate, fail-closed obligation and no authority flag is
// promoted here.
// -------------------------------------------------------------------------

inline constexpr uint16_t kTypedSafeDirectParentVersionV14 = 14;
inline constexpr uint32_t kTypedSafeDirectParentColumnsV14 = 575;

enum class TypedSafeDirectRowKindV14 : uint8_t {
    Padding = 0,
    ReceiptHeader = 1,
    Event = 2,
    ReceiptMessage = 3,
    ReceiptOutput = 4,
};

struct TypedSafeDirectParentLayoutV14 {
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
    uint32_t query_seed_base{
        output_base + kTypedSafeEventDigestLanesV13};
    uint32_t carry_base{
        query_seed_base + kTypedSafeEventDigestLanesV13};
    uint32_t active{carry_base + alg_hash::kAlgHashT};
    uint32_t row_kind{active + 1};
    uint32_t event_reset{row_kind + 1};
    uint32_t event_final{event_reset + 1};
    uint32_t query_seed_final{event_final + 1};
    uint32_t receipt_final{query_seed_final + 1};
    uint32_t message_mask_base{receipt_final + 1};
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
    uint32_t receipt_source_mask_base{
        query_seed_lane_base + kTypedSafeEventRateV13};
    uint32_t receipt_source_start{
        receipt_source_mask_base + kTypedSafeEventRateV13};
    uint32_t expected_commitment_base{receipt_source_start + 1};
    uint32_t end{
        expected_commitment_base +
        kTypedSafeEventDigestLanesV13};

    [[nodiscard]] constexpr uint32_t Message(uint32_t lane) const
    {
        return message_base + lane;
    }
    [[nodiscard]] constexpr uint32_t Output(uint32_t lane) const
    {
        return output_base + lane;
    }
    [[nodiscard]] constexpr uint32_t QuerySeed(uint32_t lane) const
    {
        return query_seed_base + lane;
    }
    [[nodiscard]] constexpr uint32_t Carry(uint32_t lane) const
    {
        return carry_base + lane;
    }
};

static_assert(
    TypedSafeDirectParentLayoutV14{}.end ==
    kTypedSafeDirectParentColumnsV14);

struct TypedSafeDirectAliasV14 {
    uint32_t event{0};
    uint32_t message_ordinal{0};
    uint32_t event_row{0};
    uint32_t event_column{0};
    uint32_t receipt_row{0};
    uint32_t receipt_column{0};

    friend bool operator==(
        const TypedSafeDirectAliasV14&,
        const TypedSafeDirectAliasV14&) = default;
};

/**
 * Witness-free verifier reconstruction for the V14 ordinary-AIR leaf.
 *
 * The complete constraint system, every preprocessed selector/constant and
 * the physical ProofOwned Event -> ReceiptMessage alias inventory are derived
 * only from the typed public program and the public expected receipt.  No
 * proof message value, event output or prover-supplied row enters this API.
 *
 * This is the construction a normalized parent can splice before it has a
 * child witness.  It deliberately does not claim that the canonical child
 * proof decoder has been joined to these exported locations.
 */
struct TypedSafeDirectVerifierCsV14 {
    TypedSafeDirectParentLayoutV14 layout{};
    alg_hash::Digest program_root{};
    alg_hash::Digest expected_transcript_commitment{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<TypedSafeDirectAliasV14>
        proof_cell_aliases;
    uint32_t trace_rows{0};
    uint32_t active_rows{0};
    uint32_t event_rows{0};
    uint32_t receipt_rows{0};
    uint32_t proof_owned_message_cells{0};
    uint32_t challenge_kinds_covered{0};
    bool public_program_rebuilt{false};
    bool witness_free{false};
    bool no_proof_value_preprocessing{false};
    bool physical_alias_inventory_complete{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildTypedSafeDirectVerifierCsV14(
    const std::vector<TypedSafeEventProgramV13>& program,
    const alg_hash::Digest& expected_transcript_commitment,
    TypedSafeDirectVerifierCsV14& out,
    std::string* why = nullptr);

struct TypedSafeDirectParentProductV14 {
    TypedSafeDirectParentLayoutV14 layout{};
    std::vector<TypedSafeEventProgramV13> program;
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    std::vector<alg_hash::Digest> event_output;
    std::vector<TypedSafeDirectAliasV14> proof_cell_aliases;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t trace_rows{0};
    uint32_t active_rows{0};
    uint32_t event_rows{0};
    uint32_t receipt_rows{0};
    uint32_t proof_owned_message_cells{0};
    uint32_t aliased_proof_owned_message_cells{0};
    uint32_t aliased_event_output_cells{0};
    uint32_t challenge_kinds_covered{0};
    uint32_t max_algebraic_degree{0};
    uint32_t violations{0};
    bool ordinary_air{false};
    bool no_post_commit_challenges{false};
    bool physical_alias_inventory_complete{false};
    bool ordered_receipt_hash_in_trace{false};
    bool query_seed_feedback_exact{false};
    bool proof_cells_are_ordinary_columns{false};
    bool canonical_child_proof_decoder_bound{false};
    bool normalized_child_cells_bound{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

struct TypedSafeDirectParentProofV14 {
    uint16_t version{kTypedSafeDirectParentVersionV14};
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    aq::AirQuotientRowsProof proof{};
    uint32_t trace_rows{0};
    uint32_t event_count{0};
    bool canonical_proof_encoding{false};
    bool decoder_copy_in_bound{false};
    bool normalized_child_cells_bound{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool BuildTypedSafeDirectParentV14(
    const std::vector<TypedSafeEventProgramV13>& program,
    const std::vector<TypedSafeEventWitnessV13>& witness,
    TypedSafeDirectParentProductV14& out,
    std::string* why = nullptr);

[[nodiscard]] bool ProveTypedSafeDirectParentV14(
    const TypedSafeDirectParentProductV14& product,
    const uint256& relation_seed,
    TypedSafeDirectParentProofV14& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyTypedSafeDirectParentProofV14(
    const std::vector<TypedSafeEventProgramV13>& program,
    const TypedSafeDirectParentProofV14& proof,
    const uint256& relation_seed,
    const alg_hash::Digest& expected_transcript_commitment,
    std::string* why = nullptr);

inline constexpr bool kTypedSafeDirectParentExecutableV14 = true;
inline constexpr bool
    kTypedSafeDirectCanonicalDecoderBoundV14 = false;
inline constexpr bool kTypedSafeDirectRecursiveAuthorityReadyV14 = false;

static_assert(!kTypedSafeDirectCanonicalDecoderBoundV14);
static_assert(!kTypedSafeDirectRecursiveAuthorityReadyV14);

} // namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H
