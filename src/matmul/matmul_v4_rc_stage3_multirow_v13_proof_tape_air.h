// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_H

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace gf = gkr_field;
namespace p2air = stage3_poseidon_air;

inline constexpr uint16_t kProofTapeAirVersionV1 = 1;
inline constexpr uint32_t kRecordsPerRowV1 = 4;
inline constexpr uint32_t kPublicRootCountV1 = 4;
inline constexpr uint32_t kPublicRootLimbsV1 = 8;
inline constexpr uint32_t kPublicPrefixRecordsV1 =
    kPublicRootCountV1 * kPublicRootLimbsV1;
inline constexpr uint32_t kHeaderRecordsV1 =
    abi::kFieldAbiHeaderWordsV1;

/**
 * The verifier-owned shape needed to regenerate the complete SAFE-V13
 * semantic source schedule.  No proof value or proof-derived count appears
 * here.  In particular, query count, group count, blowup and K=2 are protocol
 * constants; path depths and every vector length follow from n_coeffs and
 * this statement shape.
 */
struct PublicShapeV1 {
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    std::vector<uint32_t> base_column_indices;

    bool operator==(const PublicShapeV1&) const = default;
};

/**
 * Public objects selected before any dependent CTL challenge.
 *
 * tape_root is the four-lane Poseidon2 digest recomputed by this AIR over:
 *   program_root || statement_root || public_fs_seed || proof_wire_root ||
 *   the fixed SAFE-V13 ABI header || every ordered [address,value] record.
 *
 * proof_wire_root is intentionally a public commitment here.  Equality
 * between its external wire codec and the canonical source cells is owned by
 * the downstream codec/phase join; this table prevents either object from
 * being transplanted after R0.
 */
struct PublicBindingV1 {
    uint256 program_root{};
    uint256 statement_root{};
    uint256 public_fs_seed{};
    uint256 proof_wire_root{};
    alg_hash::Digest tape_root{};

    bool operator==(const PublicBindingV1&) const = default;
};

enum class RecordClassV1 : uint8_t {
    PublicProgramRoot = 1,
    PublicStatementRoot = 2,
    PublicFsSeedRoot = 3,
    PublicProofWireRoot = 4,
    AbiHeader = 5,
    AbiSource = 6,
    Padding = 7,
};

struct RecordScheduleV1 {
    RecordClassV1 record_class{RecordClassV1::Padding};
    uint32_t expected_address{0};
    bool fixed_value{true};
    uint32_t expected_value{0};
    bool source_record{false};
    bool fp_low_limb{false};
    abi::SourceKeyV1 key{};
    abi::OwnershipClassV1 ownership{
        abi::OwnershipClassV1::ChildProofEnvelope};
};

struct SourceAddressCellV1 {
    abi::SourceKeyV1 key{};
    abi::OwnershipClassV1 ownership{
        abi::OwnershipClassV1::ChildProofEnvelope};
    uint32_t address{0};
    uint32_t row{0};
    uint32_t slot{0};
    uint32_t address_column{0};
    uint32_t value_column{0};
};

/**
 * Four [address,value] records are absorbed per Poseidon2 row.  Every value
 * has an independent 32-bit decomposition.  Semantic metadata and structural
 * constants are verifier-generated preprocessed columns; raw proof values
 * never are.
 */
struct LayoutV1 {
    p2air::Layout poseidon{};
    uint32_t address_base{0};
    uint32_t value_base{0};
    uint32_t bit_base{0};
    uint32_t high_is_max_base{0};
    uint32_t high_delta_inverse_base{0};

    uint32_t active_base{0};
    uint32_t source_base{0};
    uint32_t fixed_value_base{0};
    uint32_t expected_address_base{0};
    uint32_t expected_value_base{0};
    uint32_t fp_low_base{0};
    uint32_t successor_base{0};
    uint32_t record_class_base{0};
    uint32_t semantic_kind_base{0};
    uint32_t semantic_a_base{0};
    uint32_t semantic_b_base{0};
    uint32_t semantic_c_base{0};
    uint32_t semantic_packed_base{0};

    /**
     * Verifier-owned expected tape-root limbs.  These are ordinary R0 /
     * preprocessed statement columns, rather than constants captured by an
     * opaque callback.  Keeping the expected root in cells makes the
     * terminal identity expressible by one proof-independent canonical
     * ProgramTable while the public value remains bound by the R0 session.
     */
    uint32_t expected_tape_root_base{0};

    /** Sole Rdep placeholder. All preceding columns belong to global R0. */
    uint32_t dependent_zero{0};

    [[nodiscard]] uint32_t Address(uint32_t slot) const
    {
        return address_base + slot;
    }
    [[nodiscard]] uint32_t Value(uint32_t slot) const
    {
        return value_base + slot;
    }
    [[nodiscard]] uint32_t Bit(
        uint32_t slot, uint32_t bit) const
    {
        return bit_base + 32 * slot + bit;
    }
    [[nodiscard]] uint32_t HighIsMax(uint32_t slot) const
    {
        return high_is_max_base + slot;
    }
    [[nodiscard]] uint32_t HighDeltaInverse(
        uint32_t slot) const
    {
        return high_delta_inverse_base + slot;
    }
    [[nodiscard]] uint32_t Active(uint32_t slot) const
    {
        return active_base + slot;
    }
    [[nodiscard]] uint32_t Source(uint32_t slot) const
    {
        return source_base + slot;
    }
    [[nodiscard]] uint32_t FixedValue(uint32_t slot) const
    {
        return fixed_value_base + slot;
    }
    [[nodiscard]] uint32_t ExpectedAddress(
        uint32_t slot) const
    {
        return expected_address_base + slot;
    }
    [[nodiscard]] uint32_t ExpectedValue(
        uint32_t slot) const
    {
        return expected_value_base + slot;
    }
    [[nodiscard]] uint32_t FpLow(uint32_t slot) const
    {
        return fp_low_base + slot;
    }
    [[nodiscard]] uint32_t Successor(uint32_t slot) const
    {
        return successor_base + slot;
    }
    [[nodiscard]] uint32_t RecordClass(uint32_t slot) const
    {
        return record_class_base + slot;
    }
    [[nodiscard]] uint32_t SemanticKind(uint32_t slot) const
    {
        return semantic_kind_base + slot;
    }
    [[nodiscard]] uint32_t SemanticA(uint32_t slot) const
    {
        return semantic_a_base + slot;
    }
    [[nodiscard]] uint32_t SemanticB(uint32_t slot) const
    {
        return semantic_b_base + slot;
    }
    [[nodiscard]] uint32_t SemanticC(uint32_t slot) const
    {
        return semantic_c_base + slot;
    }
    [[nodiscard]] uint32_t SemanticPacked(
        uint32_t slot) const
    {
        return semantic_packed_base + slot;
    }
    [[nodiscard]] uint32_t ExpectedTapeRoot(
        uint32_t lane) const
    {
        return expected_tape_root_base + lane;
    }
    [[nodiscard]] uint32_t End() const
    {
        return dependent_zero + 1;
    }
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ScheduleV1 {
    PublicShapeV1 shape{};
    std::vector<RecordScheduleV1> records;
    std::vector<abi::SourceCellV1> semantic_sources;
    uint32_t source_records{0};
    uint32_t active_records{0};
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    bool exact_safe_v13_header{false};
    bool semantic_schedule_regenerated{false};
    bool stable_addresses{false};
    bool valid{false};
    std::string note;
};

/** Build only from verifier-owned public shape; proof words are not inputs. */
[[nodiscard]] ScheduleV1 BuildScheduleV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding);

/**
 * Build the fixed verifier constraint system.  It depends on public shape,
 * public bindings and the expected tape root, never on a child proof value.
 */
[[nodiscard]] bool BuildConstraintSystemV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    aq::AirConstraintSystem<gf::Fp3>& out,
    LayoutV1* layout = nullptr,
    ScheduleV1* schedule = nullptr,
    std::string* why = nullptr);

/** Exact AIR-owned Poseidon tape digest for canonical SAFE-V13 ABI words. */
[[nodiscard]] alg_hash::Digest ComputeTapeRootV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words,
    std::string* why = nullptr);

/** Public seed used by the standalone proof-level table canary. */
[[nodiscard]] uint256 DeriveProofFsSeedV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding);

struct ProductV1 {
    LayoutV1 layout{};
    ScheduleV1 schedule{};
    PublicBindingV1 binding{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    std::vector<SourceAddressCellV1> source_cells;
    uint32_t violations{0};
    uint32_t first_bad_row{UINT32_MAX};
    std::string first_bad_constraint;
    bool fixed_verifier_owned_schedule{false};
    bool no_preprocessed_proof_values{false};
    bool canonical_u32_decomposition_air{false};
    bool canonical_fp_pairs_air{false};
    bool monotone_no_omission_addresses_air{false};
    bool fixed_protocol_header_air{false};
    bool public_bindings_in_r0{false};
    bool stable_source_exports{false};
    /** External wire-codec equality belongs to the downstream phase join. */
    bool proof_wire_codec_correspondence{false};
    /** Program/statement root preimage equality is not claimed by this tape. */
    bool public_root_preimage_correspondence{false};
    bool complete_v13_consumption{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * The host canonical decoder is used only to materialize the honest witness.
 * Product validity is recomputed from the fixed constraint system and the
 * retained R0 commitment.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words);

struct ProofV1 {
    uint16_t version{kProofTapeAirVersionV1};
    uint256 r0_row_root{};
    alg_hash::Digest tape_root{};
    aq::AirQuotientSplitRapRowsProof proof{};
    bool complete_v13_consumption{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    ProofV1& out,
    std::string* why = nullptr);

/** Rebuilds the fixed CS and invokes the unmodified SAFE Split-RAP verifier. */
[[nodiscard]] bool VerifyV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const ProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kProofTapeAirExecutableV1 = true;
inline constexpr bool kCompleteV13ConsumptionV1 = false;
inline constexpr bool kRecursiveAuthorityReadyV1 = false;

static_assert(!kCompleteV13ConsumptionV1);
static_assert(!kRecursiveAuthorityReadyV1);

// ---------------------------------------------------------------------------
// Packed proof-tape V2.
//
// V1 uses four [address,value] records per row because one Poseidon2 rate
// block holds eight field lanes.  A production-width SAFE proof therefore
// expands to 2^21 tape rows.  V2 packs 64 records per row without changing the
// canonical record order or tape digest: sixteen fixed Poseidon2 instances
// are chained inside each row, and instance 15 chains into instance 0 of the
// next row.  This is a representation change only; V1 remains frozen.
// ---------------------------------------------------------------------------

inline constexpr uint16_t kProofTapeAirVersionV2 = 2;
inline constexpr uint32_t kRecordsPerRowV2 = 64;
inline constexpr uint32_t kRecordsPerPoseidonV2 = 4;
inline constexpr uint32_t kPoseidonInstancesPerRowV2 =
    kRecordsPerRowV2 / kRecordsPerPoseidonV2;
static_assert(kPoseidonInstancesPerRowV2 == 16);

struct ScheduleV2 {
    PublicShapeV1 shape{};
    /** Active records only; padding is uniquely all-zero by row/slot. */
    std::vector<RecordScheduleV1> active_schedule;
    /** Complete verifier-owned schedule, including the unique zero suffix. */
    std::vector<RecordScheduleV1> records;
    std::vector<abi::SourceCellV1> semantic_sources;
    uint256 source_inventory_root{};
    uint32_t source_records{0};
    uint32_t active_records{0};
    uint32_t padding_records{0};
    uint32_t trace_rows{0};
    bool exact_v1_record_order{false};
    bool immutable_row_slot_mapping{false};
    bool exact_source_multiplicity{false};
    bool canonical_padding{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ScheduleV2 BuildScheduleV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding);

/** Exact V1 digest over the same ordered record stream, evaluated 16 blocks
 * per V2 row. */
[[nodiscard]] alg_hash::Digest ComputeTapeRootV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words,
    std::string* why = nullptr);

struct LayoutV2 {
    std::array<p2air::Layout,
               kPoseidonInstancesPerRowV2> poseidon{};
    uint32_t address_base{0};
    uint32_t value_base{0};
    uint32_t bit_base{0};
    uint32_t high_is_max_base{0};
    uint32_t high_delta_inverse_base{0};
    uint32_t active_base{0};
    uint32_t source_base{0};
    uint32_t fixed_value_base{0};
    uint32_t expected_address_base{0};
    uint32_t expected_value_base{0};
    uint32_t fp_low_base{0};
    uint32_t successor_base{0};
    uint32_t record_class_base{0};
    uint32_t semantic_kind_base{0};
    uint32_t semantic_a_base{0};
    uint32_t semantic_b_base{0};
    uint32_t semantic_c_base{0};
    uint32_t semantic_packed_base{0};
    uint32_t expected_tape_root_base{0};
    uint32_t dependent_zero{0};

    [[nodiscard]] uint32_t Address(uint32_t slot) const
    { return address_base + slot; }
    [[nodiscard]] uint32_t Value(uint32_t slot) const
    { return value_base + slot; }
    [[nodiscard]] uint32_t Bit(uint32_t slot, uint32_t bit) const
    { return bit_base + 32 * slot + bit; }
    [[nodiscard]] uint32_t HighIsMax(uint32_t slot) const
    { return high_is_max_base + slot; }
    [[nodiscard]] uint32_t HighDeltaInverse(uint32_t slot) const
    { return high_delta_inverse_base + slot; }
    [[nodiscard]] uint32_t Active(uint32_t slot) const
    { return active_base + slot; }
    [[nodiscard]] uint32_t Source(uint32_t slot) const
    { return source_base + slot; }
    [[nodiscard]] uint32_t FixedValue(uint32_t slot) const
    { return fixed_value_base + slot; }
    [[nodiscard]] uint32_t ExpectedAddress(uint32_t slot) const
    { return expected_address_base + slot; }
    [[nodiscard]] uint32_t ExpectedValue(uint32_t slot) const
    { return expected_value_base + slot; }
    [[nodiscard]] uint32_t FpLow(uint32_t slot) const
    { return fp_low_base + slot; }
    [[nodiscard]] uint32_t Successor(uint32_t slot) const
    { return successor_base + slot; }
    [[nodiscard]] uint32_t RecordClass(uint32_t slot) const
    { return record_class_base + slot; }
    [[nodiscard]] uint32_t SemanticKind(uint32_t slot) const
    { return semantic_kind_base + slot; }
    [[nodiscard]] uint32_t SemanticA(uint32_t slot) const
    { return semantic_a_base + slot; }
    [[nodiscard]] uint32_t SemanticB(uint32_t slot) const
    { return semantic_b_base + slot; }
    [[nodiscard]] uint32_t SemanticC(uint32_t slot) const
    { return semantic_c_base + slot; }
    [[nodiscard]] uint32_t SemanticPacked(uint32_t slot) const
    { return semantic_packed_base + slot; }
    [[nodiscard]] uint32_t ExpectedTapeRoot(uint32_t lane) const
    { return expected_tape_root_base + lane; }
    [[nodiscard]] uint32_t End() const
    { return dependent_zero + 1; }
};

[[nodiscard]] LayoutV2 CanonicalLayoutV2();

/**
 * Version-neutral semantic source locator.  Downstream recursive joins must
 * consume this resolver instead of reproducing V1/V2 row packing arithmetic.
 */
[[nodiscard]] std::optional<SourceAddressCellV1> ResolveSourceKeyV2(
    const ScheduleV2& schedule,
    const LayoutV2& layout,
    const abi::SourceKeyV1& key);

[[nodiscard]] std::optional<SourceAddressCellV1> ResolveSourceAddressV2(
    const ScheduleV2& schedule,
    const LayoutV2& layout,
    uint32_t address);

/**
 * Verify canonical decoded words against the immutable packed schedule.
 * This is the codec/ownership gate used before witness materialization; it
 * rejects wrong slots/addresses, reorder, duplicate, omission, nonzero
 * padding, source-key transplant and any value tamper against `tape_root`.
 */
[[nodiscard]] bool VerifyPackedWordsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words,
    std::string* why = nullptr);

[[nodiscard]] uint256 DeriveProofFsSeedV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const uint256& source_inventory_root);

inline constexpr bool kProofTapePackedExecutableV2 = true;
inline constexpr bool kPackedTapeRecursiveAuthorityReadyV2 = false;
static_assert(!kPackedTapeRecursiveAuthorityReadyV2);

// ---------------------------------------------------------------------------
// Streaming sharded tape V2.
//
// The 64-record diagnostic layout above is intentionally not a proof path:
// its ~10.9k columns make the Q192 row openings exceed the block envelope.
// Production instead retains the narrow four-record layout and divides the
// exact V1 next-power-of-two tape into contiguous, proof-executed shards.
// ---------------------------------------------------------------------------

inline constexpr uint16_t kProofTapeShardVersionV2 = 2;
inline constexpr uint32_t kProofTapeShardMaxRowsV2 = 1U << 19;
inline constexpr uint32_t kProofTapeShardRecordsPerRowV2 =
    kRecordsPerRowV1;

struct ShardPlanV2 {
    uint32_t shard_index{0};
    uint32_t shard_count{0};
    uint32_t row_begin{0};
    uint32_t trace_rows{0};
    uint32_t record_begin{0};
    uint32_t record_count{0};
    uint32_t active_records{0};
    uint32_t total_trace_rows{0};
    uint32_t total_records{0};
    uint32_t total_active_records{0};
    bool contains_first_row{false};
    bool contains_final_row{false};
    bool contains_canonical_padding{false};
    bool valid{false};
};

[[nodiscard]] std::vector<ShardPlanV2> BuildShardPlansV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding);

/** Test/model helper.  Production callers must use BuildShardPlansV2. */
[[nodiscard]] std::vector<ShardPlanV2> BuildShardPlansForMaxRowsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    uint32_t max_rows);

[[nodiscard]] uint256 ComputeShardSourceInventoryRootV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding);

[[nodiscard]] gf::Fp3 ShardAddressTagV2(
    uint32_t shard_index,
    uint32_t address);

struct ShardLayoutV2 {
    LayoutV1 tape{};
    uint32_t expected_start_state_base{0};
    uint32_t expected_end_state_base{0};
    uint32_t expected_first_value{0};
    uint32_t expected_next_value{0};
    uint32_t dependent_base{0};
    uint32_t source_inverse_base{0};
    uint32_t running_base{0};
    uint32_t expected_terminal_base{0};

    [[nodiscard]] uint32_t ExpectedStartState(uint32_t lane) const
    { return expected_start_state_base + lane; }
    [[nodiscard]] uint32_t ExpectedEndState(uint32_t lane) const
    { return expected_end_state_base + lane; }
    [[nodiscard]] uint32_t SourceInverse(
        uint32_t lane, uint32_t slot) const
    {
        return source_inverse_base +
            lane * kProofTapeShardRecordsPerRowV2 +
            slot;
    }
    [[nodiscard]] uint32_t Running(uint32_t lane) const
    { return running_base + lane; }
    [[nodiscard]] uint32_t ExpectedTerminal(uint32_t lane) const
    { return expected_terminal_base + lane; }
    [[nodiscard]] uint32_t End() const
    { return expected_terminal_base + 2; }
};

[[nodiscard]] ShardLayoutV2 CanonicalShardLayoutV2();

struct ShardStatementV2 {
    PublicShapeV1 child_shape{};
    PublicBindingV1 binding{};
    ShardPlanV2 plan{};
    alg_hash::State start_state{};
    alg_hash::State end_state{};
    uint32_t first_record_value{0};
    uint32_t next_record_value{0};
    uint256 source_inventory_root{};
};

struct ShardBoundaryStatesV2 {
    std::vector<alg_hash::State> states;
    std::vector<uint32_t> first_record_values;
    std::vector<uint32_t> next_record_values;
    alg_hash::Digest final_root{};
    bool exact_v1_tape_root{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ShardBoundaryStatesV2 ComputeShardBoundaryStatesV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words);

[[nodiscard]] bool BuildShardConstraintSystemV2(
    const ShardStatementV2& statement,
    aq::AirConstraintSystem<gf::Fp3>& out,
    ShardLayoutV2* layout = nullptr,
    std::vector<RecordScheduleV1>* records = nullptr,
    std::string* why = nullptr);

struct ShardProductV2 {
    ShardStatementV2 statement{};
    ShardLayoutV2 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    std::vector<SourceAddressCellV1> source_cells;
    uint32_t violations{0};
    uint32_t first_bad_row{UINT32_MAX};
    std::string first_bad_constraint;
    bool exact_schedule_slice{false};
    bool exact_state_boundary{false};
    bool stable_source_exports{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ShardProductV2 BuildShardProductV2(
    const ShardStatementV2& statement,
    const std::vector<uint32_t>& canonical_words);

struct ShardProofV2 {
    uint16_t version{kProofTapeShardVersionV2};
    uint32_t shard_index{0};
    uint256 r0_row_root{};
    uint256 join_context_root{};
    std::array<gf::Fp3, 2> source_terminal{};
    aq::AirQuotientSplitRapRowsProof proof{};
};

struct ShardJoinContextV2 {
    std::vector<uint256> tape_r0_roots;
    std::vector<uint256> consumer_r0_roots;
    uint256 root{};
    bool valid{false};
};

struct ShardSourceChallengesV2 {
    std::array<gf::Fp3, 2> gamma{};
    std::array<gf::Fp3, 2> alpha{};
};

[[nodiscard]] ShardJoinContextV2 BuildShardJoinContextV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint256>& tape_r0_roots,
    const std::vector<uint256>& consumer_r0_roots);

/** Canonical transcript derivation shared by tape and recursive consumers. */
[[nodiscard]] bool DeriveShardSourceChallengesV2(
    const ShardStatementV2& statement,
    const uint256& r0_row_root,
    const ShardJoinContextV2& join_context,
    ShardSourceChallengesV2& out);

[[nodiscard]] bool ProveShardV2(
    const ShardProductV2& product,
    const ShardJoinContextV2& join_context,
    ShardProofV2& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyShardV2(
    const ShardStatementV2& statement,
    const ShardJoinContextV2& join_context,
    const ShardProofV2& proof,
    std::string* why = nullptr);

struct ShardReceiptV2 {
    ShardPlanV2 plan{};
    alg_hash::State start_state{};
    alg_hash::State end_state{};
    uint32_t first_record_value{0};
    uint32_t next_record_value{0};
    uint256 source_inventory_root{};
    ShardProofV2 proof{};
};

[[nodiscard]] bool VerifyShardCoverageChainForMaxRowsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<ShardReceiptV2>& receipts,
    uint32_t max_rows,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyShardReceiptChainV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const ShardJoinContextV2& join_context,
    const std::vector<ShardReceiptV2>& receipts,
    std::string* why = nullptr);

/** Test/model helper for the same verifier with a smaller shard-row ceiling. */
[[nodiscard]] bool VerifyShardReceiptChainForMaxRowsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const ShardJoinContextV2& join_context,
    const std::vector<ShardReceiptV2>& receipts,
    uint32_t max_rows,
    std::string* why = nullptr);

inline constexpr bool kProofTapeShardExecutableV2 = true;
inline constexpr bool kProofTapeShardRecursiveAuthorityReadyV2 = false;
static_assert(!kProofTapeShardRecursiveAuthorityReadyV2);

// ---------------------------------------------------------------------------
// Public-challenge ordinary-proof shard V3.
//
// V2 remains frozen above.  V3 removes the delayed R0 dependency from the
// source-terminal challenges: the complete shard AIR is fixed from public
// roots before its one ordinary AlgAir commitment is made.
// ---------------------------------------------------------------------------

inline constexpr uint16_t kProofTapeShardVersionV3 = 3;

/**
 * Verifier-recomputable Fiat--Shamir seed for the complete V3 shard AIR.
 * Every input is either part of the public statement or the source terminal
 * carried by (and equality-constrained inside) the shard proof.
 */
[[nodiscard]] uint256 DeriveShardPublicFsSeedV3(
    const ShardStatementV2& statement,
    const std::array<gf::Fp3, 2>& source_terminal);

[[nodiscard]] bool DeriveShardPublicSourceChallengesV3(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const uint256& source_inventory_root,
    uint32_t shard_count,
    ShardSourceChallengesV2& out);

[[nodiscard]] bool BuildShardFinalConstraintSystemV3(
    const ShardStatementV2& statement,
    const std::array<gf::Fp3, 2>& source_terminal,
    aq::AirConstraintSystem<gf::Fp3>& out,
    ShardLayoutV2* layout = nullptr,
    std::string* why = nullptr);

struct ShardProofV3 {
    uint16_t version{kProofTapeShardVersionV3};
    uint32_t shard_index{0};
    std::array<gf::Fp3, 2> source_terminal{};
    aq::AirQuotientRowsProof proof{};
};

/**
 * Convert the streaming-row prover payload into the ordinary Alg verifier
 * proof type and canonicalize it through the consensus proof codec.  This is
 * the representation accepted by normalized recursive child receipts.
 */
[[nodiscard]] std::optional<AirQuotientProofAlg>
CanonicalShardPublicAlgProofV3(
    const ShardProofV3& proof,
    std::vector<unsigned char>* canonical_bytes = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool ProveShardPublicV3(
    const ShardProductV2& product,
    ShardProofV3& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyShardPublicV3(
    const ShardStatementV2& statement,
    const ShardProofV3& proof,
    std::string* why = nullptr);

inline constexpr bool kProofTapeShardPublicExecutableV3 = true;
inline constexpr bool kProofTapeShardPublicRecursiveAuthorityReadyV3 = false;
static_assert(!kProofTapeShardPublicRecursiveAuthorityReadyV3);

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_H
