// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
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

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_H
