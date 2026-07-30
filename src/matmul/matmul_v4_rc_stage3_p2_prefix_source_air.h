// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_PREFIX_SOURCE_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_PREFIX_SOURCE_AIR_H

#include <matmul/matmul_v4_rc_stage3_p2_normalized_exports.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Proof-owned V10 prefix sources in the normalized parent.
//
// The FRI transcript consumes three byte families which are not literal
// fields of its serialized batch proof:
//
//   * the receipt/public-statement Fiat--Shamir seed;
//   * ShapeCommit(n_coeffs, column_len); and
//   * OodEvalCommit(z1,z2,evals_z1,evals_z2).
//
// This append-only chip closes those local source relations without installing
// any digest or proof value as a preprocessed column:
//
//   * eight pre-existing receipt seed u32 cells are bit-decomposed to 32 bytes;
//   * one fixed-width, sparse Poseidon2 table hashes both exact payloads;
//   * payload lanes are gathered by deterministic copy constraints directly
//     from the canonical proof-field codec columns; and
//   * both four-lane digest outputs are canonically decomposed to 32 bytes.
//
// The source schedule is verifier-regenerated from the proof shape.  Only
// boolean row selectors are preprocessed.  Recursive authority deliberately
// remains false until the complete child verifier that owns the seed and codec
// cells is consumed by this same parent.
// ============================================================================

namespace matmul::v4::rc::stage3_p2_prefix_source_air {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;
namespace p2exports = stage3_p2_normalized_exports;
namespace p2join = stage3_p2_same_parent_join;
namespace pa = stage3_poseidon_air;

using gf::Fp3;

inline constexpr uint16_t kPrefixSourceAirVersionV1 = 1;
inline constexpr uint32_t kSeedWordsV1 = 8;
inline constexpr uint32_t kSeedBytesV1 = 32;
inline constexpr uint32_t kDigestLanesV1 = 4;
inline constexpr uint32_t kDigestBytesV1 = 32;
inline constexpr uint32_t kGatherBanksV1 = 2;
inline constexpr uint32_t kGatherLanesV1 = 8;
inline constexpr uint32_t kSourcePortsV1 = 8;

struct ReceiptSeedSourceRefsV1 {
    std::array<p2join::CellRefV1, kSeedWordsV1> u32_word{};
    bool canonical_receipt_statement{false};
    bool verifier_recomputed_seed{false};
    bool cells_bound_before_first_commitment{false};
    bool complete_child_verifier_same_parent{false};
};

struct LayoutV1 {
    uint32_t base{0};
    pa::Layout permutation;
    uint32_t message_base{0};
    uint32_t state_base{0};
    uint32_t active{0};
    uint32_t first{0};
    uint32_t terminal{0};
    uint32_t shape{0};
    uint32_t ood{0};
    uint32_t gather_base{0};
    uint32_t gather_load_selector_base{0};
    uint32_t gather_carry_selector_base{0};
    uint32_t gather_target_selector_base{0};
    uint32_t gather_u32_port_selector_base{0};
    uint32_t gather_fp_port_selector_base{0};
    uint32_t padding_one_selector_base{0};
    uint32_t seed_byte_base{0};
    uint32_t seed_bit_base{0};
    uint32_t seed_word_active_base{0};
    uint32_t digest_byte_base{0};
    uint32_t digest_bit_base{0};
    uint32_t digest_high_is_max_base{0};
    uint32_t digest_high_delta_inverse_base{0};
    uint32_t eval_count_carrier{0};
    uint32_t eval_count_load_selector{0};
    uint32_t eval_count_carry_selector{0};
    uint32_t eval_count_sink_selector{0};

    LayoutV1(uint32_t start = 0);

    [[nodiscard]] uint32_t Message(uint32_t lane) const;
    [[nodiscard]] uint32_t State(uint32_t lane) const;
    [[nodiscard]] uint32_t Gather(
        uint32_t bank, uint32_t lane) const;
    [[nodiscard]] uint32_t GatherLoadSelector(
        uint32_t bank, uint32_t lane) const;
    [[nodiscard]] uint32_t GatherCarrySelector(
        uint32_t bank, uint32_t lane) const;
    [[nodiscard]] uint32_t GatherTargetSelector(
        uint32_t bank, uint32_t lane) const;
    [[nodiscard]] uint32_t GatherU32PortSelector(
        uint32_t bank, uint32_t lane, uint32_t port) const;
    [[nodiscard]] uint32_t GatherFpPortSelector(
        uint32_t bank, uint32_t lane, uint32_t port) const;
    [[nodiscard]] uint32_t PaddingOneSelector(
        uint32_t lane) const;
    [[nodiscard]] uint32_t SeedByte(
        uint32_t word, uint32_t byte) const;
    [[nodiscard]] uint32_t SeedBit(
        uint32_t word, uint32_t byte, uint32_t bit) const;
    [[nodiscard]] uint32_t SeedWordActive(
        uint32_t word) const;
    [[nodiscard]] uint32_t DigestByte(
        uint32_t lane, uint32_t byte) const;
    [[nodiscard]] uint32_t DigestBit(
        uint32_t lane, uint32_t byte, uint32_t bit) const;
    [[nodiscard]] uint32_t DigestHighIsMax(
        uint32_t lane) const;
    [[nodiscard]] uint32_t DigestHighDeltaInverse(
        uint32_t lane) const;
    [[nodiscard]] uint32_t End() const;
};

struct AttachmentV1 {
    uint16_t version{kPrefixSourceAirVersionV1};
    LayoutV1 layout;
    p2exports::ProofOwnedPrefixSourceRefsV1 exports;
    uint32_t original_columns{0};
    uint32_t parent_rows{0};
    uint32_t shape_payload_fields{0};
    uint32_t ood_payload_fields{0};
    uint32_t shape_blocks{0};
    uint32_t ood_blocks{0};
    uint32_t shape_terminal_row{0};
    uint32_t ood_terminal_row{0};
    uint32_t gathered_source_fields{0};
    uint32_t cross_row_fp_sources{0};
    uint32_t added_columns{0};
    uint32_t constraint_base{0};
    uint32_t added_constraints{0};
    uint32_t violations{0};

    bool receipt_seed_cells_preexisting{false};
    bool receipt_seed_canonical_u32{false};
    bool receipt_seed_byte_decomposition_constrained{false};
    bool shape_payload_direct_codec_aliases{false};
    bool ood_payload_direct_codec_aliases{false};
    bool eval_counts_equality_constrained{false};
    bool sparse_poseidon_permutations_constrained{false};
    bool sponge_state_transitions_constrained{false};
    bool exact_10star_padding{false};
    bool digest_outputs_canonical_bytes{false};
    /** Fail-closed sentinel; Attach sets false only after auditing every pin. */
    bool source_values_preprocessed{true};
    bool selectors_only_preprocessed{false};
    bool complete_child_verifier_same_parent{false};
    bool recursively_consumed{false};
    bool recursive_authority{false};
    bool valid{false};
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Append the complete local prefix-source chip.
 *
 * `proof_bus` must expose the exact canonical V10 codec words in its ordinary
 * committed Field(port) columns. `seed_source` must name eight existing parent
 * cells, each an exact canonical u32 limb of `fs_seed`.
 */
[[nodiscard]] bool AttachV10PrefixSourceAirV1(
    fp::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const ReceiptSeedSourceRefsV1& seed_source,
    AttachmentV1& out,
    std::string* why = nullptr);

/**
 * V13 wrapper over the same proof-codec source chip. ShapeCommit and
 * OodEvalCommit have identical algebraic definitions in V10 and V13; only
 * the surrounding challenge oracle/version changes. Keeping a named wrapper
 * prevents either protocol from being accepted through an implicit
 * "version-any" path.
 */
[[nodiscard]] bool AttachV13PrefixSourceAirV1(
    fp::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const ReceiptSeedSourceRefsV1& seed_source,
    AttachmentV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateV10PrefixSourceAirV1(
    const fp::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const ReceiptSeedSourceRefsV1& seed_source,
    const AttachmentV1& attachment,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateV13PrefixSourceAirV1(
    const fp::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const ReceiptSeedSourceRefsV1& seed_source,
    const AttachmentV1& attachment,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolations(
    const fp::FoldBusComposition& parent);

inline constexpr bool kPrefixSourceAirLocalExecutableV1 = true;
inline constexpr bool kPrefixSourceAirRecursiveAuthorityV1 = false;
static_assert(kPrefixSourceAirLocalExecutableV1);
static_assert(!kPrefixSourceAirRecursiveAuthorityV1);

} // namespace matmul::v4::rc::stage3_p2_prefix_source_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_PREFIX_SOURCE_AIR_H
