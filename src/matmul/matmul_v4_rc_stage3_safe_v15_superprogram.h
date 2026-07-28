// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V15_SUPERPROGRAM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V15_SUPERPROGRAM_H

#include <matmul/matmul_v4_rc_stage3_safe_v12_recursive_bridge.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_safe_v15_superprogram {

namespace gf = gkr_field;
namespace aq = air_quotient;
namespace bridge =
    stage3_safe_v12_recursive_bridge;
namespace abi =
    stage3_multirow_v11_proof_abi;

inline constexpr uint16_t kVersionV15 = 15;
inline constexpr uint32_t kProducerSlotsV15 = 2;
inline constexpr uint32_t kConsumerWordLanesV15 = 8;
inline constexpr uint32_t kConsumerBytePortsV15 = 32;
inline constexpr uint32_t kDescriptorLanesV15 = 8;

/**
 * Fixed public placement of one canonical decoder byte at one actual V14
 * ProofOwned message cell.  No value is carried in this descriptor: the
 * source value comes from DecodeCanonicalSafeV13 and the consumer value is
 * read from V14's ordinary Message column.
 */
struct CanonicalSourceConsumerRecordV15 {
    uint32_t source_address{0};
    uint8_t source_byte{0};
    uint32_t child_event{0};
    uint32_t message_ordinal{0};
    uint8_t message_byte{0};
    uint32_t v14_row{0};
    uint32_t v14_column{0};
    uint8_t consumer_port{0};

    friend bool operator==(
        const CanonicalSourceConsumerRecordV15&,
        const CanonicalSourceConsumerRecordV15&) = default;
};

struct CanonicalSourceV15 {
    abi::SourceCellV1 decoded{};
    std::array<uint32_t, 4> use_multiplicity{};
    uint32_t producer_row{0};
    uint8_t producer_slot{0};

    friend bool operator==(
        const CanonicalSourceV15&,
        const CanonicalSourceV15&) = default;
};

struct DualCtlChallengesV15 {
    gf::Fp3 alpha1{};
    gf::Fp3 gamma1{};
    gf::Fp3 alpha2{};
    gf::Fp3 gamma2{};

};

/**
 * V14 occupies [0,575).  Every column before `dependent_begin` is committed
 * in R0.  Only denominator inverses and the two LogUp accumulators are in
 * Rdep, so neither CTL lane can influence its own Fiat--Shamir challenges.
 */
struct LayoutV15 {
    uint32_t v14_end{
        bridge::kTypedSafeDirectParentColumnsV14};
    uint32_t producer_base{v14_end};
    uint32_t producer_stride{43};
    uint32_t consumer_word_active_base{
        producer_base +
        kProducerSlotsV15 * producer_stride};
    uint32_t consumer_byte_base{
        consumer_word_active_base +
        kConsumerWordLanesV15};
    uint32_t consumer_bit_base{
        consumer_byte_base +
        kConsumerBytePortsV15};
    uint32_t consumer_active_base{
        consumer_bit_base +
        kConsumerWordLanesV15 * 32};
    uint32_t consumer_address_base{
        consumer_active_base +
        kConsumerBytePortsV15};
    uint32_t consumer_source_byte_base{
        consumer_address_base +
        kConsumerBytePortsV15};
    uint32_t descriptor_base{
        consumer_source_byte_base +
        kConsumerBytePortsV15};
    uint32_t dependent_begin{
        descriptor_base + kDescriptorLanesV15};
    uint32_t producer_inverse1_base{dependent_begin};
    uint32_t producer_inverse2_base{
        producer_inverse1_base +
        kProducerSlotsV15 * 4};
    uint32_t consumer_inverse1_base{
        producer_inverse2_base +
        kProducerSlotsV15 * 4};
    uint32_t consumer_inverse2_base{
        consumer_inverse1_base +
        kConsumerBytePortsV15};
    uint32_t running1{
        consumer_inverse2_base +
        kConsumerBytePortsV15};
    uint32_t running2{running1 + 1};
    uint32_t end{running2 + 1};

    [[nodiscard]] constexpr uint32_t ProducerActive(
        uint32_t slot) const
    {
        return producer_base + slot * producer_stride;
    }
    [[nodiscard]] constexpr uint32_t ProducerAddress(
        uint32_t slot) const
    {
        return ProducerActive(slot) + 1;
    }
    [[nodiscard]] constexpr uint32_t ProducerValue(
        uint32_t slot) const
    {
        return ProducerActive(slot) + 2;
    }
    [[nodiscard]] constexpr uint32_t ProducerMultiplicity(
        uint32_t slot, uint32_t byte) const
    {
        return ProducerActive(slot) + 3 + byte;
    }
    [[nodiscard]] constexpr uint32_t ProducerByte(
        uint32_t slot, uint32_t byte) const
    {
        return ProducerActive(slot) + 7 + byte;
    }
    [[nodiscard]] constexpr uint32_t ProducerBit(
        uint32_t slot, uint32_t bit) const
    {
        return ProducerActive(slot) + 11 + bit;
    }
    [[nodiscard]] constexpr uint32_t ConsumerByte(
        uint32_t port) const
    {
        return consumer_byte_base + port;
    }
    [[nodiscard]] constexpr uint32_t ConsumerBit(
        uint32_t lane, uint32_t bit) const
    {
        return consumer_bit_base + lane * 32 + bit;
    }
};

static_assert(LayoutV15{}.end == 1143);

struct ProductV15 {
    LayoutV15 layout{};
    bridge::NativeSplitRapMultiRowTypedSafeScheduleV2
        native_schedule;
    bridge::TypedSafeDirectParentProductV14 v14;
    std::vector<CanonicalSourceV15> sources;
    std::vector<CanonicalSourceConsumerRecordV15> records;
    alg_hash::Digest schedule_commitment{};
    DualCtlChallengesV15 challenges{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession retained_r0;
    uint32_t canonical_source_occurrences{0};
    uint32_t producer_terms{0};
    uint32_t consumer_terms{0};
    uint32_t violations{0};
    /** Host reconstructs from a caller-supplied, natively verified child. */
    bool external_child_proof_required{true};
    /** The canonical child proof tape is not yet an in-V15 AIR input. */
    bool child_proof_tape_in_v15{false};
    bool host_decoder_reconstructed_external_child{false};
    /** No independently caller-authored source-value vector is accepted. */
    bool no_free_source_vector{false};
    /** Decoder-selected source cells are public pins derived by the host. */
    bool canonical_source_values_preprocessed{true};
    bool exact_public_schedule{false};
    bool source_and_consumer_values_in_r0{false};
    bool dual_ctl_challenges_after_r0{false};
    bool dual_fp3_terminal_zero{false};
    bool canonical_source_subset_complete{false};
    bool prior_event_sources_complete{false};
    bool derived_hash_sources_complete{false};
    bool v14_outputs_to_verifier_consumers{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

struct ProofV15 {
    uint16_t version{kVersionV15};
    alg_hash::Digest schedule_commitment{};
    alg_hash::Digest v14_program_root{};
    alg_hash::Digest v14_transcript_commitment{};
    uint256 r0_commitment{};
    aq::AirQuotientSplitRapRowsProof proof{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t record_count{0};
    uint64_t serialized_proof_bytes{0};
    bool proof_level_verified{false};
    bool child_proof_tape_in_v15{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool BuildCanonicalSourceToV14V15(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const std::vector<uint32_t>& child_base_column_indices,
    const uint256& child_public_fs_seed,
    ProductV15& out,
    std::string* why = nullptr);

[[nodiscard]] bool ProveCanonicalSourceToV14V15(
    const ProductV15& product,
    const uint256& public_fs_seed,
    ProofV15& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyCanonicalSourceToV14V15(
    const ProductV15& expected_product,
    const ProofV15& proof,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

inline constexpr bool kCanonicalSourceJoinExecutableV15 = true;
inline constexpr bool kPriorEventJoinExecutableV15 = false;
inline constexpr bool kDerivedHashJoinExecutableV15 = false;
inline constexpr bool kVerifierConsumerJoinExecutableV15 = false;
inline constexpr bool kRecursiveAuthorityReadyV15 = false;

static_assert(!kRecursiveAuthorityReadyV15);

} // namespace matmul::v4::rc::stage3_safe_v15_superprogram

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V15_SUPERPROGRAM_H
