// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_PROTOCOL_PREFIX_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_PROTOCOL_PREFIX_JOIN_H

#include <matmul/matmul_v4_rc_stage3_v14_transcript_provenance_join.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v14_protocol_prefix_join {

namespace aq = air_quotient;
namespace bridge = stage3_safe_v12_recursive_bridge;
namespace derived = stage3_v13_derived_hash_air;
namespace gf = gkr_field;
namespace occurrence = stage3_v13_occurrence_manifest;
namespace provenance = stage3_v14_transcript_provenance_join;

inline constexpr uint16_t kProtocolPrefixJoinVersionV1 = 1;
inline constexpr char kProtocolPrefixV1[] =
    "BTX_RC_FRI3ALG_MULTI_ROW_RAP_SAFE_Q192_K2_V13";
inline constexpr uint32_t kProtocolPrefixBytesV1 =
    sizeof(kProtocolPrefixV1) - 1;
inline constexpr uint32_t kMessageLanesV1 =
    provenance::kConsumerLanesV1;
inline constexpr uint32_t kBytesPerMessageWordV1 = 4;
inline constexpr uint32_t kBitsPerMessageWordV1 = 32;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    friend bool operator==(const CellRefV1&, const CellRefV1&) = default;
};

/**
 * One verifier-rebuilt constant byte and its exact proof-owned V14 consumer.
 *
 * The prefix has 45 bytes, so its last byte shares a u32 cell with three ABI
 * bytes.  Recording byte positions, rather than pinning complete words, is
 * load-bearing.
 */
struct PrefixOccurrenceV1 {
    uint32_t event{0};
    uint32_t prefix_offset{0};
    uint32_t message_ordinal{0};
    uint8_t byte_in_message_word{0};
    uint8_t expected_byte{0};
    CellRefV1 message{};

    friend bool operator==(
        const PrefixOccurrenceV1&,
        const PrefixOccurrenceV1&) = default;
};

struct PlanV1 {
    uint16_t version{kProtocolPrefixJoinVersionV1};
    uint256 provenance_plan_root{};
    uint32_t trace_rows{0};
    uint32_t provenance_columns{0};
    uint32_t consumer_bit_base{0};
    uint32_t message_active_base{0};
    uint32_t byte_active_base{0};
    uint32_t expected_byte_base{0};
    uint32_t dependent_zero{0};
    uint32_t total_columns{0};
    std::vector<PrefixOccurrenceV1> occurrences;
    uint32_t transcript_events{0};
    uint32_t protocol_constant_occurrences{0};
    uint256 plan_root{};
    bool exact_manifest_rebuilt{false};
    bool exact_byte_positions{false};
    bool exact_multiplicity{false};
    bool mixed_constant_abi_word_covered{false};
    bool valid{false};
    std::string note;

    [[nodiscard]] uint32_t ConsumerBit(
        uint32_t lane, uint32_t bit) const
    {
        return consumer_bit_base +
            lane * kBitsPerMessageWordV1 + bit;
    }

    [[nodiscard]] uint32_t MessageActive(
        uint32_t lane) const
    {
        return message_active_base + lane;
    }

    [[nodiscard]] uint32_t ByteActive(
        uint32_t lane, uint32_t byte) const
    {
        return byte_active_base +
            lane * kBytesPerMessageWordV1 + byte;
    }

    [[nodiscard]] uint32_t ExpectedByte(
        uint32_t lane, uint32_t byte) const
    {
        return expected_byte_base +
            lane * kBytesPerMessageWordV1 + byte;
    }
};

/**
 * Rebuild every fixed-prefix byte occurrence from the canonical manifest.
 * No witness value or prover-supplied selector enters this plan.
 */
[[nodiscard]] bool BuildCanonicalPlanV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    PlanV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildConstraintSystemV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    aq::AirConstraintSystem<gf::Fp3>& out,
    PlanV1* plan = nullptr,
    std::string* why = nullptr);

struct ProductV1 {
    PlanV1 plan{};
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    derived::BindingV1 derived_binding{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint64_t violations{0};
    bool provenance_relation_resident{false};
    bool verifier_rebuilt_prefix_preprocessed{false};
    bool consumer_u32_decomposition_constrained{false};
    bool every_prefix_occurrence_bound{false};
    bool exact_multiplicity_consumed{false};
    bool canonical_abi_relation_resident{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const occurrence::ManifestV1& manifest,
    const provenance::ProductV1& provenance_product);

struct ProofV1 {
    uint16_t version{kProtocolPrefixJoinVersionV1};
    uint256 plan_root{};
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    derived::BindingV1 derived_binding{};
    aq::AirQuotientRowsProof proof{};
    bool canonical_abi_relation_resident{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    const uint256& fs_seed,
    ProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kProtocolPrefixJoinExecutableV1 = true;
inline constexpr bool kCanonicalAbiOwnedHereV1 = false;
inline constexpr bool kProtocolPrefixRecursiveAuthorityReadyV1 = false;

static_assert(kProtocolPrefixBytesV1 == 45);
static_assert(kProtocolPrefixBytesV1 % 4 == 1);
static_assert(!kCanonicalAbiOwnedHereV1);
static_assert(!kProtocolPrefixRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v14_protocol_prefix_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_PROTOCOL_PREFIX_JOIN_H
