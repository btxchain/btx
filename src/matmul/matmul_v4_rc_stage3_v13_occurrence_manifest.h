// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_OCCURRENCE_MANIFEST_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_OCCURRENCE_MANIFEST_H

#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_recursive_bridge.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_occurrence_manifest {

namespace abi = stage3_multirow_v11_proof_abi;
namespace bridge = stage3_safe_v12_recursive_bridge;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kOccurrenceManifestVersionV1 = 1;
inline constexpr uint32_t kNoEventV1 = UINT32_MAX;
inline constexpr uint32_t kOuterEventCountV1 = 2;

enum class ByteSourceKindV1 : uint8_t {
    ProtocolConstant = 1,
    CanonicalAbi = 2,
    PriorEventOutput = 3,
    DerivedShapeCommit = 4,
    DerivedOodEvalCommit = 5,
};

enum class SelectorFamilyV1 : uint8_t {
    None = 0,
    OodZ1FirstAcceptable = 1,
    OodZ2FirstAcceptableDistinctFromZ1 = 2,
};

/**
 * One byte in one proof-owned LE32 cell of the typed SAFE V14 program.
 *
 * A source can have two simultaneous identities.  In particular, each child
 * PublicFsSeed byte has a canonical proof-tape ABI address and must also be
 * copied from the outer FriSeed event output.  Keeping both identities is
 * load-bearing: treating either side as a free witness recreates the
 * transcript-transplant attack.
 *
 * OOD source selection is intentionally represented as a candidate set.
 * Which K=2 candidate is first acceptable depends on constrained event
 * outputs and therefore is not verifier-owned public metadata.
 */
struct ByteOccurrenceV1 {
    ByteSourceKindV1 source_kind{
        ByteSourceKindV1::ProtocolConstant};
    abi::SourceKeyV1 abi_key{};
    uint32_t abi_source_address{UINT32_MAX};
    uint8_t byte_in_abi_word{0};
    bool canonical_abi_source{false};

    uint32_t source_event_begin{kNoEventV1};
    uint32_t source_event_end{kNoEventV1};
    uint8_t source_output_lane{0};
    uint8_t byte_in_output_lane{0};
    SelectorFamilyV1 selector_family{SelectorFamilyV1::None};
    bool prior_event_output_source{false};
    bool outer_fri_seed_feedback_source{false};

    uint32_t derived_output_lane{0};
    uint8_t byte_in_derived_lane{0};
    bool derived_hash_source{false};

    uint32_t consumer_event{0};
    uint32_t consumer_message_ordinal{0};
    uint8_t byte_in_message_word{0};
    uint32_t consumer_row{0};
    uint32_t consumer_column{0};

    friend bool operator==(
        const ByteOccurrenceV1&,
        const ByteOccurrenceV1&) = default;
};

/** Field-lane aliases which are not byte-packed transcript cells. */
struct FieldOccurrenceV1 {
    uint32_t source_event{0};
    uint8_t source_output_lane{0};
    uint32_t consumer_event{0};
    uint32_t consumer_message_ordinal{0};
    uint32_t consumer_row{0};
    uint32_t consumer_column{0};

    friend bool operator==(
        const FieldOccurrenceV1&,
        const FieldOccurrenceV1&) = default;
};

struct FirstAcceptableSelectorV1 {
    SelectorFamilyV1 family{SelectorFamilyV1::None};
    std::array<uint32_t, 2> candidate_events{};
    bool candidate_set_public{false};
    bool selected_ordinal_is_witness_dependent{true};
    bool first_acceptable_air_required{true};

    friend bool operator==(
        const FirstAcceptableSelectorV1&,
        const FirstAcceptableSelectorV1&) = default;
};

enum class DerivedHashKindV1 : uint8_t {
    ShapeCommit = 1,
    OodEvaluationCommit = 2,
};

struct DerivedHashV1 {
    DerivedHashKindV1 kind{DerivedHashKindV1::ShapeCommit};
    std::vector<abi::SourceKeyV1> direct_input_keys;
    std::vector<SelectorFamilyV1> selected_event_inputs;
    uint32_t output_bytes{32};
    bool input_inventory_shape_derived{false};
    bool hash_air_required{true};

    friend bool operator==(
        const DerivedHashV1&,
        const DerivedHashV1&) = default;
};

struct ManifestV1 {
    tape::PublicShapeV1 shape{};
    std::vector<bridge::TypedSafeEventProgramV13>
        canonical_program;
    alg_hash::Digest program_root{};
    std::vector<ByteOccurrenceV1> byte_occurrences;
    std::vector<FieldOccurrenceV1> field_occurrences;
    std::array<FirstAcceptableSelectorV1, 2> selectors{};
    std::array<DerivedHashV1, 2> derived_hashes{};
    uint32_t canonical_abi_byte_occurrences{0};
    uint32_t prior_event_output_byte_occurrences{0};
    uint32_t derived_hash_byte_occurrences{0};
    uint32_t protocol_constant_byte_occurrences{0};
    uint32_t outer_fri_seed_feedback_byte_occurrences{0};
    uint32_t query_seed_feedback_field_occurrences{0};
    bool proof_tape_schedule_regenerated{false};
    bool canonical_program_rebuilt_from_shape{false};
    bool public_program_exact_match{false};
    bool every_abi_address_resolved{false};
    bool every_consumer_destination_resolved{false};
    bool no_native_verify_or_replay{true};
    bool selected_ood_ordinal_public{false};
    bool selector_air_executed{false};
    bool derived_hash_air_executed{false};
    bool consumer_equalities_executed{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/** Shape-only reconstruction of the committed typed V14 program. */
[[nodiscard]] bool BuildCanonicalTypedProgramV1(
    const tape::PublicShapeV1& shape,
    std::vector<bridge::TypedSafeEventProgramV13>& out,
    std::string* why = nullptr);

/**
 * Rebuild the exact outer-V2 + child-V13 typed program and every child
 * transcript source occurrence from verifier-owned public shape.  The
 * supplied V14 program is accepted only if it is byte-for-byte equal to that
 * reconstruction.
 *
 * This is deliberately a manifest, not an acceptance oracle.  It never calls
 * native Verify/VerifyReplay and accepts neither a proof nor a host
 * `verified` boolean.
 */
[[nodiscard]] bool BuildCanonicalOccurrenceManifestV1(
    const tape::PublicShapeV1& shape,
    const std::vector<bridge::TypedSafeEventProgramV13>&
        public_v14_program,
    ManifestV1& out,
    std::string* why = nullptr);

/** Rebuild-and-compare validation; rejects any claimed source transplant. */
[[nodiscard]] bool ValidateCanonicalOccurrenceManifestV1(
    const tape::PublicShapeV1& shape,
    const std::vector<bridge::TypedSafeEventProgramV13>&
        public_v14_program,
    const ManifestV1& claimed,
    std::string* why = nullptr);

inline constexpr bool kOccurrenceManifestExecutableV1 = true;
inline constexpr bool kOccurrenceConsumerEqualitiesExecutedV1 = false;
inline constexpr bool kOccurrenceManifestRecursiveAuthorityReadyV1 = false;

static_assert(!kOccurrenceConsumerEqualitiesExecutedV1);
static_assert(!kOccurrenceManifestRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_occurrence_manifest

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_OCCURRENCE_MANIFEST_H
