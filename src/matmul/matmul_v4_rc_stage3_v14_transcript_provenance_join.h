// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_TRANSCRIPT_PROVENANCE_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_TRANSCRIPT_PROVENANCE_JOIN_H

#include <matmul/matmul_v4_rc_stage3_v13_derived_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_v14_event_output_export_air.h>
#include <matmul/matmul_v4_rc_stage3_v14_selection_fused_join.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v14_transcript_provenance_join {

namespace aq = air_quotient;
namespace abi = stage3_multirow_v11_proof_abi;
namespace bridge = stage3_safe_v12_recursive_bridge;
namespace derived = stage3_v13_derived_hash_air;
namespace event_export = stage3_v14_event_output_export_air;
namespace fused = stage3_v14_selection_fused_join;
namespace gf = gkr_field;
namespace occurrence = stage3_v13_occurrence_manifest;
namespace selection = stage3_v13_selection_query_air;

inline constexpr uint16_t kTranscriptProvenanceJoinVersionV1 = 1;
inline constexpr uint32_t kConsumerLanesV1 =
    bridge::kTypedSafeEventRateV13;
inline constexpr uint32_t kConsumerBitsPerLaneV1 = 32;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    friend bool operator==(const CellRefV1&, const CellRefV1&) = default;
};

enum class FieldEdgeKindV1 : uint8_t {
    V14OutputToExport = 1,
    SelectionToDerivedSelectedPoint = 2,
};

struct FieldEdgeV1 {
    FieldEdgeKindV1 kind{FieldEdgeKindV1::V14OutputToExport};
    uint32_t item{0};
    uint32_t coordinate{0};
    CellRefV1 source{};
    CellRefV1 destination{};
    uint32_t carry_column{UINT32_MAX};
    uint32_t source_selector_column{UINT32_MAX};
    uint32_t destination_selector_column{UINT32_MAX};

    friend bool operator==(const FieldEdgeV1&, const FieldEdgeV1&) = default;
};

enum class ByteSourceKindV1 : uint8_t {
    PriorEventOutput = 1,
    SelectedOod = 2,
    DerivedShapeCommit = 3,
    DerivedOodEvaluationCommit = 4,
};

struct ByteSourceV1 {
    ByteSourceKindV1 kind{ByteSourceKindV1::PriorEventOutput};
    uint32_t event_or_family{0};
    uint8_t lane{0};
    uint8_t byte{0};
    /** Either one already-constrained byte cell or eight bit cells. */
    bool direct_byte{false};
    CellRefV1 byte_cell{};
    std::array<CellRefV1, 8> bit_cell{};
    uint32_t multiplicity{0};
    uint32_t carry_column{UINT32_MAX};
    uint32_t source_selector_column{UINT32_MAX};

    friend bool operator==(const ByteSourceV1&, const ByteSourceV1&) = default;
};

struct ByteConsumerV1 {
    uint32_t source{UINT32_MAX};
    uint32_t event{0};
    uint32_t message_ordinal{0};
    uint8_t byte_in_message_word{0};
    CellRefV1 message{};
    uint32_t selector_column{UINT32_MAX};

    friend bool operator==(const ByteConsumerV1&, const ByteConsumerV1&) = default;
};

struct PlanV1 {
    uint16_t version{kTranscriptProvenanceJoinVersionV1};
    uint32_t trace_rows{0};
    uint32_t fused_offset{0};
    uint32_t derived_offset{0};
    uint32_t export_offset{0};
    uint32_t fused_columns{0};
    uint32_t derived_columns{0};
    uint32_t export_columns{0};
    uint32_t consumer_bit_base{0};
    uint32_t consumer_mask_base{0};
    uint32_t component_selector_base{0};
    uint32_t dependent_zero{0};
    uint32_t total_columns{0};
    std::vector<FieldEdgeV1> field_edges;
    std::vector<ByteSourceV1> byte_sources;
    std::vector<ByteConsumerV1> byte_consumers;
    uint32_t prior_occurrences{0};
    uint32_t derived_occurrences{0};
    uint32_t selected_occurrences{0};
    uint32_t exported_event_lanes{0};
    uint32_t selected_field_edges{0};
    uint256 plan_root{};
    bool exact_manifest_rebuilt{false};
    bool exact_occurrence_multiplicities{false};
    bool every_source_resolved{false};
    bool every_consumer_resolved{false};
    bool valid{false};
    std::string note;
};

/**
 * Rebuild the complete non-ABI transcript-provenance subrelation from public
 * shape/program/bindings.  CanonicalAbi and ProtocolConstant occurrences are
 * deliberately outside this relation: the former belong to the ABI LogUp,
 * while the latter require their own fixed-prefix relation.
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
    bool actual_v14_outputs_bound{false};
    bool selected_points_bound_to_derived{false};
    bool consumer_u32_decomposition_constrained{false};
    bool prior_output_occurrences_bound{false};
    bool derived_hash_occurrences_bound{false};
    bool exact_multiplicities_consumed{false};
    bool canonical_abi_occurrences_bound{false};
    bool protocol_constant_occurrences_bound{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const occurrence::ManifestV1& manifest,
    const fused::ProductV1& v14_selection,
    const derived::ProductV1& derived_hash,
    const event_export::ProductV1& outputs);

struct ProofV1 {
    uint16_t version{kTranscriptProvenanceJoinVersionV1};
    uint256 plan_root{};
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    derived::BindingV1 derived_binding{};
    aq::AirQuotientRowsProof proof{};
    bool canonical_abi_occurrences_bound{false};
    bool protocol_constant_occurrences_bound{false};
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

inline constexpr bool kTranscriptProvenanceJoinExecutableV1 = true;
inline constexpr bool kCanonicalAbiOccurrencesOwnedHereV1 = false;
inline constexpr bool kProtocolConstantsOwnedHereV1 = false;
inline constexpr bool kTranscriptProvenanceRecursiveAuthorityReadyV1 = false;

static_assert(!kCanonicalAbiOccurrencesOwnedHereV1);
static_assert(!kProtocolConstantsOwnedHereV1);
static_assert(!kTranscriptProvenanceRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v14_transcript_provenance_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_TRANSCRIPT_PROVENANCE_JOIN_H
