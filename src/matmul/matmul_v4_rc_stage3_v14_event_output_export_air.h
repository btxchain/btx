// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_EVENT_OUTPUT_EXPORT_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_EVENT_OUTPUT_EXPORT_AIR_H

#include <matmul/matmul_v4_rc_stage3_v13_occurrence_manifest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v14_event_output_export_air {

namespace aq = air_quotient;
namespace bridge = stage3_safe_v12_recursive_bridge;
namespace gf = gkr_field;
namespace occurrence = stage3_v13_occurrence_manifest;

inline constexpr uint16_t kEventOutputExportAirVersionV1 = 1;
inline constexpr uint32_t kCanonicalBitsV1 = 64;
inline constexpr uint32_t kHighAndChunkV1 = 5;
inline constexpr uint32_t kHighAndStepsV1 =
    (32 + kHighAndChunkV1 - 1) / kHighAndChunkV1;
inline constexpr uint32_t kNoEventV1 = UINT32_MAX;

enum class ExportUseV1 : uint8_t {
    PriorTranscriptBytes = 1,
    QuerySeedFeedback = 2,
    VerifierChallenge = 4,
};

enum class DelegatedOutputKindV1 : uint8_t {
    OodCandidateToFirstAcceptableAir = 1,
    QueryCandidateToIndexAir = 2,
    SelectedOodToFirstAcceptableAir = 3,
    DerivedShapeHashToHashAir = 4,
    DerivedOodHashToHashAir = 5,
};

struct ProducerLaneV1 {
    uint32_t event{0};
    uint8_t lane{0};
    uint8_t uses{0};
    uint32_t occurrence_consumers{0};

    friend bool operator==(
        const ProducerLaneV1&,
        const ProducerLaneV1&) = default;
};

struct DelegatedLaneV1 {
    DelegatedOutputKindV1 kind{
        DelegatedOutputKindV1::OodCandidateToFirstAcceptableAir};
    uint32_t event{kNoEventV1};
    uint8_t lane{0};
    occurrence::SelectorFamilyV1 selector_family{
        occurrence::SelectorFamilyV1::None};
    uint32_t occurrence_consumers{0};

    friend bool operator==(
        const DelegatedLaneV1&,
        const DelegatedLaneV1&) = default;
};

/**
 * One producer row per UNIQUE (event,lane). Consumer occurrences are counted
 * but never duplicated into witness rows.  OOD candidates/selected OOD
 * values, query-candidate lane0 values, and derived hash outputs are assigned
 * to their dedicated AIRs in `delegated`.
 */
struct InventoryV1 {
    std::vector<ProducerLaneV1> exported;
    std::vector<DelegatedLaneV1> delegated;
    uint32_t prior_byte_occurrences{0};
    uint32_t query_seed_field_occurrences{0};
    uint32_t unique_prior_byte_lanes{0};
    uint32_t unique_verifier_challenge_lanes{0};
    uint32_t duplicate_consumers_collapsed{0};
    uint32_t delegated_ood_candidate_lanes{0};
    uint32_t delegated_query_candidate_lanes{0};
    uint32_t delegated_selected_ood_lanes{0};
    uint32_t delegated_derived_hash_lanes{0};
    bool manifest_rebuilt{false};
    bool complete{false};
    std::string note;
};

struct LayoutV1 {
    uint32_t lane_value{0};
    uint32_t bit_base{1};
    uint32_t high_and_base{65};
    uint32_t low_word{72};
    uint32_t high_word{73};
    uint32_t event_key{74};
    uint32_t lane_key{75};
    uint32_t active{76};
    uint32_t expected_event{77};
    uint32_t expected_lane{78};
    uint32_t dependent_zero{79};

    [[nodiscard]] constexpr uint32_t Bit(uint32_t bit) const
    {
        return bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t HighAnd(uint32_t step) const
    {
        return high_and_base + step;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return dependent_zero + 1;
    }
};

struct CellRefV1 {
    uint32_t column{0};
    uint32_t row{0};

    friend bool operator==(
        const CellRefV1&,
        const CellRefV1&) = default;
};

struct ExportCellV1 {
    uint32_t event{0};
    uint8_t lane{0};
    CellRefV1 v14_output_lane{};
    CellRefV1 low_le32{};
    CellRefV1 high_le32{};
    CellRefV1 event_key{};
    CellRefV1 lane_key{};
};

struct CellMapV1 {
    std::vector<ExportCellV1> exports;

    [[nodiscard]] const ExportCellV1* Find(
        uint32_t event, uint8_t lane) const;
};

struct InputV1 {
    occurrence::ManifestV1 manifest;
    // Raw u64 representatives are deliberate: tests and callers can exhibit
    // x+p.  The AIR, not the host type, enforces canonical Goldilocks.
    std::vector<std::array<uint64_t, 4>> event_output;
};

struct ProductV1 {
    LayoutV1 layout{};
    InventoryV1 inventory;
    CellMapV1 cell_map;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t trace_rows{0};
    uint32_t active_rows{0};
    uint32_t violations{1};
    uint32_t max_alg_degree{0};
    bool input_cells_ordinary{false};
    bool word_cells_ordinary{false};
    bool canonical_goldilocks_constrained{false};
    bool le32_exports_constrained{false};
    bool event_lane_positions_constrained{false};
    bool v14_output_equalities_executed{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildInventoryV1(
    const occurrence::ManifestV1& manifest,
    InventoryV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildConstraintSystemV1(
    const InventoryV1& inventory,
    aq::AirConstraintSystem<gf::Fp3>& out,
    CellMapV1& cell_map,
    std::string* why = nullptr);

[[nodiscard]] ProductV1 BuildProductV1(const InputV1& input);

[[nodiscard]] uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_v14_event_output_export_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_EVENT_OUTPUT_EXPORT_AIR_H
