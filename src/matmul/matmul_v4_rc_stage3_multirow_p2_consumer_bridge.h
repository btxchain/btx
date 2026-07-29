// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_P2_CONSUMER_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_P2_CONSUMER_BRIDGE_H

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_p2_consumer_bridge {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace tp = stage3_multirow_p2_transcript;

inline constexpr uint16_t kConsumerBridgeVersionV1 = 1;
inline constexpr uint32_t kRawBitsV1 = 64;
inline constexpr uint32_t kHighAndV1 = 32;
inline constexpr uint32_t kMaxDomainLogV1 = 24;

struct LayoutV1 {
    uint32_t source_coord_base{0};
    uint32_t consumer_value{0};
    uint32_t consumer_index{0};
    uint32_t schedule_index{0};
    uint32_t active{0};
    uint32_t ood_active{0};
    uint32_t query_active{0};
    uint32_t coefficient_active{0};
    uint32_t candidate_first{0};
    uint32_t ood_z1_active{0};
    uint32_t ood_z2_active{0};
    uint32_t distinct_required{0};
    uint32_t candidate_valid{0};
    uint32_t candidate_prior_valid{0};
    uint32_t candidate_selected{0};
    uint32_t selected_z1{0};
    uint32_t selected_z2{0};
    uint32_t pow_base{0};
    uint32_t c1_nonzero{0};
    uint32_t c1_inverse{0};
    uint32_t c2_nonzero{0};
    uint32_t c2_inverse{0};
    uint32_t ext_nonzero{0};
    uint32_t domain_nonzero{0};
    uint32_t domain_inverse{0};
    uint32_t distinct_nonzero{0};
    uint32_t distinct_inverse{0};
    uint32_t ood_base_valid{0};
    uint32_t distinct_gate{0};
    uint32_t ood_valid{0};
    uint32_t raw_bit_base{0};
    uint32_t high_and_base{0};
    uint32_t raw_low{0};
    uint32_t raw_low_nonzero{0};
    uint32_t raw_low_inverse{0};
    uint32_t raw_nonminusone{0};
    uint32_t raw_nonminusone_inverse{0};
    uint32_t candidate_index{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t SourceCoord(uint32_t coordinate) const
    {
        return source_coord_base + coordinate;
    }
    [[nodiscard]] uint32_t Pow(uint32_t step) const
    {
        return pow_base + step;
    }
    [[nodiscard]] uint32_t RawBit(uint32_t bit) const
    {
        return raw_bit_base + bit;
    }
    [[nodiscard]] uint32_t HighAnd(uint32_t bit) const
    {
        return high_and_base + bit;
    }
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct CanonicalRawAuditV1 {
    uint64_t field_value{0};
    uint64_t bits_source{0};
    uint32_t violations{0};
    bool valid{false};
};

/** Regression for the Goldilocks x versus x+p decomposition alias. */
[[nodiscard]] CanonicalRawAuditV1 AuditCanonicalRawV1(
    gf::Fp field_value, uint64_t bits_source);

struct ProductV1 {
    LayoutV1 layout{};
    tp::ReceiptV1 transcript_receipt{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t real_rows{0};
    uint32_t trace_rows{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint64_t violations{0};
    uint32_t duplicate_query_count{0};
    bool transcript_receipt_verified{false};
    bool transcript_event_cells_schedule_bound{false};
    bool k2_ood_first_valid_air_constrained{false};
    bool q192_first_valid_air_constrained{false};
    bool q192_index_decomposition_canonical{false};
    bool q192_selected_index_consumer_equal{false};
    bool duplicate_queries_permitted{false};
    bool independent_coefficient_consumer_equal{false};
    bool coefficient_labels_bound{false};
    bool proof_owned_consumer_cells{false};
    bool same_parent_event_cell_aliases{false};
    bool backend_v11_codec_executable{false};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Build the proof-owned consumer trace from an already-valid transcript
 * product. Source event cells are exact root-pinned copies in this companion;
 * a same-parent alias into the V11 backend remains an explicit residual.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const tp::ProductV1& transcript);

[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_multirow_p2_consumer_bridge

#endif
