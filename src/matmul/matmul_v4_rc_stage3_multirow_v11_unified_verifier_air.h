// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_UNIFIED_VERIFIER_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_UNIFIED_VERIFIER_AIR_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_verifier.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace dj = stage3_multirow_v11_decoder_join;
namespace dvm = stage3_multirow_v11_deep_vm;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace pj = stage3_multirow_v11_parent_join;
namespace rv = stage3_multirow_v11_recursive_verifier;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kQ96QueriesV1 = 96;
inline constexpr uint32_t kTraceRowsCapV1 = 1U << 20;
inline constexpr uint32_t kLdeRowsCapV1 = 1U << 24;

enum class PhaseV1 : uint8_t {
    ParentJoin = 0,
    MerkleHash = 1,
    MerkleFold = 2,
    DeepVm = 3,
    Decoder = 4,
    Count = 5,
};

inline constexpr uint32_t kPhasesV1 =
    static_cast<uint32_t>(PhaseV1::Count);

struct PhaseShapeV1 {
    PhaseV1 phase{PhaseV1::ParentJoin};
    uint32_t first_row{0};
    uint32_t rows{0};
    uint32_t columns{0};
    uint32_t constraints{0};
    uint32_t preprocessed_columns{0};
    uint32_t max_degree{0};
};

struct LayoutV1 {
    uint32_t data_base{0};
    uint32_t data_columns{0};
    uint32_t phase_tag_base{0};
    uint32_t phase_first_base{0};
    uint32_t phase_last_base{0};
    uint32_t phase_transition_base{0};
    uint32_t active{0};
    uint32_t expected_preprocessed_base{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t PhaseTag(PhaseV1 phase) const
    {
        return phase_tag_base +
            static_cast<uint32_t>(phase);
    }
    [[nodiscard]] uint32_t PhaseFirst(PhaseV1 phase) const
    {
        return phase_first_base +
            static_cast<uint32_t>(phase);
    }
    [[nodiscard]] uint32_t PhaseLast(PhaseV1 phase) const
    {
        return phase_last_base +
            static_cast<uint32_t>(phase);
    }
    [[nodiscard]] uint32_t PhaseTransition(PhaseV1 phase) const
    {
        return phase_transition_base +
            static_cast<uint32_t>(phase);
    }
};

struct ProductV1 {
    uint16_t version{kVersionV1};
    rv::QueryRangeV1 range{};
    pj::ProductV1 parent_join{};
    mf::ShardProductV1 merkle_fold{};
    dvm::ProductV1 deep_vm{};
    dj::ProductV1 decoder{};
    LayoutV1 layout{};
    std::array<PhaseShapeV1, kPhasesV1> phases{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint32_t commitment_coefficients{0};
    uint64_t commitment_lde_rows{0};
    uint32_t expected_preprocessed_columns{0};
    uint64_t materialized_trace_cells{0};
    uint64_t violations{0};
    bool exact_q96_range{false};
    bool all_five_phases_executable{false};
    bool vertical_max_width_layout{false};
    bool one_hot_row_scheduler_constrained{false};
    bool local_boundary_kinds_preserved{false};
    bool every_phase_preprocessed_pin_r0_bound{false};
    bool trace_cap_fits{false};
    bool lde_cap_fits{false};
    /** False: phase R0 columns currently contain child-proof values. */
    bool cs_independent_of_child_witness{false};
    /** False: VerifyV1 currently receives and rebuilds from the child proof. */
    bool verifier_input_excludes_child_proof{false};
    bool quotient_cap_audit_complete{false};
    /** Open until proof-owned decoder/DEEP occurrences share a CTL bus. */
    bool direct_cross_phase_cell_carries_complete{false};
    bool recursive_authority_ready{false};
    bool valid_foundation{false};
    std::string note;
};

/**
 * Vertically concatenate parent-join, Merkle hash, fold, DEEP/VM and decoder
 * into one Split-RAP relation. Phase-private columns reuse max(width);
 * verifier-owned phase pins are separate R0 columns constrained equal under
 * immutable one-hot row tags.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range = {
        0, 0, kQ96QueriesV1});

[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

struct ProveResultV1 {
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 preprocessed_row_group_root{};
    uint64_t proof_wire_bytes{0};
    uint64_t prove_micros{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProveResultV1 ProveV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const uint256& public_fs_seed);

struct VerifyResultV1 {
    uint64_t verify_micros{0};
    bool accepted{false};
    bool direct_cross_phase_cell_carries_complete{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] VerifyResultV1 VerifyV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

} // namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air

#endif
