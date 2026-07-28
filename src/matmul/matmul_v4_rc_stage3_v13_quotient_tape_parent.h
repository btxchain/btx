// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_QUOTIENT_TAPE_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_QUOTIENT_TAPE_PARENT_H

#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_quotient_tape_parent {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace composer = stage3_air_parent_composer;
namespace dvm = stage3_multirow_v11_deep_vm;
namespace gf = gkr_field;
namespace tape = stage3_multirow_v13_proof_tape_air;
namespace unified = stage3_multirow_v11_unified_verifier_air;
namespace rv = stage3_multirow_v11_recursive_verifier;

inline constexpr uint16_t kVersionV1 = 1;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(const CellRefV1&) const = default;
};

struct QuotientLimbAliasV1 {
    uint32_t query{UINT32_MAX};
    uint32_t source_address{UINT32_MAX};
    uint8_t limb{0};
    CellRefV1 tape_value{};
    CellRefV1 quotient_limb{};
};

/**
 * One physical parent containing the complete V13 proof-tape AIR and the
 * canonical, proof-value-free Deep/VM constraint system.  Every quotient
 * identity row contributes six aliases:
 *
 *   V13 Source(QueryRowValue(q, quotient-group, 0), coord, limb)
 *       == DeepVM.quotient_tape_limb[2*coord+limb]
 *
 * Values on both sides are ordinary committed columns.  Only immutable row
 * selectors introduced for cross-row transport are preprocessed.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    rv::QueryRangeV1 range{};
    unified::DeepVmPublicPlanV1 deep_plan{};
    unified::DeepVmCanonicalPhaseV1 deep_phase{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    composer::ChildAttachmentV1 tape_attachment{};
    composer::ChildAttachmentV1 deep_attachment{};
    std::vector<QuotientLimbAliasV1> aliases;
    uint32_t quotient_rows{0};
    uint32_t aliases_appended{0};
    uint32_t selector_columns{0};
    uint32_t carrier_columns{0};
    uint64_t violations{UINT64_MAX};
    bool canonical_deep_plan_rebuilt{false};
    bool complete_quotient_limb_inventory{false};
    bool source_addresses_fixed_by_v13_tape{false};
    bool tape_cells_ordinary{false};
    bool quotient_cells_ordinary{false};
    bool selectors_only_preprocessed{false};
    bool cross_row_transport_constrained{false};
    bool global_r0_pending{true};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Shared physical equality primitive.  Both endpoints must be ordinary
 * committed cells.  Cross-row equality is implemented by an ordinary
 * constant carrier and two immutable row selectors.
 *
 * Exposed so a bounded proof-level canary can exercise the exact primitive
 * used by the full V13/DeepVM product without proving the entire Q192 tape.
 */
[[nodiscard]] bool AppendOrdinaryCellAliasV1(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    const CellRefV1& source,
    const CellRefV1& sink,
    ProductV1& accounting,
    std::string* why = nullptr);

[[nodiscard]] bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const dvm::ProductV1& deep_product,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range,
    ProductV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kRecursiveConsumptionV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_quotient_tape_parent

#endif
