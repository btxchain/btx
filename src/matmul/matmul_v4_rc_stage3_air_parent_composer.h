// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIR_PARENT_COMPOSER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIR_PARENT_COMPOSER_H

#include <matmul/matmul_v4_rc_air_quotient.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_air_parent_composer {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Literal column interval allocated to one child relation inside a horizontal
 * parent.  Callers use this mapping to build same-parent CTLs against the
 * child's actual ordinary columns; no copied receipt values are introduced.
 */
struct ChildAttachmentV1 {
    uint16_t version{kVersionV1};
    uint32_t child_ordinal{0};
    uint32_t column_base{0};
    /** Original child witness columns addressable through ParentColumn. */
    uint32_t semantic_child_columns{0};
    /** Total columns appended, including verifier-owned lift selectors. */
    uint32_t column_count{0};
    uint32_t constraint_begin{0};
    uint32_t constraint_count{0};
    uint32_t preprocessed_count{0};
    bool literal_column_mapping{false};
    bool constraints_shifted{false};
    bool row_lifted{false};
    bool padding_zero_constrained{false};
    bool valid{false};

    [[nodiscard]] uint32_t ParentColumn(uint32_t child_column) const
    {
        return column_base + child_column;
    }
};

/**
 * Append a complete child AIR and witness to a horizontal parent.
 *
 * The child constraint callbacks are evaluated against a fixed slice of the
 * parent row, so every child column retains a literal, verifier-known parent
 * address. Canonical preprocessed values and per-column root pins are shifted
 * with the same mapping.
 *
 * Complete row-group roots cannot be preserved by concatenation: adding even
 * one column changes the committed row leaf. Such roots must be rebuilt once,
 * after all children and dependent CTLs have been appended. This function
 * therefore rejects a child or partially-built parent carrying an existing
 * row-group root instead of silently accepting a stale commitment.
 */
[[nodiscard]] bool AppendChildV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<std::vector<gf::Fp3>>& child_columns,
    uint32_t child_ordinal,
    ChildAttachmentV1& out,
    std::string* why = nullptr);

/**
 * Exact power-of-two row lift used by the canonical 14-role parent.
 *
 * A child over H_n is embedded in the first n rows of H_N. Five canonical
 * preprocessed selectors gate Everywhere/Transition/First/Last constraints
 * to precisely their original row sets and force every ordinary child column
 * to zero on rows [n,N). One ordinary wrap-broadcast column per child column
 * is constrained to the child's row-zero value; Everywhere and LastRow
 * relations at row n-1 consume this wrap bank as `next`, preserving the
 * original cyclic H_n semantics instead of reading padding row n. This is not
 * repetition or unconstrained padding. Selector multiplication raises each
 * original algebraic degree by one.
 *
 * Per-column and row-group root pins are rejected because changing the row
 * domain changes their commitment. The enclosing parent must install its one
 * final global R0 pin after every child and dependent relation is present.
 */
[[nodiscard]] bool AppendChildLiftedV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<std::vector<gf::Fp3>>& child_columns,
    uint32_t parent_rows,
    uint32_t child_ordinal,
    ChildAttachmentV1& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::stage3_air_parent_composer

#endif
