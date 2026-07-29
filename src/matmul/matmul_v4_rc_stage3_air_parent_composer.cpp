// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_air_parent_composer {
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:air_parent_composer_v1:" + detail;
    }
    return false;
}

bool ValidColumns(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (cs.n_rows < 2 || (cs.n_rows & (cs.n_rows - 1)) != 0 ||
        columns.size() != cs.n_columns) {
        return false;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return false;
    }
    return true;
}

} // namespace

bool AppendChildV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<std::vector<gf::Fp3>>& child_columns,
    uint32_t child_ordinal,
    ChildAttachmentV1& out,
    std::string* why)
{
    out = {};
    out.child_ordinal = child_ordinal;
    if (!ValidColumns(child_cs, child_columns)) {
        return Fail(why, "child_shape");
    }
    if (!parent_cs.preprocessed_row_group_roots.empty() ||
        !child_cs.preprocessed_row_group_roots.empty()) {
        return Fail(why, "row_group_root_requires_global_rebuild");
    }
    if (parent_cs.n_columns != parent_columns.size()) {
        return Fail(why, "parent_column_count");
    }
    if (parent_cs.n_columns == 0) {
        if (parent_cs.n_rows != 0 || !parent_columns.empty() ||
            !parent_cs.constraints.empty() ||
            !parent_cs.preprocessed.empty() ||
            !parent_cs.preprocessed_roots.empty()) {
            return Fail(why, "noncanonical_empty_parent");
        }
        parent_cs.n_rows = child_cs.n_rows;
    } else if (!ValidColumns(parent_cs, parent_columns)) {
        return Fail(why, "parent_shape");
    } else if (parent_cs.n_rows != child_cs.n_rows) {
        return Fail(why, "row_count_mismatch");
    }
    if (child_cs.n_columns >
        std::numeric_limits<uint32_t>::max() - parent_cs.n_columns) {
        return Fail(why, "column_count_overflow");
    }
    for (const auto& [column, values] : child_cs.preprocessed) {
        if (column >= child_cs.n_columns ||
            values.size() != child_cs.n_rows) {
            return Fail(why, "child_preprocessed_shape");
        }
    }
    for (const auto& [column, root] : child_cs.preprocessed_roots) {
        if (column >= child_cs.n_columns || root.IsNull()) {
            return Fail(why, "child_preprocessed_root");
        }
    }
    for (const auto& constraint : child_cs.constraints) {
        if (!constraint.eval || constraint.alg_degree == 0) {
            return Fail(why, "child_constraint");
        }
    }

    out.column_base = parent_cs.n_columns;
    out.semantic_child_columns = child_cs.n_columns;
    out.column_count = child_cs.n_columns;
    out.constraint_begin =
        static_cast<uint32_t>(parent_cs.constraints.size());
    out.constraint_count =
        static_cast<uint32_t>(child_cs.constraints.size());
    out.preprocessed_count =
        static_cast<uint32_t>(child_cs.preprocessed.size());

    parent_columns.insert(
        parent_columns.end(), child_columns.begin(), child_columns.end());
    parent_cs.n_columns += child_cs.n_columns;
    parent_cs.preprocessed_pin_ood =
        parent_cs.preprocessed_pin_ood || child_cs.preprocessed_pin_ood;

    constraint_bytecode::CanonicalRelocationReportV1
        relocation;
    if (!constraint_bytecode::
            AppendRelocatedAirConstraintsV1(
                child_cs, out.column_base,
                parent_cs, relocation, why)) {
        return Fail(
            why, "child_constraint_relocation");
    }
    out.canonical_constraints_relocated =
        relocation
            .canonical_constraints_relocated;
    out.native_constraints_shifted =
        relocation.native_constraints_shifted;
    out.canonical_tables_recommitted =
        relocation
            .canonical_tables_recommitted;
    out.canonical_program_relocation_exact =
        relocation
            .every_claimed_provenance_valid &&
        relocation.exact_order_preserved;
    for (const auto& [column, values] : child_cs.preprocessed) {
        parent_cs.preprocessed.emplace_back(
            out.column_base + column, values);
    }
    for (const auto& [column, root] : child_cs.preprocessed_roots) {
        parent_cs.preprocessed_roots.emplace_back(
            out.column_base + column, root);
    }

    out.literal_column_mapping = true;
    out.constraints_shifted = true;
    out.valid = true;
    return true;
}

bool AppendChildLiftedV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<std::vector<gf::Fp3>>& child_columns,
    uint32_t parent_rows,
    uint32_t child_ordinal,
    ChildAttachmentV1& out,
    std::string* why)
{
    if (!ValidColumns(child_cs, child_columns)) {
        return Fail(why, "lift_child_shape");
    }
    if (parent_rows < child_cs.n_rows ||
        (parent_rows & (parent_rows - 1)) != 0 ||
        (parent_rows % child_cs.n_rows) != 0) {
        return Fail(why, "lift_row_domain");
    }
    if (!child_cs.preprocessed_roots.empty() ||
        !child_cs.preprocessed_row_group_roots.empty()) {
        return Fail(why, "lift_commitment_requires_global_rebuild");
    }
    if (child_cs.n_columns >
        (std::numeric_limits<uint32_t>::max() - 5U) / 2U) {
        return Fail(why, "lift_column_count_overflow");
    }
    for (const auto& constraint : child_cs.constraints) {
        if (!constraint.eval || constraint.alg_degree == 0 ||
            constraint.alg_degree ==
                std::numeric_limits<uint32_t>::max()) {
            return Fail(why, "lift_child_constraint");
        }
    }

    constexpr uint32_t kActive = 0;
    constexpr uint32_t kTransition = 1;
    constexpr uint32_t kFirst = 2;
    constexpr uint32_t kLast = 3;
    constexpr uint32_t kPadding = 4;
    constexpr uint32_t kSelectors = 5;

    aq::AirConstraintSystem<gf::Fp3> lifted;
    lifted.n_rows = parent_rows;
    const uint32_t wrap_base = child_cs.n_columns;
    const uint32_t selector_base =
        child_cs.n_columns * 2U;
    lifted.n_columns = selector_base + kSelectors;
    lifted.preprocessed_pin_ood = child_cs.preprocessed_pin_ood;
    std::vector<std::vector<gf::Fp3>> lifted_columns(
        lifted.n_columns,
        std::vector<gf::Fp3>(parent_rows, gf::Fp3::Zero()));
    for (uint32_t column = 0;
         column < child_cs.n_columns; ++column) {
        std::copy(
            child_columns[column].begin(),
            child_columns[column].end(),
            lifted_columns[column].begin());
        std::fill(
            lifted_columns[wrap_base + column].begin(),
            lifted_columns[wrap_base + column].end(),
            child_columns[column][0]);
    }
    for (uint32_t row = 0; row < parent_rows; ++row) {
        if (row < child_cs.n_rows) {
            lifted_columns[selector_base + kActive][row] =
                gf::Fp3::One();
        } else {
            lifted_columns[selector_base + kPadding][row] =
                gf::Fp3::One();
        }
        if (row + 1 < child_cs.n_rows) {
            lifted_columns[selector_base + kTransition][row] =
                gf::Fp3::One();
        }
    }
    lifted_columns[selector_base + kFirst][0] =
        gf::Fp3::One();
    lifted_columns[selector_base + kLast][child_cs.n_rows - 1] =
        gf::Fp3::One();

    for (const auto& [column, values] : child_cs.preprocessed) {
        if (column >= child_cs.n_columns ||
            values.size() != child_cs.n_rows) {
            return Fail(why, "lift_preprocessed_shape");
        }
        std::vector<gf::Fp3> padded(
            parent_rows, gf::Fp3::Zero());
        std::copy(values.begin(), values.end(), padded.begin());
        lifted.preprocessed.emplace_back(
            column, std::move(padded));
    }
    for (uint32_t selector = 0;
         selector < kSelectors; ++selector) {
        lifted.preprocessed.emplace_back(
            selector_base + selector,
            lifted_columns[selector_base + selector]);
    }

    for (uint32_t column = 0;
         column < child_cs.n_columns; ++column) {
        aq::AirConstraint<gf::Fp3> first;
        first.name = "lift.wrap.first";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        first.eval =
            [column, wrap_base](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[wrap_base + column],
                    current[column]);
            };
        lifted.constraints.push_back(std::move(first));

        aq::AirConstraint<gf::Fp3> constant;
        constant.name = "lift.wrap.constant";
        constant.kind = aq::AirKind::kTransition;
        constant.alg_degree = 1;
        constant.eval =
            [column, wrap_base](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>& next) {
                return gf::Sub(
                    next[wrap_base + column],
                    current[wrap_base + column]);
            };
        lifted.constraints.push_back(std::move(constant));
    }

    const auto append_gated =
        [&](const aq::AirConstraint<gf::Fp3>& source,
            uint32_t selector, bool wrap_next) {
            aq::AirConstraint<gf::Fp3> gated;
            gated.name = source.name;
            gated.kind = aq::AirKind::kEverywhere;
            gated.alg_degree = source.alg_degree + 1;
            const auto eval = source.eval;
            const uint32_t width = child_cs.n_columns;
            gated.eval =
                [eval, width, wrap_base, selector_base,
                 selector, wrap_next](
                    const std::vector<gf::Fp3>& current,
                    const std::vector<gf::Fp3>& next) {
                    std::vector<gf::Fp3> child_current(
                        current.begin(), current.begin() + width);
                    std::vector<gf::Fp3> child_next;
                    if (wrap_next) {
                        child_next.assign(
                            current.begin() + wrap_base,
                            current.begin() + wrap_base + width);
                    } else {
                        child_next.assign(
                            next.begin(), next.begin() + width);
                    }
                    return gf::Mul(
                        current[selector_base + selector],
                        eval(child_current, child_next));
                };
            lifted.constraints.push_back(std::move(gated));
        };
    for (const auto& constraint : child_cs.constraints) {
        switch (constraint.kind) {
        case aq::AirKind::kEverywhere:
            append_gated(constraint, kTransition, false);
            append_gated(constraint, kLast, true);
            break;
        case aq::AirKind::kTransition:
            append_gated(constraint, kTransition, false);
            break;
        case aq::AirKind::kFirstRow:
            append_gated(constraint, kFirst, false);
            break;
        case aq::AirKind::kLastRow:
            append_gated(constraint, kLast, true);
            break;
        }
    }
    for (uint32_t column = 0;
         column < child_cs.n_columns; ++column) {
        aq::AirConstraint<gf::Fp3> zero;
        zero.name = "lift.padding.zero";
        zero.kind = aq::AirKind::kEverywhere;
        zero.alg_degree = 2;
        zero.eval =
            [column, selector_base](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[selector_base + kPadding],
                    current[column]);
            };
        lifted.constraints.push_back(std::move(zero));
    }

    ChildAttachmentV1 attached;
    if (!AppendChildV1(
            parent_cs, parent_columns,
            lifted, lifted_columns,
            child_ordinal, attached, why)) {
        return false;
    }
    attached.semantic_child_columns = child_cs.n_columns;
    attached.row_lifted = parent_rows != child_cs.n_rows;
    attached.padding_zero_constrained = true;
    out = attached;
    return true;
}

} // namespace matmul::v4::rc::stage3_air_parent_composer
