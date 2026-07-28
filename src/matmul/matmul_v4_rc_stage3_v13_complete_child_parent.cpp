// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_complete_child_parent.h>
#include <matmul/matmul_v4_rc_stage3_v13_terminal_fold_parent.h>

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <map>
#include <numeric>
#include <utility>

namespace matmul::v4::rc::stage3_v13_complete_child_parent {
namespace {

using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;
namespace terminal =
    stage3_v13_terminal_fold_parent;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_complete_child_parent:" +
            detail;
    }
    return false;
}

void Add(
    AirCS& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

bool IsPreprocessed(
    const AirCS& cs,
    uint32_t column)
{
    return std::any_of(
        cs.preprocessed.begin(),
        cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
}

bool SameFp3Vector(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t index = 0;
         index < left.size(); ++index) {
        if (!gf::Eq(
                left[index], right[index])) {
            return false;
        }
    }
    return true;
}

bool SameConstraintSystemStructure(
    const AirCS& left,
    const AirCS& right)
{
    if (left.n_rows != right.n_rows ||
        left.n_columns != right.n_columns ||
        left.constraints.size() !=
            right.constraints.size() ||
        left.preprocessed.size() !=
            right.preprocessed.size() ||
        left.preprocessed_roots !=
            right.preprocessed_roots ||
        left.preprocessed_pin_ood !=
            right.preprocessed_pin_ood ||
        left.preprocessed_row_group_roots !=
            right.preprocessed_row_group_roots) {
        return false;
    }
    for (uint32_t index = 0;
         index < left.constraints.size();
         ++index) {
        if (left.constraints[index].name !=
                right.constraints[index].name ||
            left.constraints[index].kind !=
                right.constraints[index].kind ||
            left.constraints[index].alg_degree !=
                right.constraints[index]
                    .alg_degree) {
            return false;
        }
    }
    for (uint32_t index = 0;
         index < left.preprocessed.size();
         ++index) {
        if (left.preprocessed[index].first !=
                right.preprocessed[index].first ||
            !SameFp3Vector(
                left.preprocessed[index].second,
                right.preprocessed[index]
                    .second)) {
            return false;
        }
    }
    return true;
}

bool AppendChildConstraintSystem(
    AirCS& parent_cs,
    const AirCS& child_cs,
    uint32_t child_ordinal,
    composer::ChildAttachmentV1& out,
    std::string* why)
{
    out = {};
    out.child_ordinal = child_ordinal;
    if (child_cs.n_rows < 2 ||
        (child_cs.n_rows &
             (child_cs.n_rows - 1)) != 0 ||
        child_cs.n_columns == 0 ||
        !parent_cs
             .preprocessed_row_group_roots
             .empty() ||
        !child_cs
             .preprocessed_row_group_roots
             .empty()) {
        return Fail(
            why, "public_child_shape");
    }
    if (parent_cs.n_columns == 0) {
        if (parent_cs.n_rows != 0 ||
            !parent_cs.constraints.empty() ||
            !parent_cs.preprocessed.empty() ||
            !parent_cs.preprocessed_roots
                 .empty()) {
            return Fail(
                why,
                "public_noncanonical_parent");
        }
        parent_cs.n_rows =
            child_cs.n_rows;
    } else if (
        parent_cs.n_rows !=
            child_cs.n_rows) {
        return Fail(
            why,
            "public_parent_row_mismatch");
    }
    if (child_cs.n_columns >
        std::numeric_limits<uint32_t>::
                max() -
            parent_cs.n_columns) {
        return Fail(
            why,
            "public_child_column_overflow");
    }
    for (const auto& [column, values] :
         child_cs.preprocessed) {
        if (column >= child_cs.n_columns ||
            values.size() !=
                child_cs.n_rows) {
            return Fail(
                why,
                "public_child_preprocessed");
        }
    }
    for (const auto& [column, root] :
         child_cs.preprocessed_roots) {
        if (column >= child_cs.n_columns ||
            root.IsNull()) {
            return Fail(
                why,
                "public_child_root");
        }
    }
    for (const auto& constraint :
         child_cs.constraints) {
        if (!constraint.eval ||
            constraint.alg_degree == 0) {
            return Fail(
                why,
                "public_child_constraint");
        }
    }

    out.column_base =
        parent_cs.n_columns;
    out.semantic_child_columns =
        child_cs.n_columns;
    out.column_count =
        child_cs.n_columns;
    out.constraint_begin =
        static_cast<uint32_t>(
            parent_cs.constraints.size());
    out.constraint_count =
        static_cast<uint32_t>(
            child_cs.constraints.size());
    out.preprocessed_count =
        static_cast<uint32_t>(
            child_cs.preprocessed.size());
    parent_cs.n_columns +=
        child_cs.n_columns;
    parent_cs.preprocessed_pin_ood =
        parent_cs.preprocessed_pin_ood ||
        child_cs.preprocessed_pin_ood;
    for (const auto& constraint :
         child_cs.constraints) {
        aq::AirConstraint<Fp3> shifted;
        shifted.name = constraint.name;
        shifted.kind = constraint.kind;
        shifted.alg_degree =
            constraint.alg_degree;
        const auto eval =
            constraint.eval;
        const uint32_t base =
            out.column_base;
        const uint32_t width =
            child_cs.n_columns;
        shifted.eval =
            [eval, base, width](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                if (current.size() <
                        base + width ||
                    next.size() <
                        base + width) {
                    return Fp3::One();
                }
                std::vector<Fp3> child_current(
                    current.begin() + base,
                    current.begin() +
                        base + width);
                std::vector<Fp3> child_next(
                    next.begin() + base,
                    next.begin() +
                        base + width);
                return eval(
                    child_current,
                    child_next);
            };
        parent_cs.constraints.push_back(
            std::move(shifted));
    }
    for (const auto& [column, values] :
         child_cs.preprocessed) {
        parent_cs.preprocessed.emplace_back(
            out.column_base + column,
            values);
    }
    for (const auto& [column, root] :
         child_cs.preprocessed_roots) {
        parent_cs
            .preprocessed_roots
            .emplace_back(
                out.column_base + column,
                root);
    }
    out.literal_column_mapping = true;
    out.constraints_shifted = true;
    out.valid = true;
    return true;
}

bool AppendChildConstraintSystemLifted(
    AirCS& parent_cs,
    const AirCS& child_cs,
    uint32_t parent_rows,
    uint32_t child_ordinal,
    composer::ChildAttachmentV1& out,
    std::string* why)
{
    if (parent_rows < child_cs.n_rows ||
        (parent_rows &
             (parent_rows - 1)) != 0 ||
        (parent_rows %
             child_cs.n_rows) != 0 ||
        !child_cs.preprocessed_roots
             .empty() ||
        !child_cs
             .preprocessed_row_group_roots
             .empty() ||
        child_cs.n_columns >
            (std::numeric_limits<
                 uint32_t>::max() -
             5U) /
                2U) {
        return Fail(
            why, "public_lift_shape");
    }
    for (const auto& constraint :
         child_cs.constraints) {
        if (!constraint.eval ||
            constraint.alg_degree == 0 ||
            constraint.alg_degree ==
                std::numeric_limits<
                    uint32_t>::max()) {
            return Fail(
                why,
                "public_lift_constraint");
        }
    }

    constexpr uint32_t kActive = 0;
    constexpr uint32_t kTransition = 1;
    constexpr uint32_t kFirst = 2;
    constexpr uint32_t kLast = 3;
    constexpr uint32_t kPadding = 4;
    constexpr uint32_t kSelectors = 5;
    AirCS lifted;
    lifted.n_rows = parent_rows;
    const uint32_t wrap_base =
        child_cs.n_columns;
    const uint32_t selector_base =
        child_cs.n_columns * 2U;
    lifted.n_columns =
        selector_base + kSelectors;
    lifted.preprocessed_pin_ood =
        child_cs.preprocessed_pin_ood;
    for (const auto& [column, values] :
         child_cs.preprocessed) {
        if (column >= child_cs.n_columns ||
            values.size() !=
                child_cs.n_rows) {
            return Fail(
                why,
                "public_lift_preprocessed");
        }
        std::vector<Fp3> padded(
            parent_rows, Fp3::Zero());
        std::copy(
            values.begin(), values.end(),
            padded.begin());
        lifted.preprocessed.emplace_back(
            column, std::move(padded));
    }
    std::array<std::vector<Fp3>, kSelectors>
        selectors;
    for (auto& selector : selectors) {
        selector.assign(
            parent_rows, Fp3::Zero());
    }
    for (uint32_t row = 0;
         row < parent_rows; ++row) {
        selectors[
            row < child_cs.n_rows
                ? kActive
                : kPadding][row] =
            Fp3::One();
        if (row + 1 <
                child_cs.n_rows) {
            selectors[kTransition][row] =
                Fp3::One();
        }
    }
    selectors[kFirst][0] =
        Fp3::One();
    selectors[kLast][
        child_cs.n_rows - 1] =
        Fp3::One();
    for (uint32_t selector = 0;
         selector < kSelectors;
         ++selector) {
        lifted.preprocessed.emplace_back(
            selector_base + selector,
            std::move(
                selectors[selector]));
    }

    for (uint32_t column = 0;
         column < child_cs.n_columns;
         ++column) {
        Add(
            lifted, "lift.wrap.first",
            aq::AirKind::kFirstRow, 1,
            [column, wrap_base](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    current[
                        wrap_base + column],
                    current[column]);
            });
        Add(
            lifted, "lift.wrap.constant",
            aq::AirKind::kTransition, 1,
            [column, wrap_base](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[
                        wrap_base + column],
                    current[
                        wrap_base + column]);
            });
    }
    const auto append_gated =
        [&](const aq::AirConstraint<Fp3>&
                source,
            uint32_t selector,
            bool wrap_next) {
            aq::AirConstraint<Fp3> gated;
            gated.name = source.name;
            gated.kind =
                aq::AirKind::kEverywhere;
            gated.alg_degree =
                source.alg_degree + 1;
            const auto eval =
                source.eval;
            const uint32_t width =
                child_cs.n_columns;
            gated.eval =
                [eval, width, wrap_base,
                 selector_base, selector,
                 wrap_next](
                    const std::vector<Fp3>&
                        current,
                    const std::vector<Fp3>&
                        next) {
                    std::vector<Fp3>
                        child_current(
                            current.begin(),
                            current.begin() +
                                width);
                    std::vector<Fp3>
                        child_next;
                    if (wrap_next) {
                        child_next.assign(
                            current.begin() +
                                wrap_base,
                            current.begin() +
                                wrap_base +
                                width);
                    } else {
                        child_next.assign(
                            next.begin(),
                            next.begin() +
                                width);
                    }
                    return gf::Mul(
                        current[
                            selector_base +
                            selector],
                        eval(
                            child_current,
                            child_next));
                };
            lifted.constraints.push_back(
                std::move(gated));
        };
    for (const auto& constraint :
         child_cs.constraints) {
        switch (constraint.kind) {
        case aq::AirKind::kEverywhere:
            append_gated(
                constraint,
                kTransition, false);
            append_gated(
                constraint,
                kLast, true);
            break;
        case aq::AirKind::kTransition:
            append_gated(
                constraint,
                kTransition, false);
            break;
        case aq::AirKind::kFirstRow:
            append_gated(
                constraint,
                kFirst, false);
            break;
        case aq::AirKind::kLastRow:
            append_gated(
                constraint,
                kLast, true);
            break;
        }
    }
    for (uint32_t column = 0;
         column < child_cs.n_columns;
         ++column) {
        Add(
            lifted, "lift.padding.zero",
            aq::AirKind::kEverywhere, 2,
            [column, selector_base](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        selector_base +
                        kPadding],
                    current[column]);
            });
    }

    composer::ChildAttachmentV1 attached;
    if (!AppendChildConstraintSystem(
            parent_cs, lifted,
            child_ordinal, attached,
            why)) {
        return false;
    }
    attached.semantic_child_columns =
        child_cs.n_columns;
    attached.row_lifted =
        parent_rows != child_cs.n_rows;
    attached
        .padding_zero_constrained = true;
    out = attached;
    return true;
}

bool AppendAtRowsConstraintSystem(
    AirCS& parent_cs,
    const AirCS& child_cs,
    uint32_t parent_rows,
    uint32_t ordinal,
    composer::ChildAttachmentV1& out,
    std::string* why)
{
    return child_cs.n_rows ==
        parent_rows
        ? AppendChildConstraintSystem(
              parent_cs, child_cs,
              ordinal, out, why)
        : AppendChildConstraintSystemLifted(
              parent_cs, child_cs,
              parent_rows, ordinal,
            out, why);
}

bool AppendLiteralAliasesConstraintSystem(
    AirCS& parent_cs,
    const std::vector<std::pair<
        terminal::CellRefV1,
        terminal::CellRefV1>>& aliases,
    terminal::LiteralAliasAttachmentV1& out,
    std::string* why)
{
    out = {};
    if (parent_cs.n_rows < 2 ||
        aliases.empty() ||
        !parent_cs.preprocessed_roots
             .empty() ||
        !parent_cs
             .preprocessed_row_group_roots
             .empty()) {
        return Fail(
            why,
            "public_literal_alias_input");
    }
    out.original_columns =
        parent_cs.n_columns;
    out.original_constraints =
        static_cast<uint32_t>(
            parent_cs.constraints.size());
    const uint32_t carrier_base =
        parent_cs.n_columns;
    const uint32_t selector_base =
        carrier_base +
        static_cast<uint32_t>(
            aliases.size());
    const uint64_t appended64 =
        uint64_t{aliases.size()} * 3;
    if (appended64 >
        std::numeric_limits<uint32_t>::
                max() -
            parent_cs.n_columns) {
        return Fail(
            why,
            "public_literal_alias_columns");
    }
    parent_cs.n_columns +=
        static_cast<uint32_t>(
            appended64);
    for (uint32_t ordinal = 0;
         ordinal < aliases.size();
         ++ordinal) {
        const auto [source, sink] =
            aliases[ordinal];
        if (source.column >=
                out.original_columns ||
            sink.column >=
                out.original_columns ||
            source.row >=
                parent_cs.n_rows ||
            sink.row >=
                parent_cs.n_rows ||
            IsPreprocessed(
                parent_cs,
                source.column) ||
            IsPreprocessed(
                parent_cs,
                sink.column)) {
            return Fail(
                why,
                "public_literal_alias_endpoint");
        }
        const uint32_t carrier =
            carrier_base + ordinal;
        const uint32_t source_selector =
            selector_base +
            2 * ordinal;
        const uint32_t sink_selector =
            source_selector + 1;
        std::vector<Fp3> source_values(
            parent_cs.n_rows,
            Fp3::Zero());
        std::vector<Fp3> sink_values(
            parent_cs.n_rows,
            Fp3::Zero());
        source_values[source.row] =
            Fp3::One();
        sink_values[sink.row] =
            Fp3::One();
        parent_cs.preprocessed.emplace_back(
            source_selector,
            std::move(source_values));
        parent_cs.preprocessed.emplace_back(
            sink_selector,
            std::move(sink_values));
        Add(
            parent_cs,
            "stage3.v13_terminal_parent."
            "alias_carry",
            aq::AirKind::kTransition, 1,
            [carrier](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[carrier],
                    current[carrier]);
            });
        Add(
            parent_cs,
            "stage3.v13_terminal_parent."
            "alias_source",
            aq::AirKind::kEverywhere, 2,
            [carrier, source_selector,
             source_column =
                 source.column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[source_selector],
                    gf::Sub(
                        current[carrier],
                        current[
                            source_column]));
            });
        Add(
            parent_cs,
            "stage3.v13_terminal_parent."
            "alias_sink",
            aq::AirKind::kEverywhere, 2,
            [carrier, sink_selector,
             sink_column = sink.column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[sink_selector],
                    gf::Sub(
                        current[carrier],
                        current[sink_column]));
            });
    }
    out.literal_aliases =
        static_cast<uint32_t>(
            aliases.size());
    out.appended_carriers =
        out.literal_aliases;
    out.constraints =
        3 * out.literal_aliases;
    out.violations = 0;
    out.endpoints_ordinary = true;
    out.selectors_only_preprocessed = true;
    out.cross_row_transport_constrained =
        out.literal_aliases != 0;
    out.global_r0_pending = true;
    out.valid =
        out.endpoints_ordinary &&
        out.selectors_only_preprocessed &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending;
    if (!out.valid) {
        return Fail(
            why,
            "public_literal_alias_invariant");
    }
    return true;
}

bool AppendPublicMerkleAliases(
    const tape::LayoutV1& tape_layout,
    const tape::ScheduleV1& tape_schedule,
    const composer::ChildAttachmentV1&
        tape_attachment,
    const merkle::PublicConstraintSystemsV1&
        systems,
    const composer::ChildAttachmentV1&
        hash_attachment,
    const composer::ChildAttachmentV1&
        fold_attachment,
    AirCS& parent_cs,
    merkle::ParentAliasAttachmentV1& out,
    std::string* why)
{
    out = {};
    std::map<uint32_t,
             tape::SourceAddressCellV1>
        tape_cells;
    for (const auto& source :
         tape_schedule.semantic_sources) {
        const uint32_t record =
            tape::kPublicPrefixRecordsV1 +
            tape::kHeaderRecordsV1 +
            source.address;
        const uint32_t row =
            record /
            tape::kRecordsPerRowV1;
        const uint32_t slot =
            record %
            tape::kRecordsPerRowV1;
        tape::SourceAddressCellV1 cell{
            .key = source.key,
            .ownership = source.ownership,
            .address = source.address,
            .row = row,
            .slot = slot,
            .address_column =
                tape_layout.Address(slot),
            .value_column =
                tape_layout.Value(slot),
        };
        if (!tape_cells.emplace(
                source.address,
                cell).second) {
            return Fail(
                why,
                "public_duplicate_tape_address");
        }
    }
    std::vector<std::pair<
        terminal::CellRefV1,
        terminal::CellRefV1>>
        aliases;
    aliases.reserve(
        systems.hash_source_carriers
            .size() +
        systems.fold_source_carriers
            .size());
    const auto append =
        [&](const std::vector<
                merkle::SourceCarrierV1>&
                carriers,
            const composer::
                ChildAttachmentV1&
                attachment) {
            for (const auto& carrier :
                 carriers) {
                const auto found =
                    tape_cells.find(
                        carrier
                            .source_address);
                if (found ==
                        tape_cells.end() ||
                    !(found->second.key ==
                      carrier.source_key)) {
                    return false;
                }
                aliases.push_back({
                    {
                        tape_attachment
                            .ParentColumn(
                                found->second
                                    .value_column),
                        found->second.row,
                    },
                    {
                        attachment
                            .ParentColumn(
                                carrier
                                    .cell
                                    .column),
                        carrier.cell.row,
                    }});
            }
            return true;
        };
    if (!systems.valid ||
        !tape_attachment.valid ||
        !hash_attachment.valid ||
        !fold_attachment.valid ||
        !append(
            systems.hash_source_carriers,
            hash_attachment) ||
        !append(
            systems.fold_source_carriers,
            fold_attachment) ||
        aliases.empty()) {
        return Fail(
            why,
            "public_merkle_alias_schedule");
    }
    terminal::LiteralAliasAttachmentV1
        literal;
    if (!AppendLiteralAliasesConstraintSystem(
            parent_cs, aliases,
            literal, why)) {
        return false;
    }
    out.source_aliases =
        literal.literal_aliases;
    out.constraints =
        literal.constraints;
    out.violations = 0;
    out.tape_cells_literal =
        out.source_aliases ==
            systems.hash_source_carriers
                .size() +
                systems.fold_source_carriers
                    .size();
    out.child_carriers_ordinary =
        literal.endpoints_ordinary;
    out.cross_row_transport_constrained =
        literal
            .cross_row_transport_constrained;
    out.global_r0_pending = true;
    out.valid =
        out.tape_cells_literal &&
        out.child_carriers_ordinary &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending;
    return out.valid;
}

bool AppendTerminalAcceptanceConstraintSystem(
    AirCS& cs,
    const merkle::CellRefV1&
        hash_acceptance,
    const composer::ChildAttachmentV1&
        hash_attachment,
    const merkle::CellRefV1&
        fold_acceptance,
    const composer::ChildAttachmentV1&
        fold_attachment,
    uint32_t& acceptance,
    std::string* why)
{
    if (hash_acceptance.row != 0 ||
        fold_acceptance.row != 0 ||
        hash_acceptance.column >=
            hash_attachment
                .semantic_child_columns ||
        fold_acceptance.column >=
            fold_attachment
                .semantic_child_columns ||
        cs.n_columns ==
            std::numeric_limits<
                uint32_t>::max()) {
        return Fail(
            why,
            "public_terminal_acceptance");
    }
    acceptance = cs.n_columns++;
    const uint32_t hash_column =
        hash_attachment.ParentColumn(
            hash_acceptance.column);
    const uint32_t fold_column =
        fold_attachment.ParentColumn(
            fold_acceptance.column);
    Add(
        cs,
        "stage3.v13_complete.accept_one",
        aq::AirKind::kFirstRow, 1,
        [acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                Fp3::One());
        });
    Add(
        cs,
        "stage3.v13_complete.accept_hash",
        aq::AirKind::kFirstRow, 1,
        [acceptance, hash_column](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                current[hash_column]);
        });
    Add(
        cs,
        "stage3.v13_complete.accept_fold",
        aq::AirKind::kFirstRow, 1,
        [acceptance, fold_column](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                current[fold_column]);
        });
    return true;
}

bool AppendSharedTapeAliasConstraintSystem(
    uint32_t tape_columns,
    const composer::ChildAttachmentV1&
        merkle_tape_attachment,
    const composer::ChildAttachmentV1&
        merkle_parent_attachment,
    const composer::ChildAttachmentV1&
        deep_tape_attachment,
    const composer::ChildAttachmentV1&
        deep_base_attachment,
    AirCS& parent_cs,
    uint32_t& aliases,
    std::string* why)
{
    aliases = 0;
    if (tape_columns == 0 ||
        !merkle_tape_attachment.valid ||
        !merkle_parent_attachment.valid ||
        !deep_tape_attachment.valid ||
        !deep_base_attachment.valid ||
        merkle_tape_attachment
                .semantic_child_columns !=
            tape_columns ||
        deep_tape_attachment
                .semantic_child_columns !=
            tape_columns) {
        return Fail(
            why,
            "public_shared_tape_input");
    }
    for (uint32_t local = 0;
         local < tape_columns; ++local) {
        const uint32_t merkle_column =
            merkle_parent_attachment
                .ParentColumn(
                    merkle_tape_attachment
                        .ParentColumn(
                            local));
        const uint32_t deep_column =
            deep_base_attachment
                .ParentColumn(
                    deep_tape_attachment
                        .ParentColumn(
                            local));
        if (merkle_column >=
                parent_cs.n_columns ||
            deep_column >=
                parent_cs.n_columns) {
            return Fail(
                why,
                "public_shared_tape_range");
        }
        Add(
            parent_cs,
            "stage3.v13_complete.shared_tape",
            aq::AirKind::kEverywhere, 1,
            [merkle_column, deep_column](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    current[merkle_column],
                    current[deep_column]);
            });
        ++aliases;
    }
    return aliases == tape_columns;
}

bool AppendAtRows(
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>&
        parent_columns,
    const AirCS& child_cs,
    const std::vector<std::vector<Fp3>>&
        child_columns,
    uint32_t parent_rows,
    uint32_t ordinal,
    composer::ChildAttachmentV1& attachment,
    std::string* why)
{
    return child_cs.n_rows == parent_rows
        ? composer::AppendChildV1(
              parent_cs, parent_columns,
              child_cs, child_columns,
              ordinal, attachment, why)
        : composer::AppendChildLiftedV1(
              parent_cs, parent_columns,
              child_cs, child_columns,
              parent_rows, ordinal,
              attachment, why);
}

bool AppendTerminalAcceptance(
    AirCS& merkle_cs,
    std::vector<std::vector<Fp3>>&
        merkle_columns,
    const merkle::OrdinaryHashProductV1&
        hash,
    const composer::ChildAttachmentV1&
        hash_attachment,
    const merkle::OrdinaryFoldProductV1&
        fold,
    const composer::ChildAttachmentV1&
        fold_attachment,
    uint32_t& acceptance,
    std::string* why)
{
    if (!hash.valid || !fold.valid ||
        hash.acceptance.row != 0 ||
        fold.acceptance.row != 0 ||
        hash.acceptance.column >=
            hash.cs.n_columns ||
        fold.acceptance.column >=
            fold.cs.n_columns ||
        merkle_cs.n_columns !=
            merkle_columns.size() ||
        merkle_cs.n_columns ==
            std::numeric_limits<uint32_t>::max()) {
        return Fail(
            why, "terminal_acceptance_input");
    }
    acceptance = merkle_cs.n_columns++;
    merkle_columns.push_back(
        std::vector<Fp3>(
            merkle_cs.n_rows,
            Fp3::Zero()));
    merkle_columns[acceptance][0] =
        Fp3::One();
    const uint32_t hash_column =
        hash_attachment.ParentColumn(
            hash.acceptance.column);
    const uint32_t fold_column =
        fold_attachment.ParentColumn(
            fold.acceptance.column);
    Add(
        merkle_cs,
        "stage3.v13_complete.accept_one",
        aq::AirKind::kFirstRow, 1,
        [acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                Fp3::One());
        });
    Add(
        merkle_cs,
        "stage3.v13_complete.accept_hash",
        aq::AirKind::kFirstRow, 1,
        [acceptance, hash_column](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                current[hash_column]);
        });
    Add(
        merkle_cs,
        "stage3.v13_complete.accept_fold",
        aq::AirKind::kFirstRow, 1,
        [acceptance, fold_column](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                current[fold_column]);
        });
    return true;
}

bool AppendSharedTapeAliases(
    const tape::ProductV1& tape_product,
    const composer::ChildAttachmentV1&
        merkle_tape_attachment,
    const composer::ChildAttachmentV1&
        merkle_parent_attachment,
    const deep::BaseProductV1& deep_base,
    const composer::ChildAttachmentV1&
        deep_base_attachment,
    AirCS& parent_cs,
    uint32_t& aliases,
    std::string* why)
{
    aliases = 0;
    const auto& deep_tape_attachment =
        deep_base.physical.tape_attachment;
    if (!tape_product.valid ||
        !merkle_tape_attachment.valid ||
        !merkle_parent_attachment.valid ||
        !deep_base.valid ||
        !deep_base_attachment.valid ||
        !deep_tape_attachment.valid ||
        !merkle_tape_attachment
             .literal_column_mapping ||
        !merkle_parent_attachment
             .literal_column_mapping ||
        !deep_base_attachment
             .literal_column_mapping ||
        !deep_tape_attachment
             .literal_column_mapping ||
        merkle_tape_attachment
                .semantic_child_columns !=
            tape_product.cs.n_columns ||
        deep_tape_attachment
                .semantic_child_columns !=
            tape_product.cs.n_columns) {
        return Fail(
            why, "shared_tape_alias_input");
    }
    for (uint32_t local = 0;
         local < tape_product.cs.n_columns;
         ++local) {
        const uint32_t merkle_column =
            merkle_parent_attachment.ParentColumn(
                merkle_tape_attachment.ParentColumn(
                    local));
        const uint32_t deep_column =
            deep_base_attachment.ParentColumn(
                deep_tape_attachment.ParentColumn(
                    local));
        if (merkle_column >=
                parent_cs.n_columns ||
            deep_column >=
                parent_cs.n_columns) {
            return Fail(
                why, "shared_tape_alias_range");
        }
        Add(
            parent_cs,
            "stage3.v13_complete.shared_tape",
            aq::AirKind::kEverywhere, 1,
            [merkle_column, deep_column](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    current[merkle_column],
                    current[deep_column]);
            });
        ++aliases;
    }
    return aliases ==
        tape_product.cs.n_columns;
}

bool AdoptComponentAsParent(
    DeterministicComponentV1& component,
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>&
        parent_columns,
    composer::ChildAttachmentV1& attachment,
    std::string* why)
{
    attachment = {};
    if (!component.valid ||
        component.cs.n_rows < 2 ||
        component.cs.n_columns == 0 ||
        component.columns.size() !=
            component.cs.n_columns ||
        !component.cs
             .preprocessed_row_group_roots
             .empty()) {
        return Fail(
            why, "adopt_component_input");
    }
    for (const auto& column :
         component.columns) {
        if (column.size() !=
            component.cs.n_rows) {
            return Fail(
                why, "adopt_component_shape");
        }
    }
    attachment.child_ordinal = 0;
    attachment.column_base = 0;
    attachment.semantic_child_columns =
        component.cs.n_columns;
    attachment.column_count =
        component.cs.n_columns;
    attachment.constraint_begin = 0;
    attachment.constraint_count =
        static_cast<uint32_t>(
            component.cs.constraints.size());
    attachment.preprocessed_count =
        static_cast<uint32_t>(
            component.cs.preprocessed.size());
    attachment.literal_column_mapping = true;
    // Base-zero relocation is the identity shift.
    attachment.constraints_shifted = true;
    attachment.row_lifted = false;
    attachment.padding_zero_constrained = false;
    attachment.valid = true;
    parent_cs = std::move(component.cs);
    parent_columns =
        std::move(component.columns);
    return true;
}

} // namespace

bool BuildDeterministicConstraintSystemV1(
    const PublicStatementV1& statement,
    PublicDeterministicComponentV1& out,
    std::string* why)
{
    out = {};
    out.statement = statement;
    if (statement.version != kVersionV1 ||
        statement.range.query_count == 0 ||
        statement.public_seed.IsNull()) {
        return Fail(
            why,
            "public_statement");
    }

    AirCS tape_cs;
    tape::LayoutV1 tape_layout;
    tape::ScheduleV1 tape_schedule;
    if (!tape::BuildConstraintSystemV1(
            statement.tape_shape,
            statement.tape_binding,
            tape_cs, &tape_layout,
            &tape_schedule, why) ||
        !merkle::BuildPublicConstraintSystemsV1(
            statement.tape_shape,
            statement.tape_binding,
            statement.range,
            out.merkle_systems,
            why)) {
        return Fail(
            why,
            "public_tape_or_merkle");
    }

    AirCS merkle_cs;
    composer::ChildAttachmentV1
        merkle_tape_attachment;
    composer::ChildAttachmentV1
        hash_attachment;
    composer::ChildAttachmentV1
        fold_attachment;
    const uint32_t merkle_rows =
        std::max({
            tape_cs.n_rows,
            out.merkle_systems
                .hash_cs.n_rows,
            out.merkle_systems
                .fold_cs.n_rows});
    if (!AppendAtRowsConstraintSystem(
            merkle_cs, tape_cs,
            merkle_rows, 0,
            merkle_tape_attachment,
            why) ||
        !AppendAtRowsConstraintSystem(
            merkle_cs,
            out.merkle_systems.hash_cs,
            merkle_rows, 1,
            hash_attachment, why) ||
        !AppendAtRowsConstraintSystem(
            merkle_cs,
            out.merkle_systems.fold_cs,
            merkle_rows, 2,
            fold_attachment, why)) {
        return false;
    }
    merkle::ParentAliasAttachmentV1
        merkle_aliases;
    uint32_t merkle_acceptance =
        UINT32_MAX;
    if (!AppendPublicMerkleAliases(
            tape_layout, tape_schedule,
            merkle_tape_attachment,
            out.merkle_systems,
            hash_attachment,
            fold_attachment,
            merkle_cs, merkle_aliases,
            why) ||
        !AppendTerminalAcceptanceConstraintSystem(
            merkle_cs,
            out.merkle_systems
                .hash_acceptance,
            hash_attachment,
            out.merkle_systems
                .fold_acceptance,
            fold_attachment,
            merkle_acceptance,
            why) ||
        !deep::BuildPublicBaseConstraintSystemV1(
            statement.tape_shape,
            statement.tape_binding,
            statement.child_program,
            statement.child_program_root,
            statement.range,
            out.deep_base, why)) {
        return false;
    }
    if (out.deep_base.cs.n_rows !=
            merkle_cs.n_rows) {
        return Fail(
            why,
            "public_shared_row_domain");
    }

    composer::ChildAttachmentV1
        merkle_parent_attachment;
    composer::ChildAttachmentV1
        deep_base_attachment;
    if (!AppendChildConstraintSystem(
            out.cs, merkle_cs, 0,
            merkle_parent_attachment,
            why) ||
        !AppendChildConstraintSystem(
            out.cs, out.deep_base.cs, 1,
            deep_base_attachment,
            why) ||
        !AppendSharedTapeAliasConstraintSystem(
            tape_cs.n_columns,
            merkle_tape_attachment,
            merkle_parent_attachment,
            out.deep_base.physical
                .tape_attachment,
            deep_base_attachment,
            out.cs,
            out.shared_tape_aliases,
            why)) {
        return false;
    }
    out.terminal_acceptance_column =
        merkle_parent_attachment
            .ParentColumn(
                merkle_acceptance);
    out.deep_base_attachment =
        deep_base_attachment;
    out.deterministic_system_rebuilt =
        merkle_aliases.valid &&
        out.deep_base.valid &&
        out.shared_tape_aliases ==
            tape_cs.n_columns &&
        out.terminal_acceptance_column <
            out.cs.n_columns;
    out.proof_values_excluded =
        out.merkle_systems
            .proof_values_excluded &&
        out.deep_base
            .proof_values_excluded;
    out.valid =
        out.deterministic_system_rebuilt &&
        out.proof_values_excluded &&
        out.cs.n_columns <
            kRCFri3AlgBatchMaxColumns &&
        out.cs
            .preprocessed_row_group_roots
            .empty();
    out.note = out.valid
        ? "stage3:v13_complete_child_parent:"
          "public_deterministic_component_rebuilt"
        : "stage3:v13_complete_child_parent:"
          "public_deterministic_component_invalid";
    if (!out.valid) {
        return Fail(
            why,
            "public_deterministic_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendFinalConstraintSystemToParentV1(
    const PublicDeterministicComponentV1&
        component,
    const composer::ChildAttachmentV1&
        component_attachment,
    const uint256&
        domain_separated_public_seed,
    const uint256& r0_row_root,
    const std::vector<uint32_t>&
        r0_base_column_indices,
    AirCS& parent_cs,
    ComponentFinalizationV1& out,
    std::string* why)
{
    out = {};
    if (!component.valid ||
        !component.deep_base_attachment.valid ||
        !component_attachment.valid ||
        component_attachment.row_lifted ||
        component_attachment
                .semantic_child_columns !=
            component.cs.n_columns ||
        component.deep_base_attachment
                .column_base >=
            component.cs.n_columns ||
        component_attachment.column_base >
            parent_cs.n_columns ||
        component.cs.n_columns >
            parent_cs.n_columns -
                component_attachment
                    .column_base ||
        domain_separated_public_seed
            .IsNull()) {
        return Fail(
            why,
            "public_component_finalize_input");
    }
    out.relocated_deep_base_attachment =
        component.deep_base_attachment;
    out.relocated_deep_base_attachment
        .column_base =
            component_attachment.ParentColumn(
                component
                    .deep_base_attachment
                    .column_base);
    if (!deep::
            AppendFinalConstraintSystemToParentV1(
                component.deep_base,
                out.relocated_deep_base_attachment,
                domain_separated_public_seed,
                r0_row_root,
                r0_base_column_indices,
                parent_cs,
                out.deep,
                why)) {
        return false;
    }
    out.terminal_acceptance_column =
        component_attachment.ParentColumn(
            component
                .terminal_acceptance_column);
    out.deterministic_component_inside_r0 =
        component_attachment.column_base +
                component.cs.n_columns <=
            r0_base_column_indices.size();
    out.terminal_acceptance_relocated =
        out.terminal_acceptance_column <
            r0_base_column_indices.size();
    out.valid =
        out.deep.valid &&
        out.deterministic_component_inside_r0 &&
        out.terminal_acceptance_relocated;
    out.note = out.valid
        ? "stage3:v13_complete_child_parent:"
          "public_component_finalized_from_global_r0"
        : "stage3:v13_complete_child_parent:"
          "public_component_finalization_invalid";
    if (!out.valid) {
        return Fail(
            why,
            "public_component_finalize_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildConstraintSystemV1(
    const PublicStatementV1& statement,
    const uint256& r0_row_root,
    VerifierConstraintSystemV1& out,
    std::string* why)
{
    out = {};
    if (r0_row_root.IsNull()) {
        return Fail(
            why, "public_r0_root");
    }
    PublicDeterministicComponentV1
        deterministic;
    if (!BuildDeterministicConstraintSystemV1(
            statement, deterministic, why)) {
        return false;
    }
    out.statement = statement;
    out.cs = deterministic.cs;
    out.merkle_systems =
        deterministic.merkle_systems;
    out.deep_base =
        deterministic.deep_base;
    out.shared_tape_aliases =
        deterministic.shared_tape_aliases;
    out.terminal_acceptance_column =
        deterministic
            .terminal_acceptance_column;
    composer::ChildAttachmentV1
        component_attachment;
    component_attachment.child_ordinal = 0;
    component_attachment.column_base = 0;
    component_attachment
        .semantic_child_columns =
            deterministic.cs.n_columns;
    component_attachment.column_count =
        deterministic.cs.n_columns;
    component_attachment.constraint_begin = 0;
    component_attachment.constraint_count =
        static_cast<uint32_t>(
            deterministic.cs
                .constraints.size());
    component_attachment.preprocessed_count =
        static_cast<uint32_t>(
            deterministic.cs
                .preprocessed.size());
    component_attachment
        .literal_column_mapping = true;
    component_attachment
        .constraints_shifted = true;
    component_attachment.valid = true;
    out.r0_base_column_indices.resize(
        out.cs.n_columns);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(),
        0U);
    ComponentFinalizationV1 finalization;
    if (!AppendFinalConstraintSystemToParentV1(
            deterministic,
            component_attachment,
            statement.public_seed,
            r0_row_root,
            out.r0_base_column_indices,
            out.cs,
            finalization,
            why)) {
        return false;
    }
    out.deep_finalization =
        finalization.deep;
    out.deterministic_system_rebuilt =
        deterministic.valid;
    out.challenge_system_rebuilt =
        finalization.valid &&
        out.deep_finalization.r0_row_root ==
            r0_row_root;
    out.proof_values_excluded =
        deterministic.proof_values_excluded;
    out.valid =
        out.deterministic_system_rebuilt &&
        out.challenge_system_rebuilt &&
        out.proof_values_excluded &&
        out.cs.n_columns <
            kRCFri3AlgBatchMaxColumns &&
        out.cs
            .preprocessed_row_group_roots
            .size() == 1;
    out.note = out.valid
        ? "stage3:v13_complete_child_parent:"
          "verifier_constraint_system_rebuilt"
        : "stage3:v13_complete_child_parent:"
          "verifier_constraint_system_invalid";
    if (!out.valid) {
        return Fail(
            why,
            "public_verifier_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyProofV1(
    const PublicStatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof&
        proof,
    std::string* why)
{
    if (proof.batch.groups.empty()) {
        return Fail(
            why,
            "proof_missing_r0_group");
    }
    const uint256 r0_row_root =
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root);
    VerifierConstraintSystemV1 rebuilt;
    if (!BuildConstraintSystemV1(
            statement, r0_row_root,
            rebuilt, why)) {
        return false;
    }
    std::string verify_why;
    if (!aq::
            AirQuotientVerifyRowsSplitRapSafeV2(
                rebuilt.cs, proof,
                rebuilt
                    .r0_base_column_indices,
                statement.public_seed,
                &verify_why)) {
        return Fail(
            why,
            "proof:" + verify_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_complete_child_parent:"
            "public_rebuilt_cs_verified";
    }
    return true;
}

bool BuildDeterministicComponentV1(
    const abi::DecodedV1& decoded,
    const tape::ProductV1& tape_product,
    const mf::ShardProductV1& shard,
    const deep::ProductV1& deep_product,
    DeterministicComponentV1& out,
    std::string* why)
{
    out = {};
    if (!tape_product.valid ||
        !shard.valid ||
        !deep_product.valid ||
        shard.query_count == 0 ||
        shard.first_query !=
            deep_product.plan.range.first_query ||
        shard.query_count !=
            deep_product.plan.range.query_count ||
        deep_product.tape_binding !=
            tape_product.binding) {
        return Fail(
            why, "input_or_tape_binding");
    }
    out.tape_shape =
        tape_product.schedule.shape;
    out.tape_binding =
        tape_product.binding;
    out.range =
        deep_product.plan.range;

    if (!merkle::BuildPublicConstraintSystemsV1(
            out.tape_shape,
            out.tape_binding,
            out.range,
            out.public_merkle_systems,
            why) ||
        !merkle::
            BuildOrdinaryProductsFromPublicSystemsV1(
                out.public_merkle_systems,
                decoded, shard,
                out.hash, out.fold,
                why)) {
        return Fail(
            why,
            "public_merkle_fold_child");
    }

    AirCS merkle_cs;
    std::vector<std::vector<Fp3>>
        merkle_columns;
    const uint32_t merkle_rows =
        std::max({
            tape_product.cs.n_rows,
            out.hash.cs.n_rows,
            out.fold.cs.n_rows});
    if (!AppendAtRows(
            merkle_cs, merkle_columns,
            tape_product.cs,
            tape_product.columns,
            merkle_rows, 0,
            out.merkle_tape_attachment,
            why) ||
        !AppendAtRows(
            merkle_cs, merkle_columns,
            out.hash.cs, out.hash.columns,
            merkle_rows, 1,
            out.hash_attachment, why) ||
        !AppendAtRows(
            merkle_cs, merkle_columns,
            out.fold.cs, out.fold.columns,
            merkle_rows, 2,
            out.fold_attachment, why) ||
        !merkle::AppendProofTapeAliasesV1(
            merkle_cs, merkle_columns,
            tape_product,
            out.merkle_tape_attachment,
            out.hash, out.hash_attachment,
            out.fold, out.fold_attachment,
            out.merkle_aliases, why)) {
        return false;
    }

    uint32_t merkle_acceptance =
        UINT32_MAX;
    if (!AppendTerminalAcceptance(
            merkle_cs, merkle_columns,
            out.hash, out.hash_attachment,
            out.fold, out.fold_attachment,
            merkle_acceptance, why) ||
        !deep::ExtractBaseProductV1(
            deep_product, out.deep_base,
            why)) {
        return false;
    }
    if (out.deep_base.tape_binding !=
            tape_product.binding ||
        out.deep_base.cs.n_rows !=
            merkle_cs.n_rows) {
        return Fail(
            why, "shared_tape_or_row_domain");
    }

    if (!composer::AppendChildV1(
            out.cs, out.columns,
            merkle_cs, merkle_columns,
            0, out.merkle_parent_attachment,
            why) ||
        !composer::AppendChildV1(
            out.cs, out.columns,
            out.deep_base.cs,
            out.deep_base.columns,
            1, out.deep_base_attachment,
            why)) {
        return false;
    }
    if (!AppendSharedTapeAliases(
            tape_product,
            out.merkle_tape_attachment,
            out.merkle_parent_attachment,
            out.deep_base,
            out.deep_base_attachment,
            out.cs,
            out.shared_tape_aliases,
            why)) {
        return false;
    }
    out.terminal_acceptance_column =
        out.merkle_parent_attachment
            .ParentColumn(
                merkle_acceptance);

    out.violations =
        deep::CountViolationsV1(
            out.cs, out.columns);
    out.exact_shared_tape_cells_aliased =
        out.shared_tape_aliases ==
            tape_product.cs.n_columns &&
        out.shared_tape_aliases != 0;
    out.exact_shared_tape_binding =
        out.deep_base.tape_binding ==
            tape_product.binding &&
        out.exact_shared_tape_cells_aliased;
    out.verifier_merkle_systems_rebuilt =
        out.public_merkle_systems.valid &&
        out.public_merkle_systems
            .proof_values_excluded &&
        out.public_merkle_systems
            .transformed_systems_rebuilt;
    out.merkle_fold_complete =
        out.merkle_aliases.valid &&
        out.hash.all_abi_words_exported &&
        out.hash.all_prior_edges_constrained &&
        out.hash.all_output_roots_constrained &&
        out.fold.all_abi_words_exported &&
        out.fold.fold_chain_constrained;
    out.quotient_deep_base_complete =
        out.deep_base.valid &&
        out.deep_base.challenge_columns_absent &&
        out.deep_base.row_group_root_pending;
    out.challenge_columns_absent =
        out.cs
            .preprocessed_row_group_roots
            .empty();
    out.terminal_acceptance_connected =
        out.terminal_acceptance_column <
            out.cs.n_columns &&
        gf::Eq(
            out.columns[
                out.terminal_acceptance_column][0],
            Fp3::One());
    out.canonical_embedding_ready =
        out.cs.n_columns <
            kRCFri3AlgBatchMaxColumns;
    out.valid =
        out.violations == 0 &&
        out.exact_shared_tape_binding &&
        out.exact_shared_tape_cells_aliased &&
        out.verifier_merkle_systems_rebuilt &&
        out.merkle_fold_complete &&
        out.quotient_deep_base_complete &&
        out.challenge_columns_absent &&
        out.terminal_acceptance_connected &&
        out.canonical_embedding_ready;
    out.note = out.valid
        ? "stage3:v13_complete_child_parent:"
          "deterministic_merkle_fold_quotient_deep;"
          "global_r0_pending"
        : "stage3:v13_complete_child_parent:"
          "deterministic_component_invalid";
    if (!out.valid) {
        return Fail(
            why, "deterministic_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendFinalRelationToParentV1(
    const DeterministicComponentV1& component,
    const composer::ChildAttachmentV1&
        component_attachment,
    const uint256& domain_separated_public_seed,
    const aq::AirQuotientTwoEpochBaseRowSession&
        parent_r0_session,
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>&
        parent_columns,
    ComponentFinalizationV1& out,
    std::string* why)
{
    out = {};
    if (!component.valid ||
        !component_attachment.valid ||
        component_attachment.row_lifted ||
        component_attachment
                .semantic_child_columns !=
            component.cs.n_columns ||
        component_attachment.column_base >
            parent_cs.n_columns ||
        component.cs.n_columns >
            parent_cs.n_columns -
                component_attachment.column_base ||
        component.terminal_acceptance_column >=
            component.cs.n_columns) {
        return Fail(
            why, "component_finalize_input");
    }
    out.relocated_deep_base_attachment =
        component.deep_base_attachment;
    out.relocated_deep_base_attachment
        .column_base =
        component_attachment.column_base +
        component.deep_base_attachment
            .column_base;
    if (!deep::AppendFinalRelationToParentV1(
            component.deep_base,
            out.relocated_deep_base_attachment,
            domain_separated_public_seed,
            parent_r0_session,
            parent_cs, parent_columns,
            out.deep, why)) {
        return false;
    }
    out.terminal_acceptance_column =
        component_attachment.ParentColumn(
            component
                .terminal_acceptance_column);
    out.deterministic_component_inside_r0 =
        component_attachment.column_base +
            component.cs.n_columns <=
        parent_r0_session
            .base_column_indices.size() &&
        out.deep
            .all_deterministic_parent_columns_prechallenge;
    out.terminal_acceptance_relocated =
        out.terminal_acceptance_column <
            parent_r0_session
                .base_column_indices.size() &&
        gf::Eq(
            parent_columns[
                out.terminal_acceptance_column][0],
            Fp3::One());
    out.valid =
        out.deep.valid &&
        out.deterministic_component_inside_r0 &&
        out.terminal_acceptance_relocated;
    out.note = out.valid
        ? "stage3:v13_complete_child_parent:"
          "component_finalized_from_global_r0"
        : "stage3:v13_complete_child_parent:"
          "component_finalization_invalid";
    if (!out.valid) {
        return Fail(
            why, "component_finalize_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildProductV1(
    const abi::DecodedV1& decoded,
    const tape::ProductV1& tape_product,
    const mf::ShardProductV1& shard,
    const deep::ProductV1& deep_product,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why)
{
    out = {};
    DeterministicComponentV1 component;
    if (public_seed.IsNull() ||
        !BuildDeterministicComponentV1(
            decoded, tape_product, shard,
            deep_product, component, why) ||
        !AdoptComponentAsParent(
            component,
            out.cs, out.columns,
            out.component_attachment,
            why)) {
        return false;
    }
    out.r0_base_column_indices.resize(
        out.cs.n_columns);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(),
        0U);
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        out.r0_session
            .base_row_commitment.IsNull() ||
        !AppendFinalRelationToParentV1(
            component,
            out.component_attachment,
            public_seed, out.r0_session,
            out.cs, out.columns,
            out.component_finalization, why)) {
        return false;
    }
    PublicStatementV1 public_statement;
    public_statement.tape_shape =
        component.tape_shape;
    public_statement.tape_binding =
        component.tape_binding;
    public_statement.range =
        component.range;
    public_statement.child_program =
        component.deep_base.physical
            .deep_plan.child_program;
    public_statement.child_program_root =
        component.deep_base.physical
            .deep_plan.child_program_root;
    public_statement.public_seed =
        public_seed;
    VerifierConstraintSystemV1
        verifier_system;
    std::string rebuild_why;
    out.verifier_constraint_system_rebuilt =
        BuildConstraintSystemV1(
            public_statement,
            out.r0_session
                .base_row_commitment,
            verifier_system,
            &rebuild_why) &&
        verifier_system
            .r0_base_column_indices ==
                out.r0_base_column_indices &&
        SameConstraintSystemStructure(
            out.cs,
            verifier_system.cs);

    out.public_merkle_systems =
        std::move(
            component
                .public_merkle_systems);
    out.hash = std::move(component.hash);
    out.fold = std::move(component.fold);
    out.merkle_aliases =
        std::move(component.merkle_aliases);
    out.merkle_tape_attachment =
        component.merkle_tape_attachment;
    out.hash_attachment =
        component.hash_attachment;
    out.fold_attachment =
        component.fold_attachment;
    out.merkle_parent_attachment =
        component.merkle_parent_attachment;
    out.deep_base =
        std::move(component.deep_base);
    out.deep_base_attachment =
        component.deep_base_attachment;
    out.deep_finalization =
        out.component_finalization.deep;
    out.terminal_acceptance_column =
        out.component_finalization
            .terminal_acceptance_column;
    out.shared_tape_aliases =
        component.shared_tape_aliases;

    // This full scan is the acceptance oracle for the composed relation.  It
    // deliberately includes the post-R0 inverse/running columns and terminal
    // constraints; summing child prechecks would miss a forged dependent
    // witness.
    out.violations =
        deep::CountViolationsV1(
            out.cs, out.columns);
    out.exact_shared_tape_binding =
        component.exact_shared_tape_binding;
    out.exact_shared_tape_cells_aliased =
        component
            .exact_shared_tape_cells_aliased;
    out.verifier_merkle_systems_rebuilt =
        component
            .verifier_merkle_systems_rebuilt;
    out.merkle_fold_complete =
        component.merkle_fold_complete;
    out.quotient_deep_complete =
        out.deep_finalization.valid &&
        out.deep_finalization
            .dual_fp3_terminal_cancelled;
    out.every_deterministic_column_precedes_r0 =
        out.deep_finalization
            .all_deterministic_parent_columns_prechallenge &&
        out.deep_finalization
            .r0_base_column_indices ==
                out.r0_base_column_indices;
    out.terminal_acceptance_connected =
        out.component_finalization
            .terminal_acceptance_relocated;
    out.proof_ready =
        out.cs.n_columns <
            kRCFri3AlgBatchMaxColumns &&
        out.cs.preprocessed_row_group_roots
            .size() == 1;
    out.recursively_consumed = false;
    out.authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.exact_shared_tape_binding &&
        out.exact_shared_tape_cells_aliased &&
        out.verifier_merkle_systems_rebuilt &&
        out.verifier_constraint_system_rebuilt &&
        out.merkle_fold_complete &&
        out.quotient_deep_complete &&
        out.every_deterministic_column_precedes_r0 &&
        out.terminal_acceptance_connected &&
        out.proof_ready &&
        !out.recursively_consumed &&
        !out.authority_ready;
    out.note = out.valid
        ? "stage3:v13_complete_child_parent:"
          "merkle_fold_quotient_deep_one_r0;"
          "recursive_consumption_pending"
        : "stage3:v13_complete_child_parent:"
          "combined_relation_invalid";
    if (!out.valid) {
        return Fail(why, "invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

} // namespace matmul::v4::rc::stage3_v13_complete_child_parent
