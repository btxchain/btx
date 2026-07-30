// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_direct_parent_spine.h>

#include <hash.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::direct_parent_spine {
namespace {

using AirConstraint = aq::AirConstraint<gf::Fp3>;
using AirCS = aq::AirConstraintSystem<gf::Fp3>;

constexpr uint32_t kRowQuery = 1;
constexpr uint32_t kRowManifest = 2;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:direct_parent_spine:" + detail;
    }
    return false;
}

bool Canonical(const gf::Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

gf::Fp3 U32(uint32_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

std::array<uint32_t, 8> RootLimbs(const uint256& root)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t limb = 0; limb < out.size(); ++limb) {
        const uint32_t offset = 4 * limb;
        out[limb] =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(root.begin()[offset + 3]) << 24);
    }
    return out;
}

bool UniqueSchedule(const std::vector<uint32_t>& schedule)
{
    if (schedule.empty()) return false;
    std::set<uint32_t> seen;
    for (uint32_t index : schedule) {
        if (!seen.insert(index).second) return false;
    }
    return true;
}

bool SameFp3(
    const std::vector<gf::Fp3>& lhs,
    const std::vector<gf::Fp3>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!gf::Eq(lhs[i], rhs[i])) return false;
    }
    return true;
}

bool ShapeMatches(
    const DirectParentStatementV1& statement,
    const DirectParentTerminalExportsV1& terminals)
{
    if (terminals.query_indices.size() !=
            statement.query_indices.size() ||
        terminals.source_parent_q.size() !=
            statement.source_parent_q.size()) {
        return false;
    }
    for (uint32_t child = 0;
         child < kDirectParentSpineArityV1; ++child) {
        const auto& expected = statement.receipts[child];
        const auto& actual = terminals.receipts[child];
        if (actual.query_indices.size() !=
                expected.query_indices.size() ||
            actual.source_parent_q.size() !=
                expected.source_parent_q.size() ||
            actual.local_q_per_query.size() !=
                expected.local_q_per_query.size() ||
            actual.program_ordinals.size() !=
                expected.program_ordinals.size()) {
            return false;
        }
        for (const auto& q : actual.source_parent_q) {
            if (!Canonical(q)) return false;
        }
        for (const auto& q : actual.local_q_per_query) {
            if (!Canonical(q)) return false;
        }
    }
    for (const auto& q : terminals.source_parent_q) {
        if (!Canonical(q)) return false;
    }
    return true;
}

RootU32ColumnsV1 AllocateRoot(uint32_t& next)
{
    RootU32ColumnsV1 out;
    for (uint32_t& limb : out.limb) limb = next++;
    return out;
}

TerminalColumnRefsV1 AllocateTerminalRefs(uint32_t& next)
{
    TerminalColumnRefsV1 out;
    out.common.row_kind = next++;
    out.common.active = next++;
    out.common.query_counter = next++;
    out.common.coverage_counter = next++;
    out.source.source_identity = AllocateRoot(next);
    out.source.query_schedule = AllocateRoot(next);
    out.source.exact_set_manifest_root = AllocateRoot(next);
    out.source.query_index = next++;
    out.source.parent_q = next++;
    for (auto& receipt : out.receipts) {
        receipt.source_identity = AllocateRoot(next);
        receipt.query_schedule = AllocateRoot(next);
        receipt.exact_set_manifest_root = AllocateRoot(next);
        receipt.statement_root = AllocateRoot(next);
        receipt.receipt_root = AllocateRoot(next);
        receipt.query_index = next++;
        receipt.source_parent_q = next++;
        receipt.local_q = next++;
        receipt.manifest_present = next++;
        receipt.receipt_ordinal = next++;
        receipt.receipt_position = next++;
        receipt.program_ordinal = next++;
    }
    return out;
}

void CollectRoot(
    const RootU32ColumnsV1& root,
    std::vector<uint32_t>& out)
{
    out.insert(out.end(), root.limb.begin(), root.limb.end());
}

std::vector<uint32_t> CollectTerminalRefs(
    const TerminalColumnRefsV1& refs)
{
    std::vector<uint32_t> out{
        refs.common.row_kind,
        refs.common.active,
        refs.common.query_counter,
        refs.common.coverage_counter,
    };
    CollectRoot(refs.source.source_identity, out);
    CollectRoot(refs.source.query_schedule, out);
    CollectRoot(refs.source.exact_set_manifest_root, out);
    out.push_back(refs.source.query_index);
    out.push_back(refs.source.parent_q);
    for (const auto& receipt : refs.receipts) {
        CollectRoot(receipt.source_identity, out);
        CollectRoot(receipt.query_schedule, out);
        CollectRoot(receipt.exact_set_manifest_root, out);
        CollectRoot(receipt.statement_root, out);
        CollectRoot(receipt.receipt_root, out);
        out.push_back(receipt.query_index);
        out.push_back(receipt.source_parent_q);
        out.push_back(receipt.local_q);
        out.push_back(receipt.manifest_present);
        out.push_back(receipt.receipt_ordinal);
        out.push_back(receipt.receipt_position);
        out.push_back(receipt.program_ordinal);
    }
    return out;
}

bool ValidDirectRefs(
    const TerminalColumnRefsV1& refs,
    const AirCS& cs)
{
    const auto all = CollectTerminalRefs(refs);
    if (all.empty()) return false;
    std::set<uint32_t> unique;
    for (uint32_t column : all) {
        const bool preprocessed = std::any_of(
            cs.preprocessed.begin(),
            cs.preprocessed.end(),
            [column](const auto& item) {
                return item.first == column;
            });
        if (column >= cs.n_columns ||
            preprocessed ||
            !unique.insert(column).second) {
            return false;
        }
    }
    return true;
}

void SetRoot(
    std::vector<std::vector<gf::Fp3>>& columns,
    const RootU32ColumnsV1& refs,
    uint32_t row,
    const uint256& root)
{
    const auto limbs = RootLimbs(root);
    for (uint32_t limb = 0; limb < limbs.size(); ++limb) {
        columns[refs.limb[limb]][row] = U32(limbs[limb]);
    }
}

void SetReceiptRoots(
    std::vector<std::vector<gf::Fp3>>& columns,
    const ReceiptColumnsV1& refs,
    uint32_t row,
    const ReceiptStatementV1& receipt)
{
    SetRoot(columns, refs.source_identity, row, receipt.source_identity);
    SetRoot(columns, refs.query_schedule, row, receipt.query_schedule);
    SetRoot(
        columns, refs.exact_set_manifest_root, row,
        receipt.exact_set_manifest_root);
    SetRoot(columns, refs.statement_root, row, receipt.statement_root);
    SetRoot(columns, refs.receipt_root, row, receipt.receipt_root);
}

void MaterializeTerminalTable(
    const DirectParentStatementV1& shape,
    const DirectParentTerminalExportsV1& terminal,
    const TerminalColumnRefsV1& refs,
    uint32_t rows,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    const uint32_t query_rows =
        static_cast<uint32_t>(shape.query_indices.size());
    const uint32_t manifest_rows = shape.total_program_ordinals;
    const uint32_t active_rows = query_rows + manifest_rows;

    for (uint32_t row = 0; row < active_rows; ++row) {
        columns[refs.common.active][row] = gf::Fp3::One();
        columns[refs.common.row_kind][row] =
            U32(row < query_rows ? kRowQuery : kRowManifest);
        SetRoot(
            columns, refs.source.source_identity, row,
            terminal.source_identity);
        SetRoot(
            columns, refs.source.query_schedule, row,
            terminal.query_schedule);
        SetRoot(
            columns, refs.source.exact_set_manifest_root, row,
            terminal.exact_set_manifest_root);
        for (uint32_t child = 0;
             child < kDirectParentSpineArityV1; ++child) {
            SetReceiptRoots(
                columns, refs.receipts[child], row,
                terminal.receipts[child]);
        }
    }

    for (uint32_t row = 0; row < query_rows; ++row) {
        columns[refs.common.query_counter][row] = U32(row);
        columns[refs.source.query_index][row] =
            U32(terminal.query_indices[row]);
        columns[refs.source.parent_q][row] =
            terminal.source_parent_q[row];
        for (uint32_t child = 0;
             child < kDirectParentSpineArityV1; ++child) {
            const auto& receipt = terminal.receipts[child];
            const auto& child_refs = refs.receipts[child];
            columns[child_refs.query_index][row] =
                U32(receipt.query_indices[row]);
            columns[child_refs.source_parent_q][row] =
                receipt.source_parent_q[row];
            columns[child_refs.local_q][row] =
                receipt.local_q_per_query[row];
        }
    }

    uint32_t coverage = 0;
    for (uint32_t child = 0;
         child < kDirectParentSpineArityV1; ++child) {
        const auto& receipt = terminal.receipts[child];
        const auto& child_refs = refs.receipts[child];
        for (uint32_t position = 0;
             position < receipt.program_ordinals.size();
             ++position, ++coverage) {
            const uint32_t row = query_rows + coverage;
            columns[refs.common.coverage_counter][row] =
                U32(coverage);
            columns[child_refs.manifest_present][row] =
                gf::Fp3::One();
            columns[child_refs.receipt_ordinal][row] =
                U32(receipt.receipt_ordinal);
            columns[child_refs.receipt_position][row] =
                U32(position);
            columns[child_refs.program_ordinal][row] =
                U32(receipt.program_ordinals[position]);
        }
    }

    // All cells beyond `active_rows` remain canonical zero.  The AIR equality
    // to the expected table makes padding smuggling a proved violation.
    (void)rows;
}

DirectParentTerminalExportsV1 ExpectedTerminals(
    const DirectParentStatementV1& statement)
{
    DirectParentTerminalExportsV1 out;
    out.source_identity = statement.source_identity;
    out.query_schedule = statement.query_schedule;
    out.exact_set_manifest_root = statement.exact_set_manifest_root;
    out.query_indices = statement.query_indices;
    out.source_parent_q = statement.source_parent_q;
    out.receipts = statement.receipts;
    return out;
}

void AppendPreprocessed(
    AirCS& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const std::vector<uint32_t>& refs)
{
    for (uint32_t column : refs) {
        cs.preprocessed.emplace_back(column, columns[column]);
    }
    cs.preprocessed_pin_ood = true;
}

void AddEquality(
    AirCS& cs,
    uint32_t actual,
    uint32_t expected,
    const char* name)
{
    AirConstraint c;
    c.name = name;
    c.kind = aq::AirKind::kEverywhere;
    c.alg_degree = 1;
    c.eval = [actual, expected](
                 const std::vector<gf::Fp3>& current,
                 const std::vector<gf::Fp3>&) {
        return gf::Sub(current[actual], current[expected]);
    };
    cs.constraints.push_back(std::move(c));
}

void AddRootEquality(
    AirCS& cs,
    const RootU32ColumnsV1& actual,
    const RootU32ColumnsV1& expected,
    const char* name)
{
    for (uint32_t limb = 0; limb < 8; ++limb) {
        AddEquality(
            cs, actual.limb[limb], expected.limb[limb], name);
    }
}

void AddWholeTableEquality(
    AirCS& cs,
    const TerminalColumnRefsV1& actual,
    const TerminalColumnRefsV1& expected)
{
    const auto a = CollectTerminalRefs(actual);
    const auto e = CollectTerminalRefs(expected);
    for (size_t i = 0; i < a.size(); ++i) {
        AddEquality(
            cs, a[i], e[i],
            "stage3.direct_parent.terminal_row_exact_equality");
    }
}

void AddSemanticConstraints(
    AirCS& cs,
    const DirectParentSpineLayoutV1& layout)
{
    const auto& a = layout.actual;

    // These are explicit relation constraints in addition to the complete
    // row-table equality.  They continue to express the intended ownership
    // relation when the `actual` columns become direct child aliases.
    for (const auto& receipt : a.receipts) {
        AddRootEquality(
            cs, receipt.source_identity,
            a.source.source_identity,
            "stage3.direct_parent.shared_source_identity");
        AddRootEquality(
            cs, receipt.query_schedule,
            a.source.query_schedule,
            "stage3.direct_parent.shared_query_schedule");
        AddRootEquality(
            cs, receipt.exact_set_manifest_root,
            a.source.exact_set_manifest_root,
            "stage3.direct_parent.shared_exact_set_manifest");
    }

    for (const auto& receipt : a.receipts) {
        AirConstraint query_index;
        query_index.name =
            "stage3.direct_parent.same_query_index";
        query_index.kind = aq::AirKind::kEverywhere;
        query_index.alg_degree = 2;
        const uint32_t is_query = layout.is_query;
        const uint32_t child_query = receipt.query_index;
        const uint32_t source_query = a.source.query_index;
        query_index.eval =
            [is_query, child_query, source_query](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[is_query],
                    gf::Sub(
                        current[child_query],
                        current[source_query]));
            };
        cs.constraints.push_back(std::move(query_index));

        AirConstraint source_q;
        source_q.name =
            "stage3.direct_parent.same_source_q";
        source_q.kind = aq::AirKind::kEverywhere;
        source_q.alg_degree = 2;
        const uint32_t child_source_q = receipt.source_parent_q;
        const uint32_t parent_q = a.source.parent_q;
        source_q.eval =
            [is_query, child_source_q, parent_q](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[is_query],
                    gf::Sub(
                        current[child_source_q],
                        current[parent_q]));
            };
        cs.constraints.push_back(std::move(source_q));
    }

    AirConstraint q_join;
    q_join.name =
        "stage3.direct_parent.q_left_plus_q_right";
    q_join.kind = aq::AirKind::kEverywhere;
    q_join.alg_degree = 2;
    const uint32_t is_query = layout.is_query;
    const uint32_t q_left = a.receipts[0].local_q;
    const uint32_t q_right = a.receipts[1].local_q;
    const uint32_t source_q = a.source.parent_q;
    q_join.eval =
        [is_query, q_left, q_right, source_q](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[is_query],
                gf::Sub(
                    gf::Add(
                        current[q_left], current[q_right]),
                    current[source_q]));
        };
    cs.constraints.push_back(std::move(q_join));

    AirConstraint present;
    present.name =
        "stage3.direct_parent.exact_one_manifest_owner";
    present.kind = aq::AirKind::kEverywhere;
    present.alg_degree = 1;
    const uint32_t is_manifest = layout.is_manifest;
    const uint32_t present_left =
        a.receipts[0].manifest_present;
    const uint32_t present_right =
        a.receipts[1].manifest_present;
    present.eval =
        [is_manifest, present_left, present_right](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                gf::Add(
                    current[present_left],
                    current[present_right]),
                current[is_manifest]);
        };
    cs.constraints.push_back(std::move(present));

    for (uint32_t child = 0;
         child < kDirectParentSpineArityV1; ++child) {
        AirConstraint boolean;
        boolean.name =
            "stage3.direct_parent.manifest_owner_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        const uint32_t column =
            a.receipts[child].manifest_present;
        boolean.eval =
            [column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[column],
                    gf::Sub(
                        current[column], gf::Fp3::One()));
            };
        cs.constraints.push_back(std::move(boolean));
    }

    const auto selected = [receipts = a.receipts](
        const std::vector<gf::Fp3>& row,
        uint32_t ReceiptColumnsV1::*member) {
        return gf::Add(
            row[receipts[0].*member],
            row[receipts[1].*member]);
    };

    AirConstraint first;
    first.name =
        "stage3.direct_parent.coverage_chain_first";
    first.kind = aq::AirKind::kEverywhere;
    first.alg_degree = 2;
    const uint32_t first_selector = layout.manifest_first;
    first.eval =
        [first_selector, selected](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            const auto slot = selected(
                current, &ReceiptColumnsV1::receipt_ordinal);
            const auto position = selected(
                current, &ReceiptColumnsV1::receipt_position);
            return gf::Mul(
                current[first_selector],
                gf::Add(slot, position));
        };
    cs.constraints.push_back(std::move(first));

    AirConstraint last;
    last.name =
        "stage3.direct_parent.coverage_chain_last";
    last.kind = aq::AirKind::kEverywhere;
    last.alg_degree = 2;
    const uint32_t last_selector = layout.manifest_last;
    last.eval =
        [last_selector, selected](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            const auto slot = selected(
                current, &ReceiptColumnsV1::receipt_ordinal);
            return gf::Mul(
                current[last_selector],
                gf::Sub(slot, gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(last));

    AirConstraint slot_step;
    slot_step.name =
        "stage3.direct_parent.coverage_chain_slot_step";
    slot_step.kind = aq::AirKind::kEverywhere;
    slot_step.alg_degree = 3;
    const uint32_t has_next = layout.manifest_has_next;
    slot_step.eval =
        [has_next, selected](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>& next) {
            const auto slot = selected(
                current, &ReceiptColumnsV1::receipt_ordinal);
            const auto slot_next = selected(
                next, &ReceiptColumnsV1::receipt_ordinal);
            const auto delta = gf::Sub(slot_next, slot);
            return gf::Mul(
                current[has_next],
                gf::Mul(
                    delta,
                    gf::Sub(delta, gf::Fp3::One())));
        };
    cs.constraints.push_back(std::move(slot_step));

    AirConstraint position_step;
    position_step.name =
        "stage3.direct_parent.coverage_chain_position_step";
    position_step.kind = aq::AirKind::kEverywhere;
    position_step.alg_degree = 3;
    position_step.eval =
        [has_next, selected](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>& next) {
            const auto slot = selected(
                current, &ReceiptColumnsV1::receipt_ordinal);
            const auto slot_next = selected(
                next, &ReceiptColumnsV1::receipt_ordinal);
            const auto delta = gf::Sub(slot_next, slot);
            const auto position = selected(
                current, &ReceiptColumnsV1::receipt_position);
            const auto position_next = selected(
                next, &ReceiptColumnsV1::receipt_position);
            const auto expected_next =
                gf::Mul(
                    gf::Sub(gf::Fp3::One(), delta),
                    gf::Add(position, gf::Fp3::One()));
            return gf::Mul(
                current[has_next],
                gf::Sub(position_next, expected_next));
        };
    cs.constraints.push_back(std::move(position_step));
}

} // namespace

bool ValidateDirectParentStatementV1(
    const DirectParentStatementV1& statement,
    std::string* why)
{
    if (statement.version !=
            kDirectParentSpineVersionV1 ||
        statement.total_program_ordinals < 2 ||
        statement.source_identity.IsNull() ||
        statement.query_schedule.IsNull() ||
        statement.exact_set_manifest_root.IsNull() ||
        !UniqueSchedule(statement.query_indices) ||
        statement.source_parent_q.size() !=
            statement.query_indices.size()) {
        return Fail(why, "statement_shape");
    }
    for (const auto& q : statement.source_parent_q) {
        if (!Canonical(q)) return Fail(why, "source_q_noncanonical");
    }

    std::vector<uint32_t> exact_set;
    exact_set.reserve(statement.total_program_ordinals);
    for (uint32_t child = 0;
         child < kDirectParentSpineArityV1; ++child) {
        const auto& receipt = statement.receipts[child];
        if (receipt.receipt_ordinal != child ||
            receipt.source_identity != statement.source_identity ||
            receipt.query_schedule != statement.query_schedule ||
            receipt.exact_set_manifest_root !=
                statement.exact_set_manifest_root ||
            receipt.statement_root.IsNull() ||
            receipt.receipt_root.IsNull() ||
            receipt.query_indices != statement.query_indices ||
            receipt.source_parent_q.size() !=
                statement.source_parent_q.size() ||
            receipt.local_q_per_query.size() !=
                statement.source_parent_q.size() ||
            receipt.program_ordinals.empty() ||
            !std::is_sorted(
                receipt.program_ordinals.begin(),
                receipt.program_ordinals.end()) ||
            std::adjacent_find(
                receipt.program_ordinals.begin(),
                receipt.program_ordinals.end()) !=
                receipt.program_ordinals.end() ||
            !SameFp3(
                receipt.source_parent_q,
                statement.source_parent_q)) {
            return Fail(why, "receipt_statement_shape");
        }
        for (const auto& q : receipt.local_q_per_query) {
            if (!Canonical(q)) {
                return Fail(why, "local_q_noncanonical");
            }
        }
        exact_set.insert(
            exact_set.end(),
            receipt.program_ordinals.begin(),
            receipt.program_ordinals.end());
    }
    if (exact_set.size() != statement.total_program_ordinals) {
        return Fail(why, "exact_set_count");
    }
    std::sort(exact_set.begin(), exact_set.end());
    for (uint32_t ordinal = 0;
         ordinal < exact_set.size(); ++ordinal) {
        if (exact_set[ordinal] != ordinal) {
            return Fail(why, "exact_set_union");
        }
    }
    for (size_t query = 0;
         query < statement.source_parent_q.size(); ++query) {
        if (!gf::Eq(
                gf::Add(
                    statement.receipts[0]
                        .local_q_per_query[query],
                    statement.receipts[1]
                        .local_q_per_query[query]),
                statement.source_parent_q[query])) {
            return Fail(why, "q_partition");
        }
    }
    if (why != nullptr) {
        *why = "stage3:direct_parent_spine:statement_ok";
    }
    return true;
}

bool AppendDirectParentSpineV1(
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const DirectParentStatementV1& statement,
    const DirectParentTerminalExportsV1& terminals,
    DirectParentSpineAppendV1& out,
    const TerminalColumnRefsV1* direct_actual,
    std::string* why)
{
    out = {};
    if (!ValidateDirectParentStatementV1(statement, why)) return false;
    if (parent_cs.n_rows < 2 ||
        (parent_cs.n_rows &
             (parent_cs.n_rows - 1)) != 0 ||
        parent_columns.size() != parent_cs.n_columns ||
        !ShapeMatches(statement, terminals)) {
        return Fail(why, "parent_or_terminal_shape");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "parent_column_rows");
        }
    }
    const uint64_t active_rows =
        static_cast<uint64_t>(statement.query_indices.size()) +
        statement.total_program_ordinals;
    if (active_rows > parent_cs.n_rows) {
        return Fail(why, "terminal_rows_exceed_parent");
    }

    DirectParentSpineLayoutV1 layout;
    layout.original_columns = parent_cs.n_columns;
    layout.terminal_rows = parent_cs.n_rows;
    layout.query_rows =
        static_cast<uint32_t>(statement.query_indices.size());
    layout.manifest_rows = statement.total_program_ordinals;
    layout.padding_rows =
        parent_cs.n_rows - static_cast<uint32_t>(active_rows);

    if (direct_actual != nullptr) {
        if (!ValidDirectRefs(
                *direct_actual, parent_cs)) {
            return Fail(why, "direct_alias_column_refs");
        }
        layout.actual = *direct_actual;
    } else {
        uint32_t next = parent_cs.n_columns;
        layout.actual = AllocateTerminalRefs(next);
        parent_cs.n_columns = next;
        parent_columns.resize(
            next,
            std::vector<gf::Fp3>(
                parent_cs.n_rows, gf::Fp3::Zero()));
        MaterializeTerminalTable(
            statement, terminals, layout.actual,
            parent_cs.n_rows, parent_columns);
        AppendPreprocessed(
            parent_cs, parent_columns,
            CollectTerminalRefs(layout.actual));
    }

    uint32_t next = parent_cs.n_columns;
    layout.expected = AllocateTerminalRefs(next);
    layout.is_query = next++;
    layout.is_manifest = next++;
    layout.is_padding = next++;
    layout.manifest_first = next++;
    layout.manifest_last = next++;
    layout.manifest_has_next = next++;
    layout.end_column = next;
    parent_cs.n_columns = next;
    parent_columns.resize(
        next,
        std::vector<gf::Fp3>(
            parent_cs.n_rows, gf::Fp3::Zero()));

    const auto expected = ExpectedTerminals(statement);
    MaterializeTerminalTable(
        statement, expected, layout.expected,
        parent_cs.n_rows, parent_columns);

    const uint32_t q_rows = layout.query_rows;
    const uint32_t manifest_end =
        q_rows + layout.manifest_rows;
    for (uint32_t row = 0; row < parent_cs.n_rows; ++row) {
        if (row < q_rows) {
            parent_columns[layout.is_query][row] =
                gf::Fp3::One();
        } else if (row < manifest_end) {
            parent_columns[layout.is_manifest][row] =
                gf::Fp3::One();
            if (row == q_rows) {
                parent_columns[layout.manifest_first][row] =
                    gf::Fp3::One();
            }
            if (row + 1 == manifest_end) {
                parent_columns[layout.manifest_last][row] =
                    gf::Fp3::One();
            }
            if (row + 1 < manifest_end) {
                parent_columns[layout.manifest_has_next][row] =
                    gf::Fp3::One();
            }
        } else {
            parent_columns[layout.is_padding][row] =
                gf::Fp3::One();
        }
    }
    auto expected_refs = CollectTerminalRefs(layout.expected);
    expected_refs.push_back(layout.is_query);
    expected_refs.push_back(layout.is_manifest);
    expected_refs.push_back(layout.is_padding);
    expected_refs.push_back(layout.manifest_first);
    expected_refs.push_back(layout.manifest_last);
    expected_refs.push_back(layout.manifest_has_next);
    AppendPreprocessed(parent_cs, parent_columns, expected_refs);

    AddWholeTableEquality(
        parent_cs, layout.actual, layout.expected);
    AddSemanticConstraints(parent_cs, layout);

    // If caller supplied direct references, verify that the witness passed to
    // this append operation is exactly the advertised terminal export.  This
    // is a construction-time consistency check; AIR row equality remains the
    // cryptographic constraint.
    if (direct_actual != nullptr) {
        std::vector<std::vector<gf::Fp3>> expected_actual(
            parent_cs.n_columns,
            std::vector<gf::Fp3>(
                parent_cs.n_rows, gf::Fp3::Zero()));
        MaterializeTerminalTable(
            statement, terminals, layout.actual,
            parent_cs.n_rows, expected_actual);
        for (uint32_t column :
             CollectTerminalRefs(layout.actual)) {
            for (uint32_t row = 0;
                 row < parent_cs.n_rows; ++row) {
                const auto& actual =
                    parent_columns[column][row];
                const auto& expected_value =
                    expected_actual[column][row];
                if (!Canonical(actual) ||
                    actual.c0 != expected_value.c0 ||
                    actual.c1 != expected_value.c1 ||
                    actual.c2 != expected_value.c2) {
                    return Fail(
                        why, "direct_alias_terminal_values");
                }
            }
        }
    }

    out.valid = true;
    out.statement_exact_set = true;
    out.statement_q_partition = true;
    out.terminal_row_equality_constrained = true;
    out.ordered_receipt_coverage_constrained = true;
    out.source_identity_constrained = true;
    out.query_schedule_constrained = true;
    out.source_q_constrained = true;
    out.local_q_join_constrained = true;
    out.padding_zero_constrained = true;
    out.preprocessed_fallback = direct_actual == nullptr;
    out.actual_columns_reused = direct_actual != nullptr;
    out.all_actual_inputs_verifier_owned =
        direct_actual == nullptr;
    out.direct_alias_capable = true;
    out.direct_child_aliases = false;
    out.recursively_consumed = false;
    out.no_free_binding_or_q_witness =
        direct_actual == nullptr;
    out.layout = layout;
    out.note =
        direct_actual == nullptr
        ? "appendable ownership spine green via public/preprocessed "
          "fallback; direct child aliases and recursive consumption remain"
        : "appendable ownership spine reuses parent columns; child-verifier "
          "alias provenance and recursive consumption remain";
    if (why != nullptr) {
        *why = "stage3:direct_parent_spine:append_ok";
    }
    return true;
}

namespace {

namespace cb = constraint_bytecode;
namespace bridge = semantic_endpoint_program_bridge;
namespace rpj = recursive_provenance_join;
namespace temporal = stage3_temporal;

constexpr char kConsumerScheduleDomain[] =
    "BTX_RC_STAGE3_CANONICAL_PROVENANCE_CONSUMER_SCHEDULE_V1";
constexpr char kConsumerRoleRouteDomain[] =
    "BTX_RC_STAGE3_CANONICAL_PROVENANCE_CONSUMER_ROLE_ROUTE_V1";

struct ConsumerExpr {
    std::vector<cb::Instruction> instructions;
    std::vector<uint32_t> degree;

    uint32_t Current(uint32_t column)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Current;
        in.lhs = column;
        instructions.push_back(in);
        degree.push_back(1);
        return static_cast<uint32_t>(instructions.size()) - 1U;
    }

    uint32_t Constant(const gf::Fp3& value)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Constant;
        in.constant = value;
        instructions.push_back(in);
        degree.push_back(0);
        return static_cast<uint32_t>(instructions.size()) - 1U;
    }

    uint32_t Binary(
        cb::Opcode opcode, uint32_t lhs, uint32_t rhs)
    {
        cb::Instruction in;
        in.opcode = opcode;
        in.lhs = lhs;
        in.rhs = rhs;
        instructions.push_back(in);
        degree.push_back(
            opcode == cb::Opcode::Mul
                ? degree[lhs] + degree[rhs]
                : std::max(degree[lhs], degree[rhs]));
        return static_cast<uint32_t>(instructions.size()) - 1U;
    }

    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Add, lhs, rhs);
    }
    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Sub, lhs, rhs);
    }
    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Mul, lhs, rhs);
    }
};

template <typename Build>
void AppendConsumerProgram(
    cb::ProgramTable& table, Build&& build)
{
    ConsumerExpr expr;
    build(expr);
    cb::Program program;
    program.version = cb::kConstraintBytecodeVersion;
    program.role = RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal =
        static_cast<uint32_t>(table.programs.size());
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = expr.degree.back();
    program.current_width = table.current_width;
    program.next_width = table.next_width;
    program.challenge_width = 0;
    program.instructions = std::move(expr.instructions);
    table.programs.push_back(std::move(program));
}

CanonicalProvenanceConsumerLayoutV1 ConsumerLayout(
    uint32_t base)
{
    CanonicalProvenanceConsumerLayoutV1 out;
    out.base = base;
    uint32_t next = base;
    out.active = next++;
    out.row_kind = next++;
    out.role = next++;
    out.endpoint = next++;
    out.event_kind = next++;
    out.producer = next++;
    out.consumer = next++;
    out.producer_position = next++;
    out.consumer_position = next++;
    out.ordinal = next++;
    out.family_index = next++;
    out.relation_column = next++;
    out.route_status = next++;
    for (auto& column : out.program_external) column = next++;
    for (auto& column : out.program_recursive) column = next++;
    for (auto& column : out.root_word) column = next++;
    out.root_bits_base = next;
    next +=
        kCanonicalProvenanceConsumerRootWordsV1 *
        kCanonicalProvenanceConsumerWordBitsV1;
    out.expected_base = next;
    next += 13U + 2U * 8U;
    out.end_column = next;
    return out;
}

std::vector<uint32_t> ConsumerMetadataColumns(
    const CanonicalProvenanceConsumerLayoutV1& layout)
{
    std::vector<uint32_t> out{
        layout.active,
        layout.row_kind,
        layout.role,
        layout.endpoint,
        layout.event_kind,
        layout.producer,
        layout.consumer,
        layout.producer_position,
        layout.consumer_position,
        layout.ordinal,
        layout.family_index,
        layout.relation_column,
        layout.route_status};
    out.insert(
        out.end(),
        layout.program_external.begin(),
        layout.program_external.end());
    out.insert(
        out.end(),
        layout.program_recursive.begin(),
        layout.program_recursive.end());
    return out;
}

bool BuildConsumerProgramTable(
    const CanonicalProvenanceConsumerLayoutV1& layout,
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = layout.end_column;
    out.next_width = layout.end_column;
    out.challenge_width = 0;

    const auto metadata = ConsumerMetadataColumns(layout);
    for (uint32_t i = 0; i < metadata.size(); ++i) {
        const uint32_t actual = metadata[i];
        const uint32_t expected = layout.expected_base + i;
        AppendConsumerProgram(
            out,
            [actual, expected](ConsumerExpr& e) {
                e.Sub(e.Current(actual), e.Current(expected));
            });
    }
    AppendConsumerProgram(
        out,
        [active = layout.active](ConsumerExpr& e) {
            const uint32_t value = e.Current(active);
            e.Mul(
                value,
                e.Sub(
                    value,
                    e.Constant(gf::Fp3::One())));
        });
    for (uint32_t word = 0;
         word < kCanonicalProvenanceConsumerRootWordsV1;
         ++word) {
        for (uint32_t bit = 0;
             bit < kCanonicalProvenanceConsumerWordBitsV1;
             ++bit) {
            const uint32_t column =
                layout.root_bits_base +
                word *
                    kCanonicalProvenanceConsumerWordBitsV1 +
                bit;
            AppendConsumerProgram(
                out,
                [column](ConsumerExpr& e) {
                    const uint32_t value = e.Current(column);
                    e.Mul(
                        value,
                        e.Sub(
                            value,
                        e.Constant(gf::Fp3::One())));
                });
        }
        AppendConsumerProgram(
            out,
            [layout, word](ConsumerExpr& e) {
                uint32_t sum =
                    e.Constant(gf::Fp3::Zero());
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit <
                        kCanonicalProvenanceConsumerWordBitsV1;
                     ++bit) {
                    const uint32_t column =
                        layout.root_bits_base +
                        word *
                            kCanonicalProvenanceConsumerWordBitsV1 +
                        bit;
                    sum = e.Add(
                        sum,
                        e.Mul(
                            e.Constant(U32(
                                static_cast<uint32_t>(
                                    weight))),
                            e.Current(column)));
                    weight <<= 1U;
                }
                e.Sub(
                    e.Current(layout.root_word[word]),
                    sum);
            });
        AppendConsumerProgram(
            out,
            [layout, word](ConsumerExpr& e) {
                const uint32_t inactive = e.Sub(
                    e.Constant(gf::Fp3::One()),
                    e.Current(layout.active));
                e.Mul(
                    inactive,
                    e.Current(layout.root_word[word]));
            });
    }
    return cb::ValidateProgramTable(out, why);
}

std::array<uint32_t, 8> Uint256Words(const uint256& value)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 1]) << 8U) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 2]) << 16U) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 3]) << 24U);
    }
    return out;
}

uint32_t RouteStatus(
    const bridge::SemanticEndpointProgramBindingV1& route)
{
    return
        (static_cast<uint32_t>(route.selected_program_key) << 0U) |
        (static_cast<uint32_t>(route.exact_program_table_match) << 1U) |
        (static_cast<uint32_t>(route.registry_semantic_claim) << 2U) |
        (static_cast<uint32_t>(route.canonical_output_metadata) << 3U) |
        (static_cast<uint32_t>(route.executed_relation_cell) << 4U) |
        (static_cast<uint32_t>(route.relation_column_exact) << 5U) |
        (static_cast<uint32_t>(route.same_trace_ctl_alias) << 6U) |
        (static_cast<uint32_t>(route.direct_alias_ready) << 7U) |
        (static_cast<uint32_t>(route.recursive_child_accepted) << 8U);
}

struct ConsumerRow {
    uint32_t active{0};
    uint32_t row_kind{0};
    uint32_t role{0};
    uint32_t endpoint{0};
    uint32_t event_kind{0};
    uint32_t producer{0};
    uint32_t consumer{0};
    uint32_t producer_position{0};
    uint32_t consumer_position{0};
    uint32_t ordinal{0};
    uint32_t family_index{UINT32_MAX};
    uint32_t relation_column{UINT32_MAX};
    uint32_t route_status{0};
    std::array<uint32_t, 8> external{};
    std::array<uint32_t, 8> recursive{};
};

std::array<uint32_t, 8> RoleRouteWords(
    RCStage3RelationRole role,
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    const char* suffix)
{
    HashWriter hash;
    hash << std::string(kConsumerRoleRouteDomain)
         << std::string(suffix)
         << static_cast<uint16_t>(role)
         << manifest.bridge_commitment;
    for (const auto& endpoint : manifest.endpoints) {
        if (endpoint.role != role) continue;
        hash << static_cast<uint16_t>(endpoint.endpoint)
             << endpoint.endpoint_ordinal
             << endpoint.family_index
             << endpoint.relation_column
             << RouteStatus(endpoint);
        for (uint32_t word :
             endpoint.program_external_sha256d_words) {
            hash << word;
        }
        for (uint32_t word :
             endpoint.program_recursive_alg_hash_words) {
            hash << word;
        }
    }
    return Uint256Words(hash.GetHash());
}

const bridge::SemanticEndpointProgramBindingV1* FindRoute(
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        manifest.endpoints.begin(),
        manifest.endpoints.end(),
        [endpoint](const auto& route) {
            return route.endpoint == endpoint;
        });
    return found == manifest.endpoints.end() ? nullptr : &*found;
}

bool BuildConsumerRows(
    const rpj::RecursiveProvenanceShapeV1& shape,
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    std::vector<rpj::RecursiveProvenanceEventKeyV1>& events,
    std::vector<ConsumerRow>& rows,
    std::string* why)
{
    if (!bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            manifest, why) ||
        !rpj::BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, events, why)) {
        return false;
    }
    rows.clear();
    const auto& roles =
        rpj::CanonicalRecursiveProvenanceRoleOrderV1();
    for (uint32_t ordinal = 0;
         ordinal < roles.size(); ++ordinal) {
        ConsumerRow row;
        row.active = 1;
        row.row_kind = static_cast<uint32_t>(
            CanonicalProvenanceConsumerRowKindV1::Role);
        row.role = static_cast<uint32_t>(roles[ordinal]);
        row.ordinal = ordinal;
        row.external =
            RoleRouteWords(roles[ordinal], manifest, "external");
        row.recursive =
            RoleRouteWords(roles[ordinal], manifest, "recursive");
        rows.push_back(std::move(row));
    }
    for (const auto& route : manifest.endpoints) {
        ConsumerRow row;
        row.active = 1;
        row.row_kind = static_cast<uint32_t>(
            CanonicalProvenanceConsumerRowKindV1::Endpoint);
        row.role = static_cast<uint32_t>(route.role);
        row.endpoint = static_cast<uint32_t>(route.endpoint);
        row.ordinal = route.endpoint_ordinal;
        row.family_index = route.family_index;
        row.relation_column = route.relation_column;
        row.route_status = RouteStatus(route);
        row.external =
            route.program_external_sha256d_words;
        row.recursive =
            route.program_recursive_alg_hash_words;
        rows.push_back(std::move(row));
    }
    for (uint32_t ordinal = 0;
         ordinal < events.size(); ++ordinal) {
        const auto& event = events[ordinal];
        const auto* route = FindRoute(manifest, event.consumer);
        if (route == nullptr) {
            return Fail(why, "consumer_event_route");
        }
        ConsumerRow row;
        row.active = 1;
        row.row_kind = static_cast<uint32_t>(
            CanonicalProvenanceConsumerRowKindV1::TemporalEvent);
        row.role = static_cast<uint32_t>(route->role);
        row.endpoint = static_cast<uint32_t>(event.consumer);
        row.event_kind = static_cast<uint32_t>(event.kind);
        row.producer = static_cast<uint32_t>(event.producer);
        row.consumer = static_cast<uint32_t>(event.consumer);
        row.producer_position = event.producer_position;
        row.consumer_position = event.consumer_position;
        row.ordinal = ordinal;
        row.family_index = route->family_index;
        row.relation_column = route->relation_column;
        row.route_status = RouteStatus(*route);
        row.external = route->program_external_sha256d_words;
        row.recursive = route->program_recursive_alg_hash_words;
        rows.push_back(std::move(row));
    }
    return true;
}

bool RootRefUnset(
    const rpj::RecursiveProvenanceParentRootRefV1& root)
{
    return std::all_of(
        root.limb.begin(), root.limb.end(),
        [](const auto& cell) {
            return cell.column == UINT32_MAX &&
                cell.row == UINT32_MAX;
        });
}

bool ValidSourceRefs(
    const rpj::RecursiveProvenanceShapeV1& shape,
    const rpj::RecursiveProvenanceParentAliasRefsV1& refs,
    const std::vector<rpj::RecursiveProvenanceEventKeyV1>& events)
{
    if (refs.version != rpj::kRecursiveProvenanceJoinVersionV1 ||
        refs.parent_rows < 2 ||
        refs.parent_original_columns == 0 ||
        refs.events.size() != events.size()) {
        return false;
    }
    std::set<uint64_t> cells;
    const auto valid_root =
        [&](const rpj::RecursiveProvenanceParentRootAliasV1& root) {
            if (!RootRefUnset(root.named_consumer)) return false;
            for (const auto& cell : root.verifier_output.limb) {
                if (cell.column >= refs.parent_original_columns ||
                    cell.row >= refs.parent_rows ||
                    !cells.insert(
                        (uint64_t{cell.column} << 32U) |
                        cell.row).second) {
                    return false;
                }
            }
            return true;
        };
    const auto& roles =
        rpj::CanonicalRecursiveProvenanceRoleOrderV1();
    for (uint32_t i = 0; i < refs.roles.size(); ++i) {
        if (refs.roles[i].role != roles[i] ||
            !valid_root(refs.roles[i].root)) {
            return false;
        }
    }
    const auto endpoint_audit =
        CurrentRCStage3RelationEndpointCellAudit();
    if (endpoint_audit.size() != refs.endpoints.size()) {
        return false;
    }
    for (uint32_t i = 0; i < refs.endpoints.size(); ++i) {
        if (refs.endpoints[i].endpoint !=
                endpoint_audit[i].endpoint ||
            refs.endpoints[i].role != endpoint_audit[i].role ||
            !valid_root(refs.endpoints[i].root)) {
            return false;
        }
    }
    for (uint32_t i = 0; i < refs.events.size(); ++i) {
        if (refs.events[i].key != events[i] ||
            !valid_root(refs.events[i].root)) {
            return false;
        }
    }
    (void)shape;
    return true;
}

rpj::RecursiveProvenanceParentRootRefV1 ConsumerRootRef(
    const CanonicalProvenanceConsumerLayoutV1& layout,
    uint32_t row)
{
    rpj::RecursiveProvenanceParentRootRefV1 out;
    for (uint32_t word = 0; word < out.limb.size(); ++word) {
        out.limb[word] = {layout.root_word[word], row};
    }
    return out;
}

bool JoinedRefs(
    const rpj::RecursiveProvenanceShapeV1& shape,
    const rpj::RecursiveProvenanceParentAliasRefsV1& sources,
    const CanonicalProvenanceConsumerLayoutV1& layout,
    const std::vector<rpj::RecursiveProvenanceEventKeyV1>& events,
    rpj::RecursiveProvenanceParentAliasRefsV1& out)
{
    if (!ValidSourceRefs(shape, sources, events)) return false;
    out = sources;
    out.parent_original_columns = layout.end_column;
    uint32_t row = 0;
    for (auto& role : out.roles) {
        role.root.named_consumer =
            ConsumerRootRef(layout, row++);
    }
    for (auto& endpoint : out.endpoints) {
        endpoint.root.named_consumer =
            ConsumerRootRef(layout, row++);
    }
    for (auto& event : out.events) {
        event.root.named_consumer =
            ConsumerRootRef(layout, row++);
    }
    return row <= sources.parent_rows;
}

uint256 ConsumerScheduleRoot(
    const rpj::RecursiveProvenanceShapeV1& shape,
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    const CanonicalProvenanceConsumerPlanV1& plan,
    const std::vector<ConsumerRow>& rows)
{
    HashWriter hash;
    hash << std::string(kConsumerScheduleDomain)
         << kCanonicalProvenanceConsumerVersionV1
         << shape.version
         << shape.episode_round_roots
         << shape.coupled_barriers
         << shape.coupled_lobes
         << shape.coupled_exchange_rounds
         << shape.episode_builder_params_root
         << shape.episode_header_target_root
         << manifest.production_site_manifest_commitment
         << manifest.bridge_commitment
         << plan.parent_rows
         << plan.parent_original_columns
         << plan.layout.base
         << plan.layout.end_column
         << plan.bytecode_program_root
         << plan.active_rows;
    for (const auto lane : plan.bytecode_program_alg_root) {
        hash << lane;
    }
    for (const auto& row : rows) {
        hash << row.active
             << row.row_kind
             << row.role
             << row.endpoint
             << row.event_kind
             << row.producer
             << row.consumer
             << row.producer_position
             << row.consumer_position
             << row.ordinal
             << row.family_index
             << row.relation_column
             << row.route_status;
        for (uint32_t word : row.external) hash << word;
        for (uint32_t word : row.recursive) hash << word;
    }
    return hash.GetHash();
}

bool IsPreprocessed(
    const AirCS& cs, uint32_t column)
{
    return std::any_of(
        cs.preprocessed.begin(), cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
}

bool ReadStrictRoot(
    const AirCS& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const rpj::RecursiveProvenanceParentRootRefV1& ref,
    temporal::TemporalRootU32V1& out,
    std::string* why)
{
    std::array<
        gf::Fp3,
        temporal::kTemporalRootWordsV1> lanes{};
    for (uint32_t word = 0; word < lanes.size(); ++word) {
        const auto cell = ref.limb[word];
        if (cell.column >= cs.n_columns ||
            cell.row >= cs.n_rows ||
            IsPreprocessed(cs, cell.column)) {
            return Fail(why, "consumer_source_ref");
        }
        lanes[word] = columns[cell.column][cell.row];
    }
    if (!temporal::DecodeCanonicalTemporalRootU32V1(
            lanes, out, why)) {
        return false;
    }
    return true;
}

void SetMetadata(
    const CanonicalProvenanceConsumerLayoutV1& layout,
    const ConsumerRow& row,
    uint32_t trace_row,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    const std::array<uint32_t, 13> values{{
        row.active,
        row.row_kind,
        row.role,
        row.endpoint,
        row.event_kind,
        row.producer,
        row.consumer,
        row.producer_position,
        row.consumer_position,
        row.ordinal,
        row.family_index,
        row.relation_column,
        row.route_status}};
    const auto metadata = ConsumerMetadataColumns(layout);
    uint32_t index = 0;
    for (uint32_t value : values) {
        columns[metadata[index]][trace_row] = U32(value);
        columns[layout.expected_base + index][trace_row] =
            U32(value);
        ++index;
    }
    for (uint32_t value : row.external) {
        columns[metadata[index]][trace_row] = U32(value);
        columns[layout.expected_base + index][trace_row] =
            U32(value);
        ++index;
    }
    for (uint32_t value : row.recursive) {
        columns[metadata[index]][trace_row] = U32(value);
        columns[layout.expected_base + index][trace_row] =
            U32(value);
        ++index;
    }
}

void SetConsumerRoot(
    const CanonicalProvenanceConsumerLayoutV1& layout,
    uint32_t row,
    const temporal::TemporalRootU32V1& root,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    for (uint32_t word = 0; word < root.words.size(); ++word) {
        const uint32_t value = root.words[word];
        columns[layout.root_word[word]][row] = U32(value);
        for (uint32_t bit = 0;
             bit < kCanonicalProvenanceConsumerWordBitsV1;
             ++bit) {
            columns[
                layout.root_bits_base +
                word *
                    kCanonicalProvenanceConsumerWordBitsV1 +
                bit][row] =
                U32((value >> bit) & 1U);
        }
    }
}

} // namespace

CanonicalProvenanceConsumerPlanV1
BuildCanonicalProvenanceConsumerPlanV1(
    const rpj::RecursiveProvenanceShapeV1& shape,
    const rpj::RecursiveProvenanceParentAliasRefsV1& verifier_sources)
{
    CanonicalProvenanceConsumerPlanV1 out;
    out.parent_rows = verifier_sources.parent_rows;
    out.parent_original_columns =
        verifier_sources.parent_original_columns;
    out.layout = ConsumerLayout(out.parent_original_columns);

    const auto manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    std::vector<rpj::RecursiveProvenanceEventKeyV1> events;
    std::vector<ConsumerRow> rows;
    std::string why;
    if (!BuildConsumerRows(
            shape, manifest, events, rows, &why) ||
        !ValidSourceRefs(shape, verifier_sources, events) ||
        rows.size() > out.parent_rows) {
        return out;
    }
    cb::ProgramTable table;
    if (!BuildConsumerProgramTable(out.layout, table, &why)) {
        return out;
    }
    out.role_rows = rpj::kRecursiveProvenanceRoleCountV1;
    out.endpoint_rows =
        rpj::kRecursiveProvenanceEndpointCountV1;
    out.temporal_rows =
        static_cast<uint32_t>(events.size());
    out.active_rows = static_cast<uint32_t>(rows.size());
    out.semantic_program_bridge_commitment =
        manifest.bridge_commitment;
    out.bytecode_program_root = cb::CommitProgramTable(table);
    out.bytecode_program_alg_root =
        cb::CommitProgramTableAlgHash(table);
    out.canonical_program_table =
        !out.bytecode_program_root.IsNull() &&
        cb::ValidateProgramTable(table, &why);
    out.exact_14_roles =
        out.role_rows ==
            rpj::kRecursiveProvenanceRoleCountV1;
    out.exact_52_endpoints =
        out.endpoint_rows ==
            rpj::kRecursiveProvenanceEndpointCountV1;
    out.exact_temporal_schedule =
        out.temporal_rows == events.size();
    out.consumer_schedule_root =
        ConsumerScheduleRoot(shape, manifest, out, rows);

    rpj::RecursiveProvenanceParentAliasRefsV1 joined;
    if (!JoinedRefs(
            shape, verifier_sources, out.layout,
            events, joined)) {
        return out;
    }
    out.fixed_alias_schedule_commitment =
        rpj::
            ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
                shape, joined);
    out.valid =
        out.exact_14_roles &&
        out.exact_52_endpoints &&
        out.exact_temporal_schedule &&
        out.canonical_program_table &&
        !out.semantic_program_bridge_commitment.IsNull() &&
        !out.consumer_schedule_root.IsNull() &&
        !out.fixed_alias_schedule_commitment.IsNull();
    return out;
}

bool AppendCanonicalProvenanceConsumerSpineV1(
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const rpj::RecursiveProvenanceShapeV1& shape,
    const rpj::RecursiveProvenanceParentAliasRefsV1& verifier_sources,
    const CanonicalProvenanceConsumerPlanV1& expected_plan,
    CanonicalProvenanceConsumerAttachmentV1& out,
    std::string* why)
{
    out = {};
    const auto plan =
        BuildCanonicalProvenanceConsumerPlanV1(
            shape, verifier_sources);
    out.plan = plan;
    out.independently_pinned_plan_match =
        plan.valid && expected_plan.valid &&
        plan == expected_plan;
    if (!out.independently_pinned_plan_match ||
        parent_cs.n_rows != plan.parent_rows ||
        parent_cs.n_columns !=
            plan.parent_original_columns ||
        parent_columns.size() != parent_cs.n_columns) {
        return Fail(why, "consumer_plan_or_parent_shape");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "consumer_parent_column_rows");
        }
    }

    const auto manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    std::vector<rpj::RecursiveProvenanceEventKeyV1> events;
    std::vector<ConsumerRow> rows;
    std::string local_why;
    if (!BuildConsumerRows(
            shape, manifest, events, rows, &local_why)) {
        return Fail(why, "consumer_rows");
    }
    cb::ProgramTable table;
    if (!BuildConsumerProgramTable(
            plan.layout, table, &local_why) ||
        cb::CommitProgramTable(table) !=
            plan.bytecode_program_root ||
        cb::CommitProgramTableAlgHash(table) !=
            plan.bytecode_program_alg_root) {
        return Fail(why, "consumer_program");
    }
    AirCS consumer_cs;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            table, parent_cs.n_rows,
            consumer_cs, &local_why)) {
        return Fail(why, "consumer_program_air");
    }

    const uint32_t constraint_base =
        static_cast<uint32_t>(
            parent_cs.constraints.size());
    parent_columns.resize(
        plan.layout.end_column,
        std::vector<gf::Fp3>(
            parent_cs.n_rows, gf::Fp3::Zero()));
    parent_cs.n_columns = plan.layout.end_column;
    for (auto& constraint : consumer_cs.constraints) {
        parent_cs.constraints.push_back(
            std::move(constraint));
    }
    for (uint32_t row = 0; row < rows.size(); ++row) {
        SetMetadata(
            plan.layout, rows[row], row,
            parent_columns);
    }
    const auto metadata =
        ConsumerMetadataColumns(plan.layout);
    for (uint32_t i = 0; i < metadata.size(); ++i) {
        const uint32_t column =
            plan.layout.expected_base + i;
        parent_cs.preprocessed.emplace_back(
            column, parent_columns[column]);
        ++out.preprocessing_columns_added;
    }
    parent_cs.preprocessed_pin_ood = true;

    rpj::RecursiveProvenanceParentAliasRefsV1 joined;
    if (!JoinedRefs(
            shape, verifier_sources, plan.layout,
            events, joined)) {
        return Fail(why, "consumer_joined_refs");
    }
    uint32_t row = 0;
    const auto copy_root =
        [&](const rpj::RecursiveProvenanceParentRootRefV1& source) {
            temporal::TemporalRootU32V1 root;
            if (!ReadStrictRoot(
                    parent_cs, parent_columns,
                    source, root, why)) {
                return false;
            }
            SetConsumerRoot(
                plan.layout, row++, root,
                parent_columns);
            return true;
        };
    for (const auto& role : joined.roles) {
        if (!copy_root(role.root.verifier_output)) return false;
    }
    for (const auto& endpoint : joined.endpoints) {
        if (!copy_root(endpoint.root.verifier_output)) return false;
    }
    for (const auto& event : joined.events) {
        if (!copy_root(event.root.verifier_output)) return false;
    }
    if (row != plan.active_rows) {
        return Fail(why, "consumer_root_rows");
    }

    if (!rpj::AppendRecursiveProvenanceParentAliasesV1(
            parent_cs, parent_columns,
            shape, joined,
            plan.fixed_alias_schedule_commitment,
            out.alias, why)) {
        return false;
    }
    out.constraints_added =
        static_cast<uint32_t>(
            parent_cs.constraints.size()) -
        constraint_base;
    out.violations =
        rpj::CountRecursiveProvenanceJoinViolationsV1(
            parent_cs, parent_columns);
    out.root_words_are_canonical_u32 = true;
    out.root_words_bit_constrained = true;
    out.all_consumer_addresses_program_allocated = true;
    out.temporal_event_schedule_bound =
        plan.exact_temporal_schedule;
    out.no_free_consumer_root_witness =
        out.alias.fixed_offset_schedule_bound &&
        out.alias.limb_equalities ==
            plan.active_rows *
                kCanonicalProvenanceConsumerRootWordsV1;
    out.named_consumer_semantics_constrained =
        out.no_free_consumer_root_witness &&
        out.root_words_bit_constrained &&
        out.all_consumer_addresses_program_allocated;
    out.underlying_relation_program_semantics_complete = false;
    out.verifier_output_semantics_constrained = false;
    out.complete_child_acceptance_in_same_parent = false;
    out.recursive_authority = false;
    out.residuals = {
        "31_original_relation_program_output_recipes_still_open",
        "verifier_output_semantics_not_constrained_in_same_parent",
        "complete_child_acceptance_not_constrained_in_same_parent"};
    out.valid =
        out.independently_pinned_plan_match &&
        out.alias.valid &&
        out.violations == 0 &&
        out.root_words_are_canonical_u32 &&
        out.root_words_bit_constrained &&
        out.all_consumer_addresses_program_allocated &&
        out.temporal_event_schedule_bound &&
        out.no_free_consumer_root_witness &&
        out.named_consumer_semantics_constrained &&
        !out.underlying_relation_program_semantics_complete &&
        !out.verifier_output_semantics_constrained &&
        !out.complete_child_acceptance_in_same_parent &&
        !out.recursive_authority;
    out.note = out.valid
        ? "stage3:canonical_provenance_consumer:"
          "named_consumer_router_executable;"
          "original_relation_semantics_and_child_acceptance_open"
        : "stage3:canonical_provenance_consumer:invalid";
    if (why != nullptr) *why = out.note;
    return out.valid;
}

} // namespace matmul::v4::rc::direct_parent_spine
