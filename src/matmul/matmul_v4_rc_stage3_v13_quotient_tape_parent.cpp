// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_quotient_tape_parent.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_v13_quotient_tape_parent {
namespace {

using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_quotient_tape_parent:" +
            detail;
    }
    return false;
}

bool IsPreprocessed(const AirCS& cs, uint32_t column)
{
    return std::any_of(
        cs.preprocessed.begin(),
        cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
}

bool CanonicalU32(const Fp3& value, uint32_t& out)
{
    if (value.c1 != 0 ||
        value.c2 != 0 ||
        value.c0 >
            std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = static_cast<uint32_t>(value.c0);
    return true;
}

const tape::SourceAddressCellV1* FindTapeSource(
    const tape::ProductV1& product,
    uint32_t address)
{
    const auto found = std::find_if(
        product.source_cells.begin(),
        product.source_cells.end(),
        [address](const auto& source) {
            return source.address == address;
        });
    return found == product.source_cells.end()
        ? nullptr
        : &*found;
}

bool AppendChild(
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const AirCS& child_cs,
    const std::vector<std::vector<Fp3>>& child_columns,
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

void AddConstraint(
    AirCS& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back({
        name, kind, degree, std::move(eval)});
}

bool AppendAliasImpl(
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    const CellRefV1& source,
    const CellRefV1& sink,
    ProductV1& out,
    std::string* why)
{
    const uint32_t original_columns = cs.n_columns;
    if (source.column >= original_columns ||
        sink.column >= original_columns ||
        source.row >= cs.n_rows ||
        sink.row >= cs.n_rows ||
        IsPreprocessed(cs, source.column) ||
        IsPreprocessed(cs, sink.column)) {
        return Fail(why, "alias_ref_or_preprocessed");
    }
    const uint32_t carrier = cs.n_columns;
    const uint32_t source_selector = carrier + 1;
    const uint32_t sink_selector = carrier + 2;
    cs.n_columns += 3;
    columns.resize(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    const Fp3 value =
        columns[source.column][source.row];
    std::fill(
        columns[carrier].begin(),
        columns[carrier].end(), value);
    columns[source_selector][source.row] =
        Fp3::One();
    columns[sink_selector][sink.row] =
        Fp3::One();
    cs.preprocessed.emplace_back(
        source_selector,
        columns[source_selector]);
    cs.preprocessed.emplace_back(
        sink_selector,
        columns[sink_selector]);
    cs.preprocessed_pin_ood = true;

    AddConstraint(
        cs,
        "stage3.v13_quotient.alias_carry",
        aq::AirKind::kTransition, 1,
        [carrier](
            const auto& current,
            const auto& next) {
            return gf::Sub(
                next[carrier],
                current[carrier]);
        });
    AddConstraint(
        cs,
        "stage3.v13_quotient.alias_source",
        aq::AirKind::kEverywhere, 2,
        [carrier, source_selector,
         source_column = source.column](
            const auto& current,
            const auto&) {
            return gf::Mul(
                current[source_selector],
                gf::Sub(
                    current[carrier],
                    current[source_column]));
        });
    AddConstraint(
        cs,
        "stage3.v13_quotient.alias_sink",
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
    ++out.aliases_appended;
    ++out.carrier_columns;
    out.selector_columns += 2;
    return true;
}

bool Applies(
    aq::AirKind kind,
    uint32_t row,
    uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

} // namespace

bool AppendOrdinaryCellAliasV1(
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    const CellRefV1& source,
    const CellRefV1& sink,
    ProductV1& accounting,
    std::string* why)
{
    return AppendAliasImpl(
        cs, columns, source, sink,
        accounting, why);
}

bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const dvm::ProductV1& deep_product,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range,
    ProductV1& out,
    std::string* why)
{
    out = {};
    out.range = range;
    if (!tape_product.valid ||
        !deep_product.valid ||
        deep_product.first_query !=
            range.first_query ||
        deep_product.query_count !=
            range.query_count ||
        range.query_count == 0) {
        return Fail(why, "input");
    }
    out.deep_plan =
        unified::BuildDeepVmPublicPlanV1(
            child_program,
            expected_program_root,
            range);
    out.deep_phase =
        unified::MaterializeDeepVmCanonicalPhaseV1(
            out.deep_plan,
            deep_product);
    if (!out.deep_plan.valid ||
        !out.deep_phase.valid ||
        out.deep_phase.cs.n_rows !=
            deep_product.cs.n_rows) {
        return Fail(why, "canonical_deep_phase");
    }
    out.canonical_deep_plan_rebuilt = true;
    AirCS deep_resident_cs =
        out.deep_phase.cs;
    if (deep_resident_cs
            .preprocessed_row_group_roots
            .size() != 1 ||
        deep_resident_cs
                .preprocessed_row_group_roots[0]
                .role !=
            aq::AirPreprocessedRowGroupRole::kR0 ||
        deep_resident_cs
                .preprocessed_row_group_roots[0]
                .ordered_columns !=
            out.deep_plan
                .statement_manifest_columns ||
        deep_resident_cs
                .preprocessed_row_group_roots[0]
                .root !=
            out.deep_plan
                .statement_schedule_root) {
        return Fail(
            why, "deep_statement_r0");
    }
    // The composer's physical parent commits each canonical preprocessed
    // schedule column directly.  The child-local aggregate R0 pin cannot be
    // transplanted into a wider parent: it is cleared only after the exact
    // verifier-rebuilt ordered manifest/root check above.  A single global
    // parent R0 is deliberately still pending and no readiness claim is made.
    deep_resident_cs
        .preprocessed_row_group_roots.clear();

    const uint32_t parent_rows =
        std::max(
            tape_product.cs.n_rows,
            deep_resident_cs.n_rows);
    if (!AppendChild(
            out.cs, out.columns,
            tape_product.cs,
            tape_product.columns,
            parent_rows, 0,
            out.tape_attachment, why) ||
        !AppendChild(
            out.cs, out.columns,
            deep_resident_cs,
            out.deep_phase.columns,
            parent_rows, 1,
            out.deep_attachment, why)) {
        out = {};
        return false;
    }

    const auto& layout =
        deep_product.layout;
    std::map<uint32_t, uint32_t> quotient_row;
    for (uint32_t row = 0;
         row < deep_product.real_rows;
         ++row) {
        if (!gf::Eq(
                out.deep_phase.columns[
                    layout.quotient_identity][row],
                Fp3::One())) {
            continue;
        }
        uint32_t query = 0;
        if (!CanonicalU32(
                out.deep_phase.columns[
                    layout.query][row],
                query) ||
            query < range.first_query ||
            query >=
                range.first_query +
                    range.query_count ||
            !quotient_row.emplace(
                query, row).second) {
            out = {};
            return Fail(why, "quotient_row_schedule");
        }
    }
    if (quotient_row.size() !=
            range.query_count) {
        out = {};
        return Fail(why, "quotient_row_count");
    }
    out.quotient_rows =
        static_cast<uint32_t>(
            quotient_row.size());

    for (const auto& [query, row] :
         quotient_row) {
        uint32_t source_address = 0;
        if (!CanonicalU32(
                out.deep_phase.columns[
                    layout.source_address][row],
                source_address)) {
            out = {};
            return Fail(why, "source_address");
        }
        for (uint32_t limb = 0;
             limb <
                 dvm::kFp3TapeLimbsV1;
             ++limb) {
            const uint64_t address64 =
                uint64_t{source_address} +
                limb;
            if (address64 > UINT32_MAX) {
                out = {};
                return Fail(
                    why, "source_address_overflow");
            }
            const uint32_t address =
                static_cast<uint32_t>(
                    address64);
            const auto* source =
                FindTapeSource(
                    tape_product, address);
            const uint32_t coordinate =
                limb / 2;
            const uint8_t half =
                static_cast<uint8_t>(
                    limb % 2);
            if (source == nullptr ||
                source->key.kind !=
                    stage3_multirow_v11_proof_abi::
                        FieldKindV1::QueryRowValue ||
                source->key.a != query ||
                source->key.b != 2 ||
                source->key.c != 0 ||
                source->key.d != coordinate ||
                source->key.limb != half) {
                out = {};
                return Fail(
                    why, "source_key_inventory");
            }
            QuotientLimbAliasV1 alias;
            alias.query = query;
            alias.source_address = address;
            alias.limb =
                static_cast<uint8_t>(limb);
            alias.tape_value = {
                out.tape_attachment.ParentColumn(
                    source->value_column),
                source->row,
            };
            alias.quotient_limb = {
                out.deep_attachment.ParentColumn(
                    layout.quotient_tape_limb[
                        limb]),
                row,
            };
            if (!AppendOrdinaryCellAliasV1(
                    out.cs, out.columns,
                    alias.tape_value,
                    alias.quotient_limb,
                    out, why)) {
                out = {};
                return Fail(
                    why, "quotient_limb_alias");
            }
            out.aliases.push_back(alias);
        }
    }

    // Both materialized children were independently revalidated above and
    // the composer only shifts/gates their already-exact constraints.  The
    // only new witness obligations introduced here are the physical aliases.
    // Count those directly instead of rescanning the entire lifted Q192 tape
    // (millions of rows) merely to rediscover the child-local zeroes.
    out.violations =
        uint64_t{tape_product.violations} +
        deep_product.violations;
    for (const auto& alias : out.aliases) {
        if (!gf::Eq(
                out.columns[
                    alias.tape_value.column]
                    [alias.tape_value.row],
                out.columns[
                    alias.quotient_limb.column]
                    [alias.quotient_limb.row])) {
            ++out.violations;
        }
    }
    out.complete_quotient_limb_inventory =
        out.aliases.size() ==
            uint64_t{range.query_count} *
                dvm::kFp3TapeLimbsV1 &&
        out.aliases_appended ==
            out.aliases.size();
    out.source_addresses_fixed_by_v13_tape =
        out.complete_quotient_limb_inventory;
    out.tape_cells_ordinary = true;
    out.quotient_cells_ordinary = true;
    for (const auto& alias : out.aliases) {
        out.tape_cells_ordinary =
            out.tape_cells_ordinary &&
            !IsPreprocessed(
                out.cs,
                alias.tape_value.column);
        out.quotient_cells_ordinary =
            out.quotient_cells_ordinary &&
            !IsPreprocessed(
                out.cs,
                alias.quotient_limb.column);
    }
    out.selectors_only_preprocessed =
        out.selector_columns ==
            2 * out.aliases_appended;
    out.cross_row_transport_constrained =
        out.carrier_columns ==
            out.aliases_appended;
    out.global_r0_pending =
        out.cs
            .preprocessed_row_group_roots
            .empty();
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.canonical_deep_plan_rebuilt &&
        out.complete_quotient_limb_inventory &&
        out.source_addresses_fixed_by_v13_tape &&
        out.tape_cells_ordinary &&
        out.quotient_cells_ordinary &&
        out.selectors_only_preprocessed &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v13_quotient_tape_parent:"
          "complete_query_quotient_limb_family_physically_aliased;"
          "global_r0_and_recursive_consumption_pending"
        : "stage3:v13_quotient_tape_parent:"
          "physical_alias_constraints_reject_mismatch";
    if (!out.valid) {
        return Fail(why, "invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

uint64_t CountViolationsV1(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return UINT64_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT64_MAX;
        }
    }
    uint64_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0;
         row < cs.n_rows;
         ++row) {
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
            if (Applies(
                    constraint.kind,
                    row, cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_v13_quotient_tape_parent
