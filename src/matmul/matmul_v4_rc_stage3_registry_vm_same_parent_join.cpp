// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_registry_vm_same_parent_join.h>

#include <algorithm>
#include <functional>
#include <limits>

namespace matmul::v4::rc::stage3_registry_vm_same_parent_join {
namespace {

using gf::Fp;
using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:registry_vm_same_parent_join:" +
            detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Applies(
    aq::AirKind kind, uint32_t row, uint32_t rows)
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

void AddFirstRowConstant(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    uint32_t column,
    const Fp3& expected)
{
    cs.constraints.push_back({
        name, aq::AirKind::kFirstRow, 1,
        [column, expected](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Sub(
                current[column], expected);
        }});
}

std::array<Fp3, registry_air::kRegistryFamilyFieldsV1>
SelectedValues(const VmChildStatementV1& child)
{
    std::array<
        Fp3,
        registry_air::kRegistryFamilyFieldsV1> out{};
    out[0] = U(child.quotient.program_id);
    out[1] =
        U(static_cast<uint16_t>(child.kind));
    out[2] =
        U(static_cast<uint16_t>(child.role));
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        out[3 + limb] =
            Fp3::FromFp(
                gf::Canonical(
                    child.quotient
                        .selected_program_key[limb]));
        out[7 + limb] =
            Fp3::FromFp(
                gf::Canonical(
                    child.selected_schema_alg_hash[
                        limb]));
    }
    out[11] =
        child.semantic_relation_complete
        ? Fp3::One()
        : Fp3::Zero();
    return out;
}

bool ValidColumn(uint32_t column, uint32_t columns)
{
    return column < columns;
}

bool ValidRefs(
    const VmChildStatementCellRefsV1& refs,
    uint32_t columns)
{
    for (uint32_t column :
         refs.registry_alg_root.limb) {
        if (!ValidColumn(column, columns)) {
            return false;
        }
    }
    if (!ValidColumn(
            refs.selected.family_index,
            columns) ||
        !ValidColumn(refs.selected.kind, columns) ||
        !ValidColumn(refs.selected.role, columns) ||
        !ValidColumn(
            refs.selected
                .semantic_relation_complete,
            columns)) {
        return false;
    }
    for (uint32_t column :
         refs.selected.program_alg_hash.limb) {
        if (!ValidColumn(column, columns)) {
            return false;
        }
    }
    for (uint32_t column :
         refs.selected.schema_alg_hash.limb) {
        if (!ValidColumn(column, columns)) {
            return false;
        }
    }
    return true;
}

bool RegistrySystemResident(
    const aq::AirConstraintSystem<Fp3>& expected,
    const aq::AirConstraintSystem<Fp3>& parent)
{
    if (parent.n_rows != expected.n_rows ||
        parent.n_columns != expected.n_columns ||
        parent.preprocessed_pin_ood !=
            expected.preprocessed_pin_ood ||
        parent.constraints.size() !=
            expected.constraints.size() ||
        parent.preprocessed.size() !=
            expected.preprocessed.size() ||
        parent.preprocessed_row_group_roots.size() !=
            expected.preprocessed_row_group_roots.size()) {
        return false;
    }
    for (uint32_t i = 0;
         i < expected.constraints.size();
         ++i) {
        if (parent.constraints[i].name !=
                expected.constraints[i].name ||
            parent.constraints[i].kind !=
                expected.constraints[i].kind ||
            parent.constraints[i].alg_degree !=
                expected.constraints[i].alg_degree) {
            return false;
        }
    }
    for (uint32_t i = 0;
         i < expected.preprocessed.size();
         ++i) {
        const auto& a = expected.preprocessed[i];
        const auto& b = parent.preprocessed[i];
        if (a.first != b.first ||
            a.second.size() != b.second.size()) {
            return false;
        }
        for (uint32_t row = 0;
             row < a.second.size();
             ++row) {
            if (!gf::Eq(
                    a.second[row],
                    b.second[row])) {
                return false;
            }
        }
    }
    for (uint32_t i = 0;
         i <
             expected.preprocessed_row_group_roots
                 .size();
         ++i) {
        const auto& a =
            expected
                .preprocessed_row_group_roots[i];
        const auto& b =
            parent
                .preprocessed_row_group_roots[i];
        if (a.version != b.version ||
            a.role != b.role ||
            a.ordered_columns !=
                b.ordered_columns ||
            a.root != b.root) {
            return false;
        }
    }
    return true;
}

} // namespace

VmChildStatementCellRefsV1
CanonicalRegistryProducerRefsV1(
    const registry_air::LayoutV1& layout)
{
    VmChildStatementCellRefsV1 out;
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        out.registry_alg_root.limb[limb] =
            layout.DigestClaim(limb);
        out.selected.program_alg_hash
            .limb[limb] =
            layout.SelectedField(3 + limb);
        out.selected.schema_alg_hash
            .limb[limb] =
            layout.SelectedField(7 + limb);
    }
    out.selected.family_index =
        layout.SelectedField(0);
    out.selected.kind =
        layout.SelectedField(1);
    out.selected.role =
        layout.SelectedField(2);
    out.selected.semantic_relation_complete =
        layout.SelectedField(11);
    return out;
}

VmChildStatementV1 BuildVmChildStatementV1(
    const registry_air::StatementV1& registry_statement,
    const cwa::PublicInputsV1& quotient)
{
    VmChildStatementV1 out;
    out.quotient = quotient;
    out.kind = registry_statement.selected.kind;
    out.role = registry_statement.selected.role;
    out.selected_schema_alg_hash =
        registry_statement.selected.schema_alg_hash;
    out.semantic_relation_complete =
        registry_statement.selected
            .semantic_relation_complete;
    return out;
}

uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    uint64_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
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
        for (const auto& constraint : cs.constraints) {
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

bool AppendRegistryVmSameParentJoinV1(
    const registry_air::ProductV1& registry_product,
    const VmChildStatementV1& child_statement,
    const VmChildStatementCellRefsV1& child_refs,
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    AppendResultV1& out,
    std::string* why)
{
    out = {};
    out.original_columns = parent_cs.n_columns;
    if (child_statement.version !=
            kRegistryVmSameParentJoinVersionV1 ||
        !registry_product.valid ||
        registry_product.layout.n_columns >
            parent_cs.n_columns ||
        !RegistrySystemResident(
            registry_product.cs,
            parent_cs) ||
        parent_columns.size() !=
            parent_cs.n_columns ||
        !ValidRefs(
            child_refs, parent_cs.n_columns)) {
        return Fail(why, "shape");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "column_rows");
        }
    }

    const auto producer_refs =
        CanonicalRegistryProducerRefsV1(
            registry_product.layout);
    if (!(child_refs == producer_refs)) {
        return Fail(
            why,
            "consumer_must_directly_alias_"
            "registry_producer_cells");
    }

    // The uint256 boundary is a canonical byte packing of four Goldilocks
    // values. In particular, Fri3AlgDigestFromUint256 rejects every x+p
    // encoding before it can be embedded in the field and alias x.
    const auto decoded =
        Fri3AlgDigestFromUint256(
            child_statement.quotient
                .program_registry_alg_root);
    if (!decoded.has_value()) {
        return Fail(
            why,
            "noncanonical_registry_alg_root");
    }

    const uint32_t before_constraints =
        static_cast<uint32_t>(
            parent_cs.constraints.size());
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        AddFirstRowConstant(
            parent_cs,
            "stage3.registry_vm_join.registry_root",
            child_refs.registry_alg_root
                .limb[limb],
            Fp3::FromFp(
                gf::Canonical((*decoded)[limb])));
    }

    const auto selected =
        SelectedValues(child_statement);
    const std::array<uint32_t,
                     registry_air::
                         kRegistryFamilyFieldsV1>
        selected_columns{
            child_refs.selected.family_index,
            child_refs.selected.kind,
            child_refs.selected.role,
            child_refs.selected.program_alg_hash
                .limb[0],
            child_refs.selected.program_alg_hash
                .limb[1],
            child_refs.selected.program_alg_hash
                .limb[2],
            child_refs.selected.program_alg_hash
                .limb[3],
            child_refs.selected.schema_alg_hash
                .limb[0],
            child_refs.selected.schema_alg_hash
                .limb[1],
            child_refs.selected.schema_alg_hash
                .limb[2],
            child_refs.selected.schema_alg_hash
                .limb[3],
            child_refs.selected
                .semantic_relation_complete};
    for (uint32_t field = 0;
         field < selected_columns.size();
         ++field) {
        AddFirstRowConstant(
            parent_cs,
            "stage3.registry_vm_join.selected_tuple",
            selected_columns[field],
            selected[field]);
    }

    out.canonical_registry_uint256_encoding =
        true;
    out.registry_air_source_constraints_resident =
        before_constraints ==
            registry_product.cs.constraints.size();
    out.exact_cell_aliases = true;
    out.added_columns =
        parent_cs.n_columns -
        out.original_columns;
    out.no_value_or_carrier_columns_added =
        out.added_columns == 0;
    out.added_constraints =
        static_cast<uint32_t>(
            parent_cs.constraints.size()) -
        before_constraints;
    out.child_program_id_kind_role_consumes_registry_cells =
        true;
    out.child_program_alg_hash_consumes_registry_cells =
        true;
    out.child_schema_alg_hash_consumes_registry_cells =
        true;
    out.child_semantic_completeness_consumes_registry_cell =
        true;
    out.child_registry_root_consumes_registry_cells =
        true;
    out.child_statement_public_constants_constrained =
        out.added_constraints ==
            kRegistryVmDirectAliasesV1;
    out.complete_vm_child_verifier_same_parent =
        false;
    out.unified_root_consumes_bridge = false;
    out.production_authority_ready = false;
    out.violations =
        CountViolationsV1(
            parent_cs, parent_columns);
    out.valid =
        out.canonical_registry_uint256_encoding &&
        out.registry_air_source_constraints_resident &&
        out.exact_cell_aliases &&
        out.no_value_or_carrier_columns_added &&
        out.child_program_id_kind_role_consumes_registry_cells &&
        out.child_program_alg_hash_consumes_registry_cells &&
        out.child_schema_alg_hash_consumes_registry_cells &&
        out.child_semantic_completeness_consumes_registry_cell &&
        out.child_registry_root_consumes_registry_cells &&
        out.child_statement_public_constants_constrained &&
        out.violations == 0 &&
        !out.complete_vm_child_verifier_same_parent &&
        !out.unified_root_consumes_bridge &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:registry_vm_same_parent_join:"
          "direct_16_cell_alias;"
          "complete_child_verifier_and_unified_root_pending"
        : "stage3:registry_vm_same_parent_join:"
          "statement_mismatch";
    return true;
}

} // namespace matmul::v4::rc::stage3_registry_vm_same_parent_join
