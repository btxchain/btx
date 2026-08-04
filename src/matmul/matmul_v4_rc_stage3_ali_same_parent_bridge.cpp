// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_ali_same_parent_bridge.h>

#include <algorithm>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_ali_same_parent_bridge {

namespace {

using gf::Fp3;

bool Fail(std::string* why, const char* reason)
{
    if (why != nullptr) {
        *why =
            std::string{"stage3:ali_same_parent:"} +
            reason;
    }
    return false;
}

void AddWord(
    std::vector<StatementWordV1>& words,
    StatementWordKindV1 kind,
    uint32_t value,
    uint32_t ordinal = 0)
{
    words.push_back({kind, ordinal, value});
}

void AddU64Words(
    std::vector<StatementWordV1>& words,
    StatementWordKindV1 kind,
    uint64_t value)
{
    AddWord(
        words, kind,
        static_cast<uint32_t>(value), 0);
    AddWord(
        words, kind,
        static_cast<uint32_t>(value >> 32), 1);
}

bool ValidCell(
    const CellRefV1& ref,
    const aq::AirConstraintSystem<Fp3>& cs)
{
    return ref.column < cs.n_columns &&
        ref.row < cs.n_rows;
}

uint64_t CellIdentity(const CellRefV1& ref)
{
    return
        (uint64_t{ref.column} << 32) |
        ref.row;
}

bool CanonicalBaseCell(const Fp3& value)
{
    return
        value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP &&
        value.c1 == 0 &&
        value.c2 == 0;
}

bool ReferencedColumnPreprocessed(
    uint32_t column,
    const aq::AirConstraintSystem<Fp3>& cs)
{
    if (std::any_of(
            cs.preprocessed.begin(),
            cs.preprocessed.end(),
            [column](const auto& entry) {
                return entry.first == column;
            }) ||
        std::any_of(
            cs.preprocessed_roots.begin(),
            cs.preprocessed_roots.end(),
            [column](const auto& entry) {
                return entry.first == column;
            })) {
        return true;
    }
    for (const auto& group :
         cs.preprocessed_row_group_roots) {
        if (std::find(
                group.ordered_columns.begin(),
                group.ordered_columns.end(),
                column) !=
            group.ordered_columns.end()) {
            return true;
        }
    }
    return false;
}

struct PendingEquality {
    CellPairV1 cells;
    uint32_t expected{0};
};

bool AddPending(
    const CellPairV1& cells,
    uint32_t expected,
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    std::set<uint64_t>& used,
    std::vector<PendingEquality>& pending,
    std::string* why)
{
    if (!ValidCell(cells.manifest_producer, cs) ||
        !ValidCell(cells.normalized_vm_consumer, cs)) {
        return Fail(why, "cell_ref");
    }
    if (cells.manifest_producer ==
            cells.normalized_vm_consumer ||
        ReferencedColumnPreprocessed(
            cells.manifest_producer.column, cs) ||
        ReferencedColumnPreprocessed(
            cells.normalized_vm_consumer.column, cs)) {
        return Fail(why, "collapsed_or_preprocessed");
    }
    if (!used.insert(
            CellIdentity(
                cells.manifest_producer)).second ||
        !used.insert(
            CellIdentity(
                cells.normalized_vm_consumer)).second) {
        return Fail(why, "duplicate_cell_ref");
    }
    const Fp3 exact =
        Fp3::FromFp(gf::FromU64(expected));
    const Fp3& producer =
        columns[cells.manifest_producer.column]
            [cells.manifest_producer.row];
    const Fp3& consumer =
        columns[cells.normalized_vm_consumer.column]
            [cells.normalized_vm_consumer.row];
    if (!CanonicalBaseCell(producer) ||
        !CanonicalBaseCell(consumer) ||
        !gf::Eq(producer, exact) ||
        !gf::Eq(
            consumer,
            exact)) {
        return Fail(why, "honest_value_mismatch");
    }
    pending.push_back({cells, expected});
    return true;
}

void InstallSelector(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t column,
    uint32_t row)
{
    columns[column][row] = Fp3::One();
    cs.preprocessed.push_back(
        {column, columns[column]});
}

void AppendEquality(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    const PendingEquality& pending,
    EqualityLayoutV1& layout)
{
    CellRefV1 source =
        pending.cells.manifest_producer;
    CellRefV1 sink =
        pending.cells.normalized_vm_consumer;
    if (source.row > sink.row) {
        std::swap(source, sink);
    }
    const Fp3 expected =
        Fp3::FromFp(gf::FromU64(pending.expected));
    layout.same_row = source.row == sink.row;
    if (layout.same_row) {
        layout.source_selector = cs.n_columns++;
        columns.push_back(
            std::vector<Fp3>(
                cs.n_rows, Fp3::Zero()));
        InstallSelector(
            cs, columns,
            layout.source_selector, source.row);
        const uint32_t selector =
            layout.source_selector;
        cs.constraints.push_back({
            "stage3.ali_same_parent.exact_value",
            aq::AirKind::kEverywhere, 2,
            [selector, source, expected](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    current[selector],
                    gf::Sub(
                        current[source.column],
                        expected));
            }});
        cs.constraints.push_back({
            "stage3.ali_same_parent.same_row",
            aq::AirKind::kEverywhere, 2,
            [selector, source, sink](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    current[selector],
                    gf::Sub(
                        current[source.column],
                        current[sink.column]));
            }});
        return;
    }

    layout.carrier = cs.n_columns++;
    layout.source_selector = cs.n_columns++;
    layout.sink_selector = cs.n_columns++;
    layout.carry_selector = cs.n_columns++;
    columns.resize(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    for (uint32_t row = source.row;
         row <= sink.row;
         ++row) {
        columns[layout.carrier][row] = expected;
    }
    InstallSelector(
        cs, columns,
        layout.source_selector, source.row);
    InstallSelector(
        cs, columns,
        layout.sink_selector, sink.row);
    for (uint32_t row = source.row;
         row < sink.row;
         ++row) {
        columns[layout.carry_selector][row] =
            Fp3::One();
    }
    cs.preprocessed.push_back({
        layout.carry_selector,
        columns[layout.carry_selector]});

    const uint32_t carrier = layout.carrier;
    const uint32_t source_selector =
        layout.source_selector;
    const uint32_t sink_selector =
        layout.sink_selector;
    const uint32_t carry_selector =
        layout.carry_selector;
    cs.constraints.push_back({
        "stage3.ali_same_parent.exact_source",
        aq::AirKind::kEverywhere, 2,
        [source_selector, source, expected](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Mul(
                current[source_selector],
                gf::Sub(
                    current[source.column],
                    expected));
        }});
    cs.constraints.push_back({
        "stage3.ali_same_parent.source_carrier",
        aq::AirKind::kEverywhere, 2,
        [carrier, source_selector, source](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Mul(
                current[source_selector],
                gf::Sub(
                    current[carrier],
                    current[source.column]));
        }});
    cs.constraints.push_back({
        "stage3.ali_same_parent.sink_carrier",
        aq::AirKind::kEverywhere, 2,
        [carrier, sink_selector, sink](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Mul(
                current[sink_selector],
                gf::Sub(
                    current[carrier],
                    current[sink.column]));
        }});
    cs.constraints.push_back({
        "stage3.ali_same_parent.carry",
        aq::AirKind::kTransition, 2,
        [carrier, carry_selector](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>& next) {
            return gf::Mul(
                current[carry_selector],
                gf::Sub(
                    next[carrier],
                    current[carrier]));
        }});
}

} // namespace

bool BuildCanonicalAliVmStatementV1(
    uint32_t family_index,
    CanonicalAliVmStatementV1& out,
    std::string* why)
{
    out = {};
    // Immutable build-time program tables make this inventory process-local
    // consensus data. Derive it once, then copy only the selected entry.
    static const ali::ProductionAliManifestV1 manifest =
        ali::BuildProductionAliManifestV1();
    if (!manifest.local_manifest_complete ||
        manifest.recursive_root_consumed ||
        manifest.production_authority ||
        family_index >= manifest.families.size()) {
        return Fail(why, "manifest_or_family");
    }
    const ali::ProductionAliFamilyV1& family =
        manifest.families[family_index];
    out.family_index = family_index;
    out.manifest_commitment = manifest.commitment;
    out.source_program_key = family.source_program_key;
    out.compiled_program_key =
        family.compiled_program_key;

    AddWord(
        out.words, StatementWordKindV1::FamilyIndex,
        family.family_index);
    AddWord(
        out.words, StatementWordKindV1::ProofSiteKind,
        static_cast<uint32_t>(family.kind));
    AddWord(
        out.words, StatementWordKindV1::RelationRole,
        static_cast<uint32_t>(family.role));
    AddWord(
        out.words,
        StatementWordKindV1::SemanticRelationComplete,
        family.semantic_relation_complete ? 1U : 0U);
    AddWord(
        out.words,
        StatementWordKindV1::SemanticEndpointCount,
        static_cast<uint32_t>(
            family.semantic_endpoints.size()));
    for (uint32_t endpoint = 0;
         endpoint < family.semantic_endpoints.size();
         ++endpoint) {
        AddWord(
            out.words,
            StatementWordKindV1::SemanticEndpoint,
            family.semantic_endpoints[endpoint],
            endpoint);
    }
    AddWord(
        out.words, StatementWordKindV1::SourceCurrentWidth,
        family.source_current_width);
    AddWord(
        out.words, StatementWordKindV1::SourceNextWidth,
        family.source_next_width);
    AddWord(
        out.words,
        StatementWordKindV1::SourceChallengeWidth,
        family.source_challenge_width);
    AddWord(
        out.words,
        StatementWordKindV1::SourceConstraintCount,
        family.source_constraint_count);
    AddWord(
        out.words,
        StatementWordKindV1::SourceInstructionCount,
        family.source_instruction_count);
    AddWord(
        out.words,
        StatementWordKindV1::SourceChallengeLoads,
        family.source_challenge_loads);
    AddWord(
        out.words,
        StatementWordKindV1::SourceMaximumDegree,
        family.source_max_degree);
    AddU64Words(
        out.words,
        StatementWordKindV1::SourceMaximumComposedDegree,
        family.source_max_composed_degree);
    AddWord(
        out.words, StatementWordKindV1::SourceQuotientLen,
        family.source_quotient_len);
    AddWord(
        out.words, StatementWordKindV1::SourceNCoeffs,
        family.source_n_coeffs);
    AddWord(
        out.words, StatementWordKindV1::SourceNLde,
        family.source_n_lde);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledCurrentWidth,
        family.compiled_current_width);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledNextWidth,
        family.compiled_next_width);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledChallengeWidth,
        family.compiled_challenge_width);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledConstraintCount,
        family.compiled_constraint_count);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledInstructionCount,
        family.compiled_instruction_count);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledChallengeLoads,
        family.compiled_challenge_loads);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledMaximumDegree,
        family.compiled_max_degree);
    AddU64Words(
        out.words,
        StatementWordKindV1::CompiledMaximumComposedDegree,
        family.compiled_max_composed_degree);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledQuotientLen,
        family.compiled_quotient_len);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledNCoeffs,
        family.compiled_n_coeffs);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledNLde,
        family.compiled_n_lde);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledPhysicalColumns,
        family.compiled_physical_columns);
    AddWord(
        out.words, StatementWordKindV1::SemanticRows,
        family.semantic_rows);
    AddWord(
        out.words, StatementWordKindV1::PaddedSourceRows,
        family.padded_source_rows);
    AddU64Words(
        out.words,
        StatementWordKindV1::VerticalLogicalRows,
        family.vertical_logical_rows);
    AddU64Words(
        out.words,
        StatementWordKindV1::VerticalPaddedRows,
        family.vertical_padded_rows);
    AddU64Words(
        out.words,
        StatementWordKindV1::CoefficientCap,
        family.coefficient_cap);
    AddWord(
        out.words, StatementWordKindV1::MinimumVmSegments,
        family.minimum_vm_segments);
    AddWord(
        out.words,
        StatementWordKindV1::SourceTableCanonical,
        family.source_table_canonical ? 1U : 0U);
    AddWord(
        out.words,
        StatementWordKindV1::SourceTableNonStub,
        family.source_table_non_stub ? 1U : 0U);
    AddWord(
        out.words,
        StatementWordKindV1::ChallengeClassDegreeChecked,
        family.challenge_class_degree_checked ? 1U : 0U);
    AddWord(
        out.words,
        StatementWordKindV1::CompiledTableCanonical,
        family.compiled_table_canonical ? 1U : 0U);
    AddWord(
        out.words, StatementWordKindV1::ExactQ192Rows,
        family.exact_q192_rows ? 1U : 0U);
    AddWord(
        out.words,
        StatementWordKindV1::QuotientAndLdeBoundsDerived,
        family.quotient_and_lde_bounds_derived ? 1U : 0U);
    AddWord(
        out.words, StatementWordKindV1::WithinCoefficientCap,
        family.within_coefficient_cap ? 1U : 0U);
    AddWord(
        out.words, StatementWordKindV1::ConstantWidth53,
        family.constant_width_53 ? 1U : 0U);
    return true;
}

bool AppendAliSameParentBridgeV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const AliSameParentRefsV1& refs,
    AppendResultV1& out,
    std::string* why)
{
    out = {};
    if (refs.version !=
            kAliSameParentBridgeVersionV1 ||
        parent_cs.n_rows < 2 ||
        (parent_cs.n_rows &
         (parent_cs.n_rows - 1U)) != 0 ||
        parent_columns.size() != parent_cs.n_columns) {
        return Fail(why, "parent_shape");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "column_rows");
        }
    }
    CanonicalAliVmStatementV1 statement;
    if (!BuildCanonicalAliVmStatementV1(
            refs.family_index, statement, why) ||
        refs.words.size() != statement.words.size()) {
        return Fail(why, "statement_shape");
    }

    std::vector<PendingEquality> pending;
    pending.reserve(
        3 * kAliDigestLanesV1 +
        statement.words.size());
    std::set<uint64_t> used;
    for (uint32_t lane = 0;
         lane < kAliDigestLanesV1;
         ++lane) {
        const auto add_digest =
            [&](const CellPairV1& cells,
                gf::Fp value) {
                if (value >= gf::kP) {
                    return Fail(
                        why,
                        "noncanonical_digest_limb");
                }
                // A canonical Goldilocks limb is transported as two exact
                // u32 cells elsewhere when hashed. Here the parent cell is a
                // field cell and is pinned to that canonical field value.
                if (!ValidCell(
                        cells.manifest_producer,
                        parent_cs) ||
                    !ValidCell(
                        cells.normalized_vm_consumer,
                        parent_cs) ||
                    cells.manifest_producer ==
                        cells.normalized_vm_consumer ||
                    ReferencedColumnPreprocessed(
                        cells.manifest_producer.column,
                        parent_cs) ||
                    ReferencedColumnPreprocessed(
                        cells.normalized_vm_consumer.column,
                        parent_cs) ||
                    !used.insert(
                        CellIdentity(
                            cells.manifest_producer)).second ||
                    !used.insert(
                        CellIdentity(
                            cells.normalized_vm_consumer)).second ||
                    !CanonicalBaseCell(
                        parent_columns[
                            cells.manifest_producer.column]
                            [cells.manifest_producer.row]) ||
                    !CanonicalBaseCell(
                        parent_columns[
                            cells.normalized_vm_consumer.column]
                            [cells.normalized_vm_consumer.row]) ||
                    !gf::Eq(
                        parent_columns[
                            cells.manifest_producer.column]
                            [cells.manifest_producer.row],
                        Fp3::FromFp(value)) ||
                    !gf::Eq(
                        parent_columns[
                            cells.normalized_vm_consumer.column]
                            [cells.normalized_vm_consumer.row],
                        Fp3::FromFp(value))) {
                    return Fail(why, "digest_cell");
                }
                // PendingEquality stores u32. Digest limbs require the full
                // base-field value, so append them below through a separate
                // exact-Fp path.
                return true;
            };
        if (!add_digest(
                refs.manifest_commitment[lane],
                statement.manifest_commitment[lane]) ||
            !add_digest(
                refs.source_program_key[lane],
                statement.source_program_key[lane]) ||
            !add_digest(
                refs.compiled_program_key[lane],
                statement.compiled_program_key[lane])) {
            return false;
        }
    }

    // Digest limbs need full Fp constants; the carrier helper's statement
    // scalar is u32. Append them with an exact local helper before u32 words.
    struct PendingFp {
        CellPairV1 cells;
        Fp3 expected;
    };
    std::vector<PendingFp> pending_fp;
    pending_fp.reserve(3 * kAliDigestLanesV1);
    for (uint32_t lane = 0;
         lane < kAliDigestLanesV1;
         ++lane) {
        pending_fp.push_back({
            refs.manifest_commitment[lane],
            Fp3::FromFp(
                statement.manifest_commitment[lane])});
        pending_fp.push_back({
            refs.source_program_key[lane],
            Fp3::FromFp(
                statement.source_program_key[lane])});
        pending_fp.push_back({
            refs.compiled_program_key[lane],
            Fp3::FromFp(
                statement.compiled_program_key[lane])});
    }

    for (uint32_t index = 0;
         index < statement.words.size();
         ++index) {
        if (refs.words[index].kind !=
                statement.words[index].kind ||
            refs.words[index].ordinal !=
                statement.words[index].ordinal ||
            !AddPending(
                refs.words[index].cells,
                statement.words[index].value,
                parent_cs, parent_columns,
                used, pending, why)) {
            return Fail(why, "word_order_or_cell");
        }
    }

    out.family_index = refs.family_index;
    out.original_columns = parent_cs.n_columns;
    out.equality_layouts.reserve(
        pending_fp.size() + pending.size());
    const auto append_fp =
        [&](const PendingFp& entry,
            EqualityLayoutV1& layout) {
            CellRefV1 source =
                entry.cells.manifest_producer;
            CellRefV1 sink =
                entry.cells.normalized_vm_consumer;
            if (source.row > sink.row) {
                std::swap(source, sink);
            }
            layout.same_row = source.row == sink.row;
            if (layout.same_row) {
                layout.source_selector =
                    parent_cs.n_columns++;
                parent_columns.push_back(
                    std::vector<Fp3>(
                        parent_cs.n_rows,
                        Fp3::Zero()));
                InstallSelector(
                    parent_cs, parent_columns,
                    layout.source_selector,
                    source.row);
                const uint32_t selector =
                    layout.source_selector;
                const Fp3 expected = entry.expected;
                parent_cs.constraints.push_back({
                    "stage3.ali_same_parent.digest_exact",
                    aq::AirKind::kEverywhere, 2,
                    [selector, source, expected](
                        const std::vector<Fp3>& current,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            current[selector],
                            gf::Sub(
                                current[source.column],
                                expected));
                    }});
                parent_cs.constraints.push_back({
                    "stage3.ali_same_parent.digest_equal",
                    aq::AirKind::kEverywhere, 2,
                    [selector, source, sink](
                        const std::vector<Fp3>& current,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            current[selector],
                            gf::Sub(
                                current[source.column],
                                current[sink.column]));
                    }});
                return;
            }
            layout.carrier =
                parent_cs.n_columns++;
            layout.source_selector =
                parent_cs.n_columns++;
            layout.sink_selector =
                parent_cs.n_columns++;
            layout.carry_selector =
                parent_cs.n_columns++;
            parent_columns.resize(
                parent_cs.n_columns,
                std::vector<Fp3>(
                    parent_cs.n_rows,
                    Fp3::Zero()));
            for (uint32_t row = source.row;
                 row <= sink.row;
                 ++row) {
                parent_columns[layout.carrier][row] =
                    entry.expected;
            }
            InstallSelector(
                parent_cs, parent_columns,
                layout.source_selector, source.row);
            InstallSelector(
                parent_cs, parent_columns,
                layout.sink_selector, sink.row);
            for (uint32_t row = source.row;
                 row < sink.row;
                 ++row) {
                parent_columns[
                    layout.carry_selector][row] =
                    Fp3::One();
            }
            parent_cs.preprocessed.push_back({
                layout.carry_selector,
                parent_columns[
                    layout.carry_selector]});
            const uint32_t carrier = layout.carrier;
            const uint32_t source_selector =
                layout.source_selector;
            const uint32_t sink_selector =
                layout.sink_selector;
            const uint32_t carry_selector =
                layout.carry_selector;
            const Fp3 expected = entry.expected;
            parent_cs.constraints.push_back({
                "stage3.ali_same_parent.digest_source_exact",
                aq::AirKind::kEverywhere, 2,
                [source_selector, source, expected](
                    const std::vector<Fp3>& current,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        current[source_selector],
                        gf::Sub(
                            current[source.column],
                            expected));
                }});
            parent_cs.constraints.push_back({
                "stage3.ali_same_parent.digest_source",
                aq::AirKind::kEverywhere, 2,
                [carrier, source_selector, source](
                    const std::vector<Fp3>& current,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        current[source_selector],
                        gf::Sub(
                            current[carrier],
                            current[source.column]));
                }});
            parent_cs.constraints.push_back({
                "stage3.ali_same_parent.digest_sink",
                aq::AirKind::kEverywhere, 2,
                [carrier, sink_selector, sink](
                    const std::vector<Fp3>& current,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        current[sink_selector],
                        gf::Sub(
                            current[carrier],
                            current[sink.column]));
                }});
            parent_cs.constraints.push_back({
                "stage3.ali_same_parent.digest_carry",
                aq::AirKind::kTransition, 2,
                [carrier, carry_selector](
                    const std::vector<Fp3>& current,
                    const std::vector<Fp3>& next) {
                    return gf::Mul(
                        current[carry_selector],
                        gf::Sub(
                            next[carrier],
                            current[carrier]));
                }});
        };
    for (const PendingFp& entry : pending_fp) {
        EqualityLayoutV1 layout;
        append_fp(entry, layout);
        out.equality_layouts.push_back(layout);
    }
    for (const PendingEquality& entry : pending) {
        EqualityLayoutV1 layout;
        AppendEquality(
            parent_cs, parent_columns,
            entry, layout);
        out.equality_layouts.push_back(layout);
    }

    out.manifest_commitment_equalities =
        kAliDigestLanesV1;
    out.source_key_equalities =
        kAliDigestLanesV1;
    out.compiled_key_equalities =
        kAliDigestLanesV1;
    out.statement_word_equalities =
        static_cast<uint32_t>(pending.size());
    out.equality_count =
        static_cast<uint32_t>(
            out.equality_layouts.size());
    out.appended_columns =
        parent_cs.n_columns - out.original_columns;
    for (const StatementWordV1& word :
         statement.words) {
        switch (word.kind) {
        case StatementWordKindV1::SourceMaximumDegree:
        case StatementWordKindV1::SourceMaximumComposedDegree:
        case StatementWordKindV1::CompiledMaximumDegree:
        case StatementWordKindV1::CompiledMaximumComposedDegree:
            ++out.degree_words_constrained;
            break;
        case StatementWordKindV1::SourceConstraintCount:
        case StatementWordKindV1::CompiledConstraintCount:
            ++out.constraint_count_words_constrained;
            break;
        case StatementWordKindV1::SemanticRows:
        case StatementWordKindV1::PaddedSourceRows:
        case StatementWordKindV1::VerticalLogicalRows:
        case StatementWordKindV1::VerticalPaddedRows:
        case StatementWordKindV1::CoefficientCap:
        case StatementWordKindV1::MinimumVmSegments:
            ++out.row_and_cap_words_constrained;
            break;
        default:
            break;
        }
    }
    out.exact_manifest_commitment_root_pinned = true;
    out.exact_source_and_compiled_keys_pinned = true;
    out.exact_word_order_and_values_pinned = true;
    out.literal_parent_refs_reused = true;
    out.cross_row_transport_constrained = true;
    out.only_position_selectors_preprocessed = true;
    out.actual_values_preprocessed = false;
    // Row-wise proofs authenticate the sparse selector columns by canonical
    // dual-OOD evaluation; no actual manifest/VM value is preprocessed.
    parent_cs.preprocessed_pin_ood = true;
    out.normalized_vm_cell_ownership_proved =
        kAliSameParentNormalizedVmOwnershipProvedV1;
    out.canonical_manifest_hash_replayed_in_parent = false;
    out.recursively_consumed =
        kAliSameParentRecursiveConsumptionV1;
    out.recursive_authority =
        kAliSameParentAuthorityV1;
    out.residuals = {
        "typed_normalized_vm_owner_chip_not_yet_attached",
        "canonical_manifest_alg_hash_not_replayed_in_parent",
        "joined_parent_recursive_proof_not_executed"};
    out.valid =
        out.equality_count ==
            3 * kAliDigestLanesV1 +
                statement.words.size() &&
        !out.normalized_vm_cell_ownership_proved &&
        !out.canonical_manifest_hash_replayed_in_parent &&
        !out.recursively_consumed &&
        !out.recursive_authority;
    out.note = out.valid
        ? "stage3:ali_same_parent:exact canonical manifest, keys, "
          "degree, constraint, row and cap cells constrained; "
          "typed VM ownership/hash replay/recursive consumption pending"
        : "stage3:ali_same_parent:append_invariant";
    return out.valid;
}

uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows == 0) {
        return UINT32_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT32_MAX;
        }
    }
    uint32_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            bool active = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                active = true;
                break;
            case aq::AirKind::kTransition:
                active = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                active = row == 0;
                break;
            case aq::AirKind::kLastRow:
                active = row + 1 == cs.n_rows;
                break;
            }
            if (active &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_ali_same_parent_bridge
