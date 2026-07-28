// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air {
namespace {

using gf::Fp3;

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint32_t out = 1;
    while (out < value) out <<= 1;
    return out;
}

uint32_t MaxDegree(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(
            out, constraint.alg_degree);
    }
    return out;
}

struct PhaseViewV1 {
    PhaseV1 phase{PhaseV1::ParentJoin};
    const aq::AirConstraintSystem<Fp3>* cs{nullptr};
    const std::vector<std::vector<Fp3>>* columns{nullptr};
};

bool ShapeExact(const PhaseViewV1& phase)
{
    if (phase.cs == nullptr ||
        phase.columns == nullptr ||
        phase.cs->n_rows < 2 ||
        phase.cs->n_columns == 0 ||
        phase.columns->size() !=
            phase.cs->n_columns) {
        return false;
    }
    for (const auto& column :
         *phase.columns) {
        if (column.size() != phase.cs->n_rows) {
            return false;
        }
    }
    for (const auto& [column, values] :
         phase.cs->preprocessed) {
        if (column >= phase.cs->n_columns ||
            values.size() != phase.cs->n_rows) {
            return false;
        }
    }
    return true;
}

std::vector<uint32_t> PreprocessedColumns(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    std::vector<uint32_t> out;
    out.reserve(cs.preprocessed.size());
    for (const auto& [column, values] :
         cs.preprocessed) {
        (void)values;
        out.push_back(column);
    }
    std::sort(out.begin(), out.end());
    out.erase(
        std::unique(out.begin(), out.end()),
        out.end());
    return out;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> out;
    out.name = name;
    out.kind = kind;
    out.alg_degree = degree;
    out.eval = std::move(eval);
    cs.constraints.push_back(
        std::move(out));
}

void AddSchedulerConstraints(
    const LayoutV1& layout,
    aq::AirConstraintSystem<Fp3>& cs)
{
    AppendAcceptanceOutputConstraintsV1(
        layout, cs);
    AddConstraint(
        cs,
        "stage3.v11_unified.active_boolean",
        aq::AirKind::kEverywhere, 2,
        [active = layout.active](
            const auto& cur,
            const auto&) {
            return gf::Mul(
                cur[active],
                gf::Sub(
                    cur[active],
                    Fp3::One()));
        });
    AddConstraint(
        cs,
        "stage3.v11_unified.one_hot_sum",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const auto& cur,
            const auto&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t phase = 0;
                 phase < kPhasesV1;
                 ++phase) {
                sum = gf::Add(
                    sum,
                    cur[layout.PhaseTag(
                        static_cast<PhaseV1>(
                            phase))]);
            }
            return gf::Sub(
                sum, cur[layout.active]);
        });
    for (uint32_t index = 0;
         index < kPhasesV1;
         ++index) {
        const auto phase =
            static_cast<PhaseV1>(index);
        const uint32_t tag =
            layout.PhaseTag(phase);
        AddConstraint(
            cs,
            "stage3.v11_unified.phase_boolean",
            aq::AirKind::kEverywhere, 2,
            [tag](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[tag],
                    gf::Sub(
                        cur[tag],
                        Fp3::One()));
            });
        for (uint32_t selector : {
                 layout.PhaseFirst(phase),
                 layout.PhaseLast(phase),
                 layout.PhaseTransition(phase)}) {
            AddConstraint(
                cs,
                "stage3.v11_unified."
                "phase_selector_subset",
                aq::AirKind::kEverywhere, 2,
                [tag, selector](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[selector],
                        gf::Sub(
                            Fp3::One(),
                            cur[tag]));
                });
        }
    }
}

void AddGatedPhaseConstraint(
    const LayoutV1& layout,
    PhaseV1 phase,
    const aq::AirConstraint<Fp3>& local,
    aq::AirConstraintSystem<Fp3>& out)
{
    uint32_t selector = layout.PhaseTag(phase);
    aq::AirKind global_kind =
        aq::AirKind::kEverywhere;
    switch (local.kind) {
    case aq::AirKind::kEverywhere:
        selector = layout.PhaseTag(phase);
        break;
    case aq::AirKind::kTransition:
        selector =
            layout.PhaseTransition(phase);
        global_kind =
            aq::AirKind::kTransition;
        break;
    case aq::AirKind::kFirstRow:
        selector = layout.PhaseFirst(phase);
        break;
    case aq::AirKind::kLastRow:
        selector = layout.PhaseLast(phase);
        break;
    }
    auto eval = local.eval;
    AddConstraint(
        out,
        local.name == nullptr
        ? "stage3.v11_unified.unnamed_local"
        : local.name,
        global_kind,
        local.alg_degree + 1,
        [selector, eval = std::move(eval)](
            const auto& cur,
            const auto& next) {
            return gf::Mul(
                cur[selector],
                eval(cur, next));
        });
}

} // namespace

void AppendAcceptanceOutputConstraintsV1(
    const LayoutV1& layout,
    aq::AirConstraintSystem<Fp3>& cs)
{
    AddConstraint(
        cs,
        "stage3.v11_unified.acceptance_boolean",
        aq::AirKind::kEverywhere, 2,
        [acceptance = layout.acceptance](
            const auto& cur,
            const auto&) {
            return gf::Mul(
                cur[acceptance],
                gf::Sub(
                    cur[acceptance],
                    Fp3::One()));
        });
    AddConstraint(
        cs,
        "stage3.v11_unified.acceptance_output",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const auto& cur,
            const auto&) {
            return gf::Sub(
                cur[layout.acceptance],
                cur[layout.PhaseFirst(
                    PhaseV1::ParentJoin)]);
        });
}

ProductV1 BuildProductV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range)
{
    ProductV1 out;
    out.range = range;
    auto fail = [&out](
                    const std::string& detail) {
        out.valid_foundation = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_unified_verifier:" +
            detail;
        return out;
    };
    out.exact_q96_range =
        range.ordinal == 0 &&
        range.first_query == 0 &&
        range.query_count == kQ96QueriesV1;
    if (!out.exact_q96_range ||
        input.expected_child_statement_root.IsNull() ||
        !input.parent_join.valid ||
        pj::RecountViolationsV1(
            input.parent_join,
            input.parent_join.columns) != 0) {
        return fail("range_statement_or_parent");
    }

    std::vector<uint32_t> words;
    std::string why;
    if (!abi::EncodeCanonicalV1(
            input.proof.envelope,
            words, nullptr, &why)) {
        return fail("encode:" + why);
    }
    const auto decoded =
        abi::DecodeCanonicalV1(words, &why);
    if (!decoded.has_value() ||
        !decoded->canonical ||
        !decoded->complete) {
        return fail("decode:" + why);
    }

    out.parent_join = input.parent_join;
    out.merkle_fold =
        mf::BuildShardV1(
            *decoded, input.transcript,
            range.first_query,
            range.query_count);
    if (!out.merkle_fold.valid) {
        return fail(
            "merkle:" +
            out.merkle_fold.note);
    }
    out.deep_vm =
        dvm::BuildProductV1(
            input.proof,
            input.transcript,
            input.child_program,
            input.expected_child_program_root,
            range.first_query,
            range.query_count);
    if (!out.deep_vm.valid) {
        return fail(
            "deep_vm:" +
            out.deep_vm.note);
    }
    out.decoder =
        dj::BuildProductV1(
            *decoded, out.parent_join,
            {out.merkle_fold});
    if (!out.decoder.valid ||
        dj::RecountViolationsV1(
            out.decoder,
            out.decoder.columns) != 0) {
        return fail(
            "decoder:" +
            out.decoder.note);
    }

    const std::array<PhaseViewV1, kPhasesV1>
        views{{
            {PhaseV1::ParentJoin,
             &out.parent_join.cs,
             &out.parent_join.columns},
            {PhaseV1::MerkleHash,
             &out.merkle_fold.hash_cs,
             &out.merkle_fold.hash_columns},
            {PhaseV1::MerkleFold,
             &out.merkle_fold.fold_cs,
             &out.merkle_fold.fold_columns},
            {PhaseV1::DeepVm,
             &out.deep_vm.cs,
             &out.deep_vm.columns},
            {PhaseV1::Decoder,
             &out.decoder.cs,
             &out.decoder.columns},
        }};
    for (const auto& view : views) {
        if (!ShapeExact(view)) {
            return fail("phase_shape");
        }
    }

    uint64_t active_rows = 0;
    uint32_t max_width = 0;
    uint64_t expected_pins = 0;
    for (uint32_t index = 0;
         index < views.size();
         ++index) {
        const auto& view = views[index];
        auto& shape = out.phases[index];
        shape.phase = view.phase;
        shape.first_row =
            static_cast<uint32_t>(
                active_rows);
        shape.rows = view.cs->n_rows;
        shape.columns =
            view.cs->n_columns;
        shape.constraints =
            static_cast<uint32_t>(
                view.cs->constraints.size());
        shape.preprocessed_columns =
            static_cast<uint32_t>(
                view.cs->preprocessed.size());
        shape.max_degree =
            MaxDegree(*view.cs);
        active_rows += view.cs->n_rows;
        max_width =
            std::max(
                max_width,
                view.cs->n_columns);
        expected_pins +=
            view.cs->preprocessed.size();
    }
    if (active_rows >
            std::numeric_limits<uint32_t>::max() ||
        expected_pins >
            std::numeric_limits<uint32_t>::max()) {
        return fail("inventory_overflow");
    }
    out.active_rows =
        static_cast<uint32_t>(
            active_rows);
    out.trace_rows =
        NextPowerOfTwo(active_rows);
    out.trace_cap_fits =
        out.trace_rows != 0 &&
        out.trace_rows <=
            kTraceRowsCapV1;
    out.lde_cap_fits =
        out.trace_rows != 0 &&
        uint64_t{out.trace_rows} *
                kRCFriBlowup <=
            kLdeRowsCapV1;
    if (!out.trace_cap_fits ||
        !out.lde_cap_fits) {
        return fail("row_cap");
    }

    out.expected_preprocessed_columns =
        static_cast<uint32_t>(
            expected_pins);
    out.layout.data_columns = max_width;
    uint32_t cursor = max_width;
    out.layout.phase_tag_base = cursor;
    cursor += kPhasesV1;
    out.layout.phase_first_base = cursor;
    cursor += kPhasesV1;
    out.layout.phase_last_base = cursor;
    cursor += kPhasesV1;
    out.layout.phase_transition_base = cursor;
    cursor += kPhasesV1;
    out.layout.active = cursor++;
    out.layout.acceptance = cursor++;
    out.layout.expected_preprocessed_base =
        cursor;
    cursor +=
        out.expected_preprocessed_columns;
    out.layout.n_columns = cursor;
    out.trace_columns = cursor;
    out.materialized_trace_cells =
        uint64_t{out.trace_rows} *
        out.trace_columns;
    out.columns.assign(
        out.trace_columns,
        std::vector<Fp3>(
            out.trace_rows,
            Fp3::Zero()));
    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns =
        out.trace_columns;
    out.cs.preprocessed_pin_ood = true;

    std::vector<Fp3> active_schedule(
        out.trace_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < out.active_rows;
         ++row) {
        active_schedule[row] = Fp3::One();
        out.columns[out.layout.active][row] =
            Fp3::One();
    }
    out.columns[out.layout.acceptance][0] =
        Fp3::One();
    out.cs.preprocessed.emplace_back(
        out.layout.active,
        active_schedule);

    uint32_t expected_cursor =
        out.layout.expected_preprocessed_base;
    for (uint32_t index = 0;
         index < views.size();
         ++index) {
        const auto& view = views[index];
        const auto& shape = out.phases[index];
        const uint32_t first = shape.first_row;
        const uint32_t last =
            first + shape.rows - 1;
        for (uint32_t column = 0;
             column < view.cs->n_columns;
             ++column) {
            std::copy(
                (*view.columns)[column].begin(),
                (*view.columns)[column].end(),
                out.columns[column].begin() +
                    first);
        }

        std::vector<Fp3> tag(
            out.trace_rows, Fp3::Zero());
        std::vector<Fp3> first_tag(
            out.trace_rows, Fp3::Zero());
        std::vector<Fp3> last_tag(
            out.trace_rows, Fp3::Zero());
        std::vector<Fp3> transition_tag(
            out.trace_rows, Fp3::Zero());
        for (uint32_t row = first;
             row <= last;
             ++row) {
            tag[row] = Fp3::One();
            if (row < last) {
                transition_tag[row] =
                    Fp3::One();
            }
        }
        first_tag[first] = Fp3::One();
        last_tag[last] = Fp3::One();
        for (const auto& [column, canonical] :
             view.cs->preprocessed) {
            const uint32_t expected =
                expected_cursor++;
            std::copy(
                canonical.begin(),
                canonical.end(),
                out.columns[expected].begin() +
                    first);
            out.cs.preprocessed.emplace_back(
                expected,
                out.columns[expected]);
            AddConstraint(
                out.cs,
                "stage3.v11_unified."
                "phase_preprocessed_equality",
                aq::AirKind::kEverywhere, 2,
                [phase_tag =
                     out.layout.PhaseTag(
                         view.phase),
                 column, expected](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[phase_tag],
                        gf::Sub(
                            cur[column],
                            cur[expected]));
                });
        }
        for (const auto& constraint :
             view.cs->constraints) {
            AddGatedPhaseConstraint(
                out.layout, view.phase,
                constraint, out.cs);
        }
        const std::array<
            std::pair<uint32_t,
                      std::vector<Fp3>>, 4>
            schedule{{
                {out.layout.PhaseTag(
                     view.phase),
                 std::move(tag)},
                {out.layout.PhaseFirst(
                     view.phase),
                 std::move(first_tag)},
                {out.layout.PhaseLast(
                     view.phase),
                 std::move(last_tag)},
                {out.layout.PhaseTransition(
                     view.phase),
                 std::move(transition_tag)},
            }};
        for (const auto& [column, values] :
             schedule) {
            out.columns[column] = values;
            out.cs.preprocessed.emplace_back(
                column, values);
        }
    }
    if (expected_cursor !=
        out.layout.n_columns) {
        return fail("expected_pin_inventory");
    }
    AddSchedulerConstraints(
        out.layout, out.cs);

    out.preprocessed_columns =
        PreprocessedColumns(out.cs);
    out.constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    out.max_constraint_degree =
        MaxDegree(out.cs);
    out.quotient_len =
        out.cs.QuotientLen();
    const uint32_t commitment_coeffs =
        NextPowerOfTwo(std::max(
            out.trace_rows,
            out.quotient_len));
    out.commitment_coefficients =
        commitment_coeffs;
    out.commitment_lde_rows =
        uint64_t{commitment_coeffs} *
        kRCFriBlowup;
    out.quotient_cap_audit_complete =
        commitment_coeffs != 0;
    out.cs_independent_of_child_witness =
        false;
    out.verifier_input_excludes_child_proof =
        false;
    out.lde_cap_fits =
        commitment_coeffs != 0 &&
        out.commitment_lde_rows <=
            kLdeRowsCapV1;
    if (!out.lde_cap_fits) {
        return fail(
            "quotient_lde_cap;rows=" +
            std::to_string(out.trace_rows) +
            ";cols=" +
            std::to_string(out.trace_columns) +
            ";degree=" +
            std::to_string(
                out.max_constraint_degree) +
            ";quotient=" +
            std::to_string(out.quotient_len));
    }
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        return fail(
            "r0_root:" + session.note);
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.preprocessed_columns,
        .root =
            out.preprocessed_row_group_root,
    });
    out.violations =
        air_recurse::
            CountWitnessViolationsOnH(
                out.cs, out.columns);
    out.all_five_phases_executable =
        out.parent_join.valid &&
        out.merkle_fold.valid &&
        out.deep_vm.valid &&
        out.decoder.valid;
    out.vertical_max_width_layout =
        out.layout.data_columns ==
            std::max({
                out.parent_join.cs.n_columns,
                out.merkle_fold.hash_cs.n_columns,
                out.merkle_fold.fold_cs.n_columns,
                out.deep_vm.cs.n_columns,
                out.decoder.cs.n_columns});
    out.one_hot_row_scheduler_constrained =
        true;
    out.local_boundary_kinds_preserved =
        true;
    out.every_phase_preprocessed_pin_r0_bound =
        expected_cursor -
            out.layout
                .expected_preprocessed_base ==
            out.expected_preprocessed_columns &&
        !out.preprocessed_row_group_root.IsNull();
    out.acceptance_ordinary_witness =
        std::find(
            out.preprocessed_columns.begin(),
            out.preprocessed_columns.end(),
            out.layout.acceptance) ==
        out.preprocessed_columns.end();
    out.acceptance_unique =
        std::count_if(
            out.columns[
                out.layout.acceptance].begin(),
            out.columns[
                out.layout.acceptance].end(),
            [](const Fp3& value) {
                return gf::Eq(
                    value, Fp3::One());
            }) == 1 &&
        gf::Eq(
            out.columns[
                out.layout.acceptance][0],
            Fp3::One());
    out.whole_verifier_acceptance_constrained =
        out.acceptance_ordinary_witness &&
        out.acceptance_unique;
    out.direct_cross_phase_cell_carries_complete =
        false;
    out.recursive_authority_ready = false;
    out.valid_foundation =
        out.exact_q96_range &&
        out.all_five_phases_executable &&
        out.vertical_max_width_layout &&
        out.one_hot_row_scheduler_constrained &&
        out.local_boundary_kinds_preserved &&
        out.every_phase_preprocessed_pin_r0_bound &&
        out.acceptance_ordinary_witness &&
        out.acceptance_unique &&
        out.whole_verifier_acceptance_constrained &&
        out.trace_cap_fits &&
        out.lde_cap_fits &&
        out.violations == 0 &&
        out.cs_independent_of_child_witness &&
        out.verifier_input_excludes_child_proof &&
        !out.direct_cross_phase_cell_carries_complete &&
        !out.recursive_authority_ready;
    out.note = out.valid_foundation
        ? "stage3:v11_unified_verifier:"
          "five_phase_vertical_split_rap;"
          "direct_cross_phase_carries_open"
        : "stage3:v11_unified_verifier:"
          "constraint_failure";
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() !=
        product.cs.n_columns) {
        return
            std::numeric_limits<
                uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() !=
            product.cs.n_rows) {
            return
                std::numeric_limits<
                    uint64_t>::max();
        }
    }
    return
        air_recurse::
            CountWitnessViolationsOnH(
                product.cs, columns);
}

ProveResultV1 ProveV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const uint256& public_fs_seed)
{
    ProveResultV1 out;
    const auto product =
        BuildProductV1(input, range);
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    if (!product.valid_foundation ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_unified_verifier:"
            "prove:" + product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            public_fs_seed);
    out.prove_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            begin).count();
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.note =
            "stage3:v11_unified_verifier:"
            "prove:" + proved.note;
        return out;
    }
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    if (bytes == 0 || bytes != wire.size()) {
        out.note =
            "stage3:v11_unified_verifier:"
            "prove:serialize";
        return out;
    }
    out.proof = proved.proof;
    out.proof_wire_bytes = bytes;
    out.ok = true;
    out.note =
        "stage3:v11_unified_verifier:"
        "prove:five_phase;"
        "carry_residual_open";
    return out;
}

VerifyResultV1 VerifyV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed)
{
    VerifyResultV1 out;
    const auto product =
        BuildProductV1(input, range);
    if (!product.valid_foundation ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_unified_verifier:"
            "verify:" + product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    std::string why;
    out.accepted =
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proof,
            product.preprocessed_columns,
            public_fs_seed, &why);
    out.verify_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            begin).count();
    if (proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.accepted = false;
        why = "r0_root";
    }
    out.direct_cross_phase_cell_carries_complete =
        product
            .direct_cross_phase_cell_carries_complete;
    out.recursive_authority_ready = false;
    out.note = out.accepted
        ? "stage3:v11_unified_verifier:"
          "verify:five_phase;"
          "carry_residual_open"
        : "stage3:v11_unified_verifier:"
          "verify:" + why;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air
