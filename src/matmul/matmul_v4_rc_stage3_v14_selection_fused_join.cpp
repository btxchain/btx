// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v14_selection_fused_join.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_v14_selection_fused_join {
namespace {

using gf::Fp3;

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why =
            "stage3:v14_selection_fused_join:" + reason;
    }
    return false;
}

void AddPreprocessed(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(
        column, std::move(values));
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
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

const std::vector<Fp3>* Preprocessed(
    const aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column)
{
    const auto found = std::find_if(
        cs.preprocessed.begin(),
        cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
    return found == cs.preprocessed.end()
        ? nullptr
        : &found->second;
}

bool BuildEventRows(
    const bridge::TypedSafeDirectVerifierCsV14& v14,
    uint32_t event_count,
    std::vector<uint32_t>& out,
    std::string* why)
{
    out.clear();
    const bridge::TypedSafeDirectParentLayoutV14 layout;
    const auto* selector =
        Preprocessed(v14.cs, layout.event_final);
    if (selector == nullptr ||
        selector->size() != v14.trace_rows) {
        return Fail(why, "event_final_selector");
    }
    for (uint32_t row = 0;
         row < selector->size(); ++row) {
        if (gf::Eq((*selector)[row], Fp3::One())) {
            out.push_back(row);
        } else if (!gf::IsZero((*selector)[row])) {
            return Fail(why, "event_final_nonboolean");
        }
    }
    if (out.size() != event_count) {
        return Fail(why, "event_final_multiplicity");
    }
    return true;
}

void AppendShiftedSelectionConstraints(
    const aq::AirConstraintSystem<Fp3>& local,
    uint32_t offset,
    aq::AirConstraintSystem<Fp3>& fused)
{
    for (const auto& constraint : local.constraints) {
        aq::AirConstraint<Fp3> shifted;
        shifted.name = constraint.name;
        shifted.kind = constraint.kind;
        shifted.alg_degree = constraint.alg_degree;
        const auto eval = constraint.eval;
        const uint32_t local_columns = local.n_columns;
        shifted.eval =
            [eval, offset, local_columns](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                std::vector<Fp3> local_current(
                    local_columns, Fp3::Zero());
                std::vector<Fp3> local_next(
                    local_columns, Fp3::Zero());
                for (uint32_t column = 0;
                     column < local_columns; ++column) {
                    local_current[column] =
                        current[offset + column];
                    local_next[column] =
                        next[offset + column];
                }
                return eval(local_current, local_next);
            };
        fused.constraints.push_back(std::move(shifted));
    }
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1)) == 0;
}

} // namespace

LayoutV1 CanonicalLayoutV1(uint32_t edge_count)
{
    LayoutV1 out;
    uint32_t cursor = out.expected_multiplicity + 1;
    out.carry_base = cursor;
    cursor += edge_count;
    out.source_selector_base = cursor;
    cursor += edge_count;
    out.destination_selector_base = cursor;
    cursor += edge_count;
    out.join_selector_base = cursor;
    cursor += edge_count;
    out.dependent_zero = cursor++;
    out.end = cursor;
    return out;
}

bool BuildConstraintSystemV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    aq::AirConstraintSystem<Fp3>& out,
    LayoutV1& layout,
    ScheduleV1& schedule,
    std::string* why)
{
    out = {};
    schedule = {};
    std::string local_why;
    if (!manifest.valid ||
        !occurrence::ValidateCanonicalOccurrenceManifestV1(
            manifest.shape,
            manifest.canonical_program,
            manifest, &local_why)) {
        return Fail(why, "manifest:" + local_why);
    }
    schedule.manifest = manifest;
    schedule.exact_manifest_rebuilt = true;

    bridge::TypedSafeDirectVerifierCsV14 v14;
    if (!bridge::BuildTypedSafeDirectVerifierCsV14(
            manifest.canonical_program,
            expected_transcript_commitment,
            v14, &local_why)) {
        return Fail(why, "v14:" + local_why);
    }
    if (!BuildEventRows(
            v14,
            static_cast<uint32_t>(
                manifest.canonical_program.size()),
            schedule.v14_event_row, why)) {
        return false;
    }

    if (manifest.shape.n_coeffs >
        UINT32_MAX / kRCFriBlowup) {
        return Fail(why, "n_lde_overflow");
    }
    schedule.n_lde =
        manifest.shape.n_coeffs * kRCFriBlowup;
    schedule.query_count =
        selection::kProductionQueriesV1;
    if (!IsPowerOfTwo(schedule.n_lde)) {
        return Fail(why, "n_lde");
    }
    aq::AirConstraintSystem<Fp3> selected_cs;
    selection::CellMapV1 selected_cells;
    if (!selection::BuildConstraintSystemV1(
            schedule.n_lde,
            schedule.query_count,
            selected_cs, selected_cells,
            &local_why)) {
        return Fail(why, "selection:" + local_why);
    }

    std::array<uint32_t, 4> candidate_events{};
    for (uint32_t pair = 0; pair < 2; ++pair) {
        const auto& selector = manifest.selectors[pair];
        if (!selector.candidate_set_public ||
            !selector.selected_ordinal_is_witness_dependent ||
            !selector.first_acceptable_air_required) {
            return Fail(why, "selector_manifest");
        }
        for (uint32_t ordinal = 0;
             ordinal < 2; ++ordinal) {
            candidate_events[2 * pair + ordinal] =
                selector.candidate_events[ordinal];
        }
    }
    std::vector<uint32_t> query_events;
    for (uint32_t event = 0;
         event < manifest.canonical_program.size();
         ++event) {
        if (manifest.canonical_program[event].kind ==
            bridge::TypedSafeChallengeKindV13::
                QueryCandidate) {
            query_events.push_back(event);
        }
    }
    if (query_events.size() != schedule.query_count) {
        return Fail(why, "query_event_multiplicity");
    }

    const bridge::TypedSafeDirectParentLayoutV14 v14_layout;
    for (uint32_t candidate = 0;
         candidate < 4; ++candidate) {
        const uint32_t event = candidate_events[candidate];
        if (event >= schedule.v14_event_row.size()) {
            return Fail(why, "candidate_event");
        }
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            EdgeV1 edge;
            edge.role = EdgeRoleV1::OodCandidate;
            edge.event = event;
            edge.ordinal = candidate;
            edge.coordinate = coordinate;
            edge.source_row =
                schedule.v14_event_row[event];
            edge.source_column =
                v14_layout.Output(coordinate);
            edge.destination_row =
                static_cast<uint32_t>(
                    schedule.edges.size());
            edge.destination_column =
                selected_cells
                    .ood_candidate[candidate]
                    .coordinate[coordinate].column;
            edge.join_row =
                static_cast<uint32_t>(
                    schedule.edges.size());
            schedule.edges.push_back(edge);
            ++schedule.ood_edges;
        }
    }
    for (uint32_t query = 0;
         query < query_events.size(); ++query) {
        const uint32_t event = query_events[query];
        EdgeV1 edge;
        edge.role = EdgeRoleV1::QueryCandidate;
        edge.event = event;
        edge.ordinal = query;
        edge.coordinate = 0;
        edge.source_row =
            schedule.v14_event_row[event];
        edge.source_column = v14_layout.Output(0);
        edge.destination_row =
            selected_cells.query[query]
                .v14_digest_lane0.row;
        edge.destination_column =
            selected_cells.query[query]
                .v14_digest_lane0.column;
        edge.join_row =
            static_cast<uint32_t>(
                schedule.edges.size());
        schedule.edges.push_back(edge);
        ++schedule.query_edges;
    }
    schedule.exact_k2_multiplicity =
        schedule.ood_edges == 12;
    schedule.exact_q192_multiplicity =
        schedule.query_edges ==
            selection::kProductionQueriesV1;
    schedule.trace_rows = v14.trace_rows;
    if (schedule.trace_rows < selected_cs.n_rows ||
        schedule.trace_rows < schedule.edges.size()) {
        return Fail(why, "fused_trace_rows");
    }

    layout = CanonicalLayoutV1(
        static_cast<uint32_t>(schedule.edges.size()));
    for (uint32_t edge = 0;
         edge < schedule.edges.size(); ++edge) {
        schedule.edges[edge].carry_column =
            layout.Carry(edge);
        schedule.edges[edge].source_selector_column =
            layout.SourceSelector(edge);
        schedule.edges[edge].
            destination_selector_column =
            layout.DestinationSelector(edge);
        schedule.edges[edge].join_selector_column =
            layout.JoinSelector(edge);
    }

    out = v14.cs;
    out.n_columns = layout.end;
    AppendShiftedSelectionConstraints(
        selected_cs, layout.selection_base, out);
    for (const auto& [column, values] :
         selected_cs.preprocessed) {
        std::vector<Fp3> extended(
            schedule.trace_rows, Fp3::Zero());
        std::copy(
            values.begin(), values.end(),
            extended.begin());
        AddPreprocessed(
            out, layout.Selection(column),
            std::move(extended));
    }

    std::vector<Fp3> active(
        schedule.trace_rows, Fp3::Zero());
    std::vector<Fp3> expected_role(
        schedule.trace_rows, Fp3::Zero());
    std::vector<Fp3> expected_event(
        schedule.trace_rows, Fp3::Zero());
    std::vector<Fp3> expected_ordinal(
        schedule.trace_rows, Fp3::Zero());
    std::vector<Fp3> expected_coordinate(
        schedule.trace_rows, Fp3::Zero());
    std::vector<Fp3> expected_multiplicity(
        schedule.trace_rows, Fp3::Zero());
    for (uint32_t edge = 0;
         edge < schedule.edges.size(); ++edge) {
        const auto& item = schedule.edges[edge];
        active[item.join_row] = Fp3::One();
        expected_role[item.join_row] =
            U(static_cast<uint32_t>(item.role));
        expected_event[item.join_row] =
            U(item.event);
        expected_ordinal[item.join_row] =
            U(item.ordinal);
        expected_coordinate[item.join_row] =
            U(item.coordinate);
        expected_multiplicity[item.join_row] =
            Fp3::One();

        std::vector<Fp3> source(
            schedule.trace_rows, Fp3::Zero());
        std::vector<Fp3> destination(
            schedule.trace_rows, Fp3::Zero());
        std::vector<Fp3> join(
            schedule.trace_rows, Fp3::Zero());
        source[item.source_row] = Fp3::One();
        destination[item.destination_row] =
            Fp3::One();
        join[item.join_row] = Fp3::One();
        AddPreprocessed(
            out, item.source_selector_column,
            std::move(source));
        AddPreprocessed(
            out, item.destination_selector_column,
            std::move(destination));
        AddPreprocessed(
            out, item.join_selector_column,
            std::move(join));
    }
    AddPreprocessed(
        out, layout.edge_active, std::move(active));
    AddPreprocessed(
        out, layout.expected_role,
        std::move(expected_role));
    AddPreprocessed(
        out, layout.expected_event,
        std::move(expected_event));
    AddPreprocessed(
        out, layout.expected_ordinal,
        std::move(expected_ordinal));
    AddPreprocessed(
        out, layout.expected_coordinate,
        std::move(expected_coordinate));
    AddPreprocessed(
        out, layout.expected_multiplicity,
        std::move(expected_multiplicity));
    out.preprocessed_pin_ood = true;

    for (const auto [value, expected] :
         std::array<std::pair<uint32_t, uint32_t>, 5>{{
             {layout.edge_role, layout.expected_role},
             {layout.edge_event, layout.expected_event},
             {layout.edge_ordinal, layout.expected_ordinal},
             {layout.edge_coordinate,
              layout.expected_coordinate},
             {layout.edge_multiplicity,
              layout.expected_multiplicity},
         }}) {
        AddConstraint(
            out,
            "stage3.v14_fused.edge_metadata",
            aq::AirKind::kEverywhere, 2,
            [layout, value, expected](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.edge_active],
                    gf::Sub(cur[value], cur[expected]));
            });
    }
    for (const uint32_t column : {
             layout.edge_value,
             layout.edge_role,
             layout.edge_event,
             layout.edge_ordinal,
             layout.edge_coordinate,
             layout.edge_multiplicity,
         }) {
        AddConstraint(
            out,
            "stage3.v14_fused.edge_padding_zero",
            aq::AirKind::kEverywhere, 2,
            [layout, column](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.edge_active]),
                    cur[column]);
            });
    }
    for (uint32_t edge = 0;
         edge < schedule.edges.size(); ++edge) {
        const EdgeV1 item = schedule.edges[edge];
        AddConstraint(
            out,
            "stage3.v14_fused.edge_carry_stable",
            aq::AirKind::kTransition, 1,
            [item](
                const auto& cur,
                const auto& next) {
                return gf::Sub(
                    next[item.carry_column],
                    cur[item.carry_column]);
            });
        AddConstraint(
            out,
            "stage3.v14_fused.v14_source",
            aq::AirKind::kEverywhere, 2,
            [item](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[item.source_selector_column],
                    gf::Sub(
                        cur[item.carry_column],
                        cur[item.source_column]));
            });
        AddConstraint(
            out,
            "stage3.v14_fused.selection_destination",
            aq::AirKind::kEverywhere, 2,
            [layout, item](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[item.destination_selector_column],
                    gf::Sub(
                        cur[item.carry_column],
                        cur[layout.Selection(
                            item.destination_column)]));
            });
        AddConstraint(
            out,
            "stage3.v14_fused.edge_table_value",
            aq::AirKind::kEverywhere, 2,
            [layout, item](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[item.join_selector_column],
                    gf::Sub(
                        cur[layout.edge_value],
                        cur[item.carry_column]));
            });
    }
    AddConstraint(
        out,
        "stage3.v14_fused.dependent_zero",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const auto& cur,
            const auto&) {
            return cur[layout.dependent_zero];
        });

    schedule.ordinary_same_parent_cells = true;
    schedule.valid =
        schedule.exact_manifest_rebuilt &&
        schedule.exact_k2_multiplicity &&
        schedule.exact_q192_multiplicity &&
        schedule.ordinary_same_parent_cells &&
        schedule.edges.size() ==
            schedule.ood_edges + schedule.query_edges;
    schedule.note = schedule.valid
        ? "actual V14 OOD/query outputs fused to selection inputs"
        : "invalid V14/selection fused schedule";
    if (!schedule.valid) {
        return Fail(why, "schedule");
    }
    if (why != nullptr) *why = schedule.note;
    return true;
}

ProductV1 BuildProductV1(
    const occurrence::ManifestV1& manifest,
    const bridge::TypedSafeDirectParentProductV14& v14,
    const selection::ProductV1& selected)
{
    ProductV1 out;
    std::string why;
    if (!v14.valid ||
        !selected.valid ||
        v14.program != manifest.canonical_program ||
        v14.trace_rows != v14.cs.n_rows) {
        out.note =
            "stage3:v14_selection_fused_join:product_input";
        return out;
    }
    out.expected_transcript_commitment =
        v14.transcript_commitment;
    if (!BuildConstraintSystemV1(
            manifest,
            out.expected_transcript_commitment,
            out.cs, out.layout,
            out.schedule, &why)) {
        out.note = why;
        return out;
    }
    if (selected.query_count !=
            out.schedule.query_count ||
        selected.trace_rows != selected.cs.n_rows ||
        selected.trace_rows > out.cs.n_rows ||
        v14.cs.n_columns != out.layout.v14_columns ||
        selected.cs.n_columns !=
            out.layout.selection_columns ||
        v14.columns.size() != v14.cs.n_columns ||
        selected.columns.size() !=
            selected.cs.n_columns) {
        out.note =
            "stage3:v14_selection_fused_join:component_shape";
        return out;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (uint32_t column = 0;
         column < v14.cs.n_columns; ++column) {
        if (v14.columns[column].size() != out.cs.n_rows) {
            out.note =
                "stage3:v14_selection_fused_join:v14_rows";
            return out;
        }
        out.columns[column] = v14.columns[column];
    }
    for (uint32_t column = 0;
         column < selected.cs.n_columns; ++column) {
        if (selected.columns[column].size() !=
                selected.cs.n_rows) {
            out.note =
                "stage3:v14_selection_fused_join:"
                "selection_rows";
            return out;
        }
        std::copy(
            selected.columns[column].begin(),
            selected.columns[column].end(),
            out.columns[
                out.layout.Selection(column)].begin());
    }
    // Candidate values are transition-stable in the selection chip. Extend
    // them across the larger V14 trace; every other selection witness cell
    // remains canonical zero beyond the local selection schedule.
    const selection::LayoutV1 selected_layout;
    for (uint32_t candidate = 0;
         candidate < selection::kOodCandidatesV1;
         ++candidate) {
        for (uint32_t coordinate = 0;
             coordinate <
                 selection::kFp3CoordinatesV1;
             ++coordinate) {
            const uint32_t column =
                out.layout.Selection(
                    selected_layout.Candidate(
                        candidate, coordinate));
            const Fp3 value = out.columns[column][0];
            std::fill(
                out.columns[column].begin() +
                    selected.cs.n_rows,
                out.columns[column].end(),
                value);
        }
    }
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        if (column >= out.columns.size() ||
            values.size() != out.cs.n_rows) {
            out.note =
                "stage3:v14_selection_fused_join:"
                "preprocessed_shape";
            return out;
        }
        out.columns[column] = values;
    }
    for (const auto& edge : out.schedule.edges) {
        const Fp3 value =
            out.columns[edge.source_column]
                       [edge.source_row];
        std::fill(
            out.columns[edge.carry_column].begin(),
            out.columns[edge.carry_column].end(),
            value);
        out.columns[out.layout.edge_value]
                   [edge.join_row] = value;
        out.columns[out.layout.edge_role]
                   [edge.join_row] =
            U(static_cast<uint32_t>(edge.role));
        out.columns[out.layout.edge_event]
                   [edge.join_row] =
            U(edge.event);
        out.columns[out.layout.edge_ordinal]
                   [edge.join_row] =
            U(edge.ordinal);
        out.columns[out.layout.edge_coordinate]
                   [edge.join_row] =
            U(edge.coordinate);
        out.columns[out.layout.edge_multiplicity]
                   [edge.join_row] =
            Fp3::One();
    }
    out.violations =
        CountViolationsV1(out.cs, out.columns);
    for (const auto& constraint : out.cs.constraints) {
        out.max_alg_degree =
            std::max(
                out.max_alg_degree,
                constraint.alg_degree);
    }
    out.v14_constraints_fused = true;
    out.selection_constraints_fused = true;
    out.ood_candidate_outputs_bound =
        out.schedule.ood_edges == 12;
    out.query_candidate_outputs_bound =
        out.schedule.query_edges ==
            selection::kProductionQueriesV1;
    out.query_reduction_local_proof_tape_equality =
        selected.query_reduction_constrained &&
        selected.local_tape_equality_cells_constrained;
    out.actual_proof_tape_cells_bound = false;
    out.selected_z_to_derived_hash_bound = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.v14_constraints_fused &&
        out.selection_constraints_fused &&
        out.ood_candidate_outputs_bound &&
        out.query_candidate_outputs_bound &&
        out.query_reduction_local_proof_tape_equality &&
        !out.actual_proof_tape_cells_bound &&
        !out.selected_z_to_derived_hash_bound &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "V14 OOD/Q192 outputs joined to exact selection chip"
        : "V14 selection fused witness violates constraints";
    return out;
}

bool ProveV1(
    const ProductV1& product,
    const uint256& fs_seed,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.violations != 0 ||
        fs_seed.IsNull() ||
        product.actual_proof_tape_cells_bound ||
        product.selected_z_to_derived_hash_bound ||
        product.recursively_consumed ||
        product.recursive_authority_ready) {
        return Fail(why, "prove_input");
    }
    const auto proved =
        aq::AirQuotientProveRows(
            product.cs, product.columns, fs_seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "prove:" + proved.note);
    }
    out.program_root =
        product.schedule.manifest.program_root;
    out.transcript_commitment =
        product.expected_transcript_commitment;
    out.proof = proved.proof;
    out.note =
        "V14 OOD/query joins proved; proof-tape joins remain";
    return true;
}

bool VerifyV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (proof.version != kFusedSelectionJoinVersionV1 ||
        proof.program_root != manifest.program_root ||
        proof.transcript_commitment !=
            expected_transcript_commitment ||
        fs_seed.IsNull() ||
        proof.actual_proof_tape_cells_bound ||
        proof.selected_z_to_derived_hash_bound ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready) {
        return Fail(why, "proof_envelope");
    }
    aq::AirConstraintSystem<Fp3> cs;
    LayoutV1 layout;
    ScheduleV1 schedule;
    if (!BuildConstraintSystemV1(
            manifest,
            expected_transcript_commitment,
            cs, layout, schedule, why)) {
        return false;
    }
    return aq::AirQuotientVerifyRows(
        cs, proof.proof, fs_seed, why);
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
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            const bool applies =
                constraint.kind == aq::AirKind::kEverywhere ||
                (constraint.kind ==
                     aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind ==
                     aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows) ||
                (constraint.kind ==
                     aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows);
            if (applies &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_v14_selection_fused_join
