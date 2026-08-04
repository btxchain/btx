// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_same_parent_join.h>

#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace matmul::v4::rc::stage3_p2_same_parent_join {
namespace {

namespace ar = air_recurse;

using AirCS = aq::AirConstraintSystem<Fp3>;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:p2_same_parent_join:" + message;
    }
    return false;
}

bool SameCell(const CellRefV1& a, const CellRefV1& b)
{
    return a.column == b.column && a.row == b.row;
}

bool ValidCell(const CellRefV1& ref, const AirCS& cs)
{
    return ref.column < cs.n_columns && ref.row < cs.n_rows;
}

uint32_t EndpointRow(const EndpointV1& endpoint)
{
    return endpoint.kind == EndpointKindV1::Cell
        ? endpoint.cell.row
        : endpoint.row;
}

bool ValidEndpoint(const EndpointV1& endpoint, const AirCS& cs)
{
    switch (endpoint.kind) {
    case EndpointKindV1::Cell:
        return ValidCell(endpoint.cell, cs);
    case EndpointKindV1::PoseidonOutput:
        return endpoint.row < cs.n_rows &&
               endpoint.output_lane < alg_hash::kAlgHashT &&
               endpoint.poseidon.perm.End() <= cs.n_columns;
    case EndpointKindV1::PoseidonOutputFp3:
        return endpoint.row < cs.n_rows &&
               endpoint.poseidon.perm.End() <= cs.n_columns;
    case EndpointKindV1::Fp3Coordinates:
        if (endpoint.row >= cs.n_rows) return false;
        for (const CellRefV1& coordinate :
             endpoint.fp3_coordinates.coord) {
            if (!ValidCell(coordinate, cs) ||
                coordinate.row != endpoint.row) {
                return false;
            }
        }
        return true;
    case EndpointKindV1::LinearCombination:
        if (endpoint.row >= cs.n_rows ||
            endpoint.linear_terms.empty()) {
            return false;
        }
        for (const LinearTermV1& term :
             endpoint.linear_terms) {
            if (!ValidCell(term.cell, cs)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

Fp3 EndpointValue(
    const EndpointV1& endpoint,
    const std::vector<Fp3>& row)
{
    switch (endpoint.kind) {
    case EndpointKindV1::Cell:
        return row[endpoint.cell.column];
    case EndpointKindV1::PoseidonOutput:
        return ar::PermOutputLane(
            endpoint.poseidon.perm, row,
            endpoint.output_lane);
    case EndpointKindV1::PoseidonOutputFp3: {
        const Fp3 u{0, 1, 0};
        const Fp3 u2{0, 0, 1};
        return gf::Add(
            ar::PermOutputLane(
                endpoint.poseidon.perm, row, 0),
            gf::Add(
                gf::Mul(
                    u,
                    ar::PermOutputLane(
                        endpoint.poseidon.perm,
                        row, 1)),
                gf::Mul(
                    u2,
                    ar::PermOutputLane(
                        endpoint.poseidon.perm,
                        row, 2))));
    }
    case EndpointKindV1::Fp3Coordinates: {
        const Fp3 u{0, 1, 0};
        const Fp3 u2{0, 0, 1};
        return gf::Add(
            row[endpoint.fp3_coordinates.coord[0].column],
            gf::Add(
                gf::Mul(
                    u,
                    row[endpoint.fp3_coordinates.coord[1]
                            .column]),
                gf::Mul(
                    u2,
                    row[endpoint.fp3_coordinates.coord[2]
                            .column])));
    }
    case EndpointKindV1::LinearCombination: {
        Fp3 value = endpoint.constant;
        for (const LinearTermV1& term :
             endpoint.linear_terms) {
            value = gf::Add(
                value,
                gf::Mul(
                    row[term.cell.column],
                    Fp3::FromFp(gf::FromU64(
                        term.coefficient))));
        }
        return value;
    }
    }
    return Fp3::Zero();
}

Fp3 EndpointValue(
    const EndpointV1& endpoint,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (endpoint.kind ==
            EndpointKindV1::LinearCombination) {
        Fp3 value = endpoint.constant;
        for (const LinearTermV1& term :
             endpoint.linear_terms) {
            value = gf::Add(
                value,
                gf::Mul(
                    columns[term.cell.column]
                        [term.cell.row],
                    Fp3::FromFp(gf::FromU64(
                        term.coefficient))));
        }
        return value;
    }
    std::vector<Fp3> row(columns.size(), Fp3::Zero());
    const uint32_t source_row = EndpointRow(endpoint);
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        row[column] = columns[column][source_row];
    }
    return EndpointValue(endpoint, row);
}

bool CrossRowLinearCombination(
    const EndpointV1& endpoint)
{
    if (endpoint.kind !=
            EndpointKindV1::LinearCombination) {
        return false;
    }
    return std::any_of(
        endpoint.linear_terms.begin(),
        endpoint.linear_terms.end(),
        [&](const LinearTermV1& term) {
            return term.cell.row != endpoint.row;
        });
}

EndpointV1 CellEndpoint(const CellRefV1& cell)
{
    EndpointV1 out;
    out.kind = EndpointKindV1::Cell;
    out.cell = cell;
    out.row = cell.row;
    return out;
}

EndpointV1 PoseidonEndpoint(
    const pa::Layout& poseidon,
    uint32_t row,
    uint32_t lane)
{
    EndpointV1 out;
    out.kind = EndpointKindV1::PoseidonOutput;
    out.poseidon = poseidon;
    out.output_lane = lane;
    out.row = row;
    return out;
}

bool PackedWordEndpoint(
    const BytesCellRefsV1& bytes,
    size_t offset,
    EndpointV1& out)
{
    if (offset >= bytes.byte.size()) return false;
    out = {};
    out.kind = EndpointKindV1::LinearCombination;
    out.row = bytes.byte[offset].row;
    const uint32_t coefficients[4] = {
        1U, 1U << 8, 1U << 16, 1U << 24};
    for (size_t byte = 0;
         byte < 4 && offset + byte < bytes.byte.size();
         ++byte) {
        const CellRefV1 ref = bytes.byte[offset + byte];
        if (ref.column == kInvalidColumn ||
            ref.row != out.row) {
            return false;
        }
        out.linear_terms.push_back(
            {ref, coefficients[byte]});
    }
    return !out.linear_terms.empty();
}

bool FindEventRows(
    const p2air::BuildResult& transcript,
    uint32_t ordinal,
    uint32_t& start,
    uint32_t& terminal)
{
    bool found_start = false;
    bool found_terminal = false;
    for (uint32_t row = 0;
         row < transcript.cs.n_rows; ++row) {
        const uint32_t event =
            static_cast<uint32_t>(gf::Canonical(
                transcript.columns[
                    transcript.layout.event_ordinal_col][row]
                    .c0));
        const bool active = !gf::IsZero(
            transcript.columns[
                transcript.layout.active_col][row]);
        if (!active || event != ordinal) continue;
        if (!gf::IsZero(
                transcript.columns[
                    transcript.layout.event_start_col][row])) {
            start = row;
            found_start = true;
        }
        if (!gf::IsZero(
                transcript.columns[
                    transcript.layout.terminal_col][row])) {
            terminal = row;
            found_terminal = true;
        }
    }
    return found_start && found_terminal &&
           start <= terminal;
}

CellRefV1 FriMessageCell(
    const p2air::BuildResult& transcript,
    uint32_t event_start,
    uint32_t absorb_lane)
{
    return {
        transcript.layout.MessageCol(
            0, absorb_lane % alg_hash::kAlgHashRate),
        event_start +
            absorb_lane / alg_hash::kAlgHashRate};
}

CellRefV1 AirqMessageCell(
    const airq::BuildResult& transcript,
    uint32_t absorb_lane)
{
    return {
        transcript.layout.MessageCol(
            absorb_lane % alg_hash::kAlgHashRate),
        absorb_lane / alg_hash::kAlgHashRate};
}

void AddEquality(
    JoinPlanV1& plan,
    EqualityRoleV1 role,
    uint32_t semantic,
    uint32_t coordinate,
    EndpointV1 source,
    EndpointV1 sink)
{
    plan.equalities.push_back(
        {role, semantic, coordinate,
         std::move(source), std::move(sink)});
    switch (role) {
    case EqualityRoleV1::FriProofSource:
        ++plan.fri_source_equalities;
        break;
    case EqualityRoleV1::FriVerifierConsumer:
        ++plan.fri_consumer_equalities;
        break;
    case EqualityRoleV1::AirqProofSource:
        ++plan.airq_source_equalities;
        break;
    case EqualityRoleV1::AirqVerifierConsumer:
        ++plan.airq_consumer_equalities;
        break;
    }
}

bool ExactEqualityCounters(const JoinPlanV1& plan)
{
    uint32_t fri_source = 0;
    uint32_t fri_consumer = 0;
    uint32_t airq_source = 0;
    uint32_t airq_consumer = 0;
    for (const EqualityV1& equality : plan.equalities) {
        switch (equality.role) {
        case EqualityRoleV1::FriProofSource:
            ++fri_source;
            break;
        case EqualityRoleV1::FriVerifierConsumer:
            ++fri_consumer;
            break;
        case EqualityRoleV1::AirqProofSource:
            ++airq_source;
            break;
        case EqualityRoleV1::AirqVerifierConsumer:
            ++airq_consumer;
            break;
        }
    }
    return plan.fri_source_equalities == fri_source &&
        plan.fri_consumer_equalities == fri_consumer &&
        plan.airq_source_equalities == airq_source &&
        plan.airq_consumer_equalities == airq_consumer &&
        uint64_t{fri_source} + fri_consumer +
                airq_source + airq_consumer ==
            plan.equalities.size();
}

bool ExactSlice(
    const BytesCellRefsV1& alias,
    const BytesCellRefsV1& prefix,
    size_t offset,
    size_t length)
{
    if (alias.byte.size() != length ||
        offset + length > prefix.byte.size()) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        if (!SameCell(
                alias.byte[i],
                prefix.byte[offset + i])) {
            return false;
        }
    }
    return true;
}

bool ValidateNamedFriSlices(
    const p2bind::BindingResult& binding,
    const FriProofSourceRefsV1& sources,
    std::vector<std::string>& residuals)
{
    if (sources.prefix_schedule.size() !=
            binding.prefix_schedule.size() ||
        sources.prefix_schedule.size() < 5) {
        residuals.push_back(
            "fri_prefix_schedule_byte_exports_missing");
        return false;
    }
    if (!sources.prefix_schedule[0].byte.empty()) {
        residuals.push_back(
            "airq_must_not_alias_fri_prefix");
        return false;
    }
    const size_t domain =
        std::strlen(kRCFri3AlgP2Q192K2DomainTagV10);
    const BytesCellRefsV1& initial =
        sources.prefix_schedule[1];
    if (!ExactSlice(
            sources.fs_seed, initial, domain, 32)) {
        residuals.push_back(
            "fri_seed_byte_alias_missing");
    }
    if (!ExactSlice(
            sources.shape_commit, initial,
            domain + 56, 32)) {
        residuals.push_back(
            "fri_shape_commit_byte_alias_missing");
    }
    if (!ExactSlice(
            sources.row_commit_root, initial,
            domain + 88, 32)) {
        residuals.push_back(
            "fri_row_root_byte_alias_missing");
    }
    if (sources.prefix_schedule[3].byte.size() < 32 ||
        !ExactSlice(
            sources.ood_eval_commit_root,
            sources.prefix_schedule[3],
            sources.prefix_schedule[3].byte.size() - 32,
            32)) {
        residuals.push_back(
            "fri_ood_root_byte_alias_missing");
    }

    const size_t fold_challenges =
        binding.prefix_schedule.size() - 5;
    if (sources.fold_roots.size() !=
            fold_challenges + 1) {
        residuals.push_back(
            "fri_fold_root_byte_exports_missing");
    } else {
        for (size_t fold = 0;
             fold < sources.fold_roots.size();
             ++fold) {
            const size_t schedule =
                fold < fold_challenges
                ? 4 + fold
                : binding.prefix_schedule.size() - 1;
            const auto& prefix =
                sources.prefix_schedule[schedule];
            if (prefix.byte.size() < 32 ||
                !ExactSlice(
                    sources.fold_roots[fold],
                    prefix, prefix.byte.size() - 32, 32)) {
                residuals.push_back(
                    "fri_fold_root_byte_alias_" +
                    std::to_string(fold));
            }
        }
    }
    return residuals.empty();
}

} // namespace

bool AppendSameParentJoinV1(
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const JoinPlanV1& plan,
    AppendResultV1& out,
    std::string* why)
{
    out = {};
    if (plan.version != kSameParentJoinVersionV1 ||
        parent_cs.n_rows < 2 ||
        (parent_cs.n_rows & (parent_cs.n_rows - 1)) != 0 ||
        parent_columns.size() != parent_cs.n_columns ||
        plan.equalities.empty() ||
        !ExactEqualityCounters(plan)) {
        return Fail(why, "parent_or_plan_shape");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "parent_column_rows");
        }
    }
    for (const EqualityV1& equality :
         plan.equalities) {
        if (!ValidEndpoint(equality.source, parent_cs) ||
            !ValidEndpoint(equality.sink, parent_cs)) {
            return Fail(why, "endpoint_ref");
        }
        if (!gf::Eq(
                EndpointValue(
                    equality.source, parent_columns),
                EndpointValue(
                    equality.sink, parent_columns))) {
            return Fail(why, "honest_endpoint_value_mismatch");
        }
    }

    out.original_columns = parent_cs.n_columns;
    out.equality_layouts.reserve(
        plan.equalities.size());
    for (const EqualityV1& equality :
         plan.equalities) {
        EndpointV1 low = equality.source;
        EndpointV1 high = equality.sink;
        const bool source_cross =
            CrossRowLinearCombination(low);
        const bool sink_cross =
            CrossRowLinearCombination(high);
        if (source_cross || sink_cross) {
            if (source_cross && sink_cross) {
                return Fail(
                    why,
                    "two_cross_row_linear_endpoints");
            }
            EndpointV1& packed =
                source_cross ? low : high;
            EndpointV1& other =
                source_cross ? high : low;
            const uint32_t target_row =
                EndpointRow(other);
            if (packed.row != target_row) {
                return Fail(
                    why,
                    "cross_row_linear_target");
            }
            EqualityLayoutV1 layout;
            layout.same_row = false;
            layout.source_selector =
                parent_cs.n_columns++;
            parent_columns.push_back(
                std::vector<Fp3>(
                    parent_cs.n_rows, Fp3::Zero()));
            parent_columns[
                layout.source_selector][target_row] =
                Fp3::One();
            parent_cs.preprocessed.push_back({
                layout.source_selector,
                parent_columns[
                    layout.source_selector]});

            std::vector<LinearTermV1> carried;
            carried.reserve(
                packed.linear_terms.size());
            for (const LinearTermV1& term :
                 packed.linear_terms) {
                const uint32_t carrier =
                    parent_cs.n_columns++;
                const uint32_t source_selector =
                    parent_cs.n_columns++;
                const uint32_t carry_selector =
                    parent_cs.n_columns++;
                parent_columns.resize(
                    parent_cs.n_columns,
                    std::vector<Fp3>(
                        parent_cs.n_rows,
                        Fp3::Zero()));
                const uint32_t low_row =
                    std::min(
                        term.cell.row, target_row);
                const uint32_t high_row =
                    std::max(
                        term.cell.row, target_row);
                const Fp3 value =
                    parent_columns[
                        term.cell.column][term.cell.row];
                for (uint32_t row = low_row;
                     row <= high_row; ++row) {
                    parent_columns[carrier][row] = value;
                }
                parent_columns[
                    source_selector][term.cell.row] =
                    Fp3::One();
                for (uint32_t row = low_row;
                     row < high_row; ++row) {
                    parent_columns[
                        carry_selector][row] =
                        Fp3::One();
                }
                parent_cs.preprocessed.push_back({
                    source_selector,
                    parent_columns[source_selector]});
                parent_cs.preprocessed.push_back({
                    carry_selector,
                    parent_columns[carry_selector]});
                parent_cs.constraints.push_back({
                    "stage3.p2join.cross_byte_source",
                    aq::AirKind::kEverywhere, 2,
                    [carrier, source_selector,
                     source = term.cell.column](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            cur[source_selector],
                            gf::Sub(
                                cur[carrier],
                                cur[source]));
                    }});
                parent_cs.constraints.push_back({
                    "stage3.p2join.cross_byte_carry",
                    aq::AirKind::kTransition, 2,
                    [carrier, carry_selector](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>& next) {
                        return gf::Mul(
                            cur[carry_selector],
                            gf::Sub(
                                next[carrier],
                                cur[carrier]));
                    }});
                carried.push_back({
                    {carrier, target_row},
                    term.coefficient});
                layout.transport_carriers.push_back(
                    carrier);
                layout.transport_source_selectors.push_back(
                    source_selector);
                layout.transport_carry_selectors.push_back(
                    carry_selector);
            }
            packed.linear_terms = std::move(carried);
            const uint32_t selector =
                layout.source_selector;
            parent_cs.constraints.push_back({
                "stage3.p2join.cross_byte_pack",
                aq::AirKind::kEverywhere, 2,
                [selector, packed, other](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[selector],
                        gf::Sub(
                            EndpointValue(packed, cur),
                            EndpointValue(other, cur)));
                }});
            out.equality_layouts.push_back(
                std::move(layout));
            continue;
        }
        uint32_t low_row = EndpointRow(low);
        uint32_t high_row = EndpointRow(high);
        if (low_row > high_row) {
            std::swap(low, high);
            std::swap(low_row, high_row);
        }

        EqualityLayoutV1 layout;
        layout.same_row = low_row == high_row;
        if (layout.same_row) {
            layout.source_selector =
                parent_cs.n_columns++;
            parent_columns.push_back(
                std::vector<Fp3>(
                    parent_cs.n_rows, Fp3::Zero()));
            parent_columns[
                layout.source_selector][low_row] =
                Fp3::One();
            parent_cs.preprocessed.push_back(
                {layout.source_selector,
                 parent_columns[
                     layout.source_selector]});
            const uint32_t selector =
                layout.source_selector;
            parent_cs.constraints.push_back(
                {"stage3.p2join.same_row",
                 aq::AirKind::kEverywhere, 2,
                 [selector, low, high](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
                     return gf::Mul(
                         cur[selector],
                         gf::Sub(
                             EndpointValue(low, cur),
                             EndpointValue(high, cur)));
                 }});
        } else {
            layout.carrier = parent_cs.n_columns++;
            layout.source_selector =
                parent_cs.n_columns++;
            layout.sink_selector =
                parent_cs.n_columns++;
            layout.carry_selector =
                parent_cs.n_columns++;
            parent_columns.resize(
                parent_cs.n_columns,
                std::vector<Fp3>(
                    parent_cs.n_rows, Fp3::Zero()));

            const Fp3 value =
                EndpointValue(low, parent_columns);
            for (uint32_t row = low_row;
                 row <= high_row; ++row) {
                parent_columns[layout.carrier][row] =
                    value;
            }
            parent_columns[
                layout.source_selector][low_row] =
                Fp3::One();
            parent_columns[
                layout.sink_selector][high_row] =
                Fp3::One();
            for (uint32_t row = low_row;
                 row < high_row; ++row) {
                parent_columns[
                    layout.carry_selector][row] =
                    Fp3::One();
            }
            parent_cs.preprocessed.push_back(
                {layout.source_selector,
                 parent_columns[
                     layout.source_selector]});
            parent_cs.preprocessed.push_back(
                {layout.sink_selector,
                 parent_columns[
                     layout.sink_selector]});
            parent_cs.preprocessed.push_back(
                {layout.carry_selector,
                 parent_columns[
                     layout.carry_selector]});

            const uint32_t carrier =
                layout.carrier;
            const uint32_t source_selector =
                layout.source_selector;
            const uint32_t sink_selector =
                layout.sink_selector;
            const uint32_t carry_selector =
                layout.carry_selector;
            parent_cs.constraints.push_back(
                {"stage3.p2join.source",
                 aq::AirKind::kEverywhere, 2,
                 [carrier, source_selector, low](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
                     return gf::Mul(
                         cur[source_selector],
                         gf::Sub(
                             cur[carrier],
                             EndpointValue(low, cur)));
                 }});
            parent_cs.constraints.push_back(
                {"stage3.p2join.sink",
                 aq::AirKind::kEverywhere, 2,
                 [carrier, sink_selector, high](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
                     return gf::Mul(
                         cur[sink_selector],
                         gf::Sub(
                             cur[carrier],
                             EndpointValue(high, cur)));
                 }});
            parent_cs.constraints.push_back(
                {"stage3.p2join.carry",
                 aq::AirKind::kTransition, 2,
                 [carrier, carry_selector](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>& next) {
                     return gf::Mul(
                         cur[carry_selector],
                         gf::Sub(
                             next[carrier],
                             cur[carrier]));
                 }});
        }
        out.equality_layouts.push_back(layout);
    }

    out.appended_columns =
        parent_cs.n_columns - out.original_columns;
    out.equality_count =
        static_cast<uint32_t>(plan.equalities.size());
    out.column_refs_reused = true;
    out.row_tagged_equalities_constrained = true;
    out.cross_row_transport_constrained = true;
    out.selectors_only_preprocessed = true;
    out.actual_values_preprocessed = false;
    out.proof_owned_sources_equality_constrained =
        plan.fri_source_equalities +
            plan.airq_source_equalities >
        0;
    out.verifier_consumers_equality_constrained =
        plan.fri_consumer_equalities +
            plan.airq_consumer_equalities >
        0;
    out.source_columns_proven_verifier_owned = false;
    out.consumer_columns_proven_verifier_owned = false;
    out.recursively_consumed = false;
    out.recursive_authority = false;
    out.residuals = {
        "source_column_ownership_requires_parent_verifier_air",
        "consumer_column_ownership_requires_parent_verifier_air",
        "joined_parent_recursive_consumption_not_executed"};
    out.valid = true;
    out.note =
        "same-parent row-tagged P2 equalities appended; "
        "only position selectors are preprocessed; verifier-column "
        "ownership and recursive consumption remain explicit";
    if (why != nullptr) {
        *why = "stage3:p2_same_parent_join:append_ok";
    }
    return true;
}

bool BuildFriV10JoinPlanV1(
    const p2bind::BindingResult& binding,
    const p2air::BuildResult& transcript,
    const FriProofSourceRefsV1& sources,
    const FriConsumerRefsV1& consumers,
    JoinPlanV1& out,
    std::vector<std::string>& residuals,
    std::string* why)
{
    out = {};
    residuals.clear();
    if (!binding.valid || !transcript.valid ||
        binding.statement.event_prefixes.size() !=
            transcript.manifest.size() ||
        binding.consumer_manifest.entries.size() !=
            transcript.manifest.size()) {
        return Fail(why, "fri_binding_or_transcript");
    }
    if (!ValidateNamedFriSlices(
            binding, sources, residuals)) {
        return Fail(why, residuals.front());
    }
    if (consumers.events.size() !=
            transcript.manifest.size()) {
        residuals.push_back(
            "fri_verifier_consumer_cells_missing");
        return Fail(why, residuals.back());
    }

    // Bind each distinct proof-owned byte prefix once. The base transcript
    // AIR fixes its exact canonical reuse across the paired OOD/weight/query
    // event families.
    for (size_t schedule = 1;
         schedule < binding.prefix_schedule.size();
         ++schedule) {
        const auto& descriptor =
            binding.prefix_schedule[schedule];
        const auto& source =
            sources.prefix_schedule[schedule];
        if (!descriptor.proof_owned ||
            source.byte.size() !=
                descriptor.fs_prefix.size()) {
            residuals.push_back(
                "fri_prefix_bytes_" +
                std::to_string(schedule));
            return Fail(why, residuals.back());
        }
        uint32_t start = 0;
        uint32_t terminal = 0;
        if (!FindEventRows(
                transcript,
                descriptor.first_event_ordinal,
                start, terminal)) {
            return Fail(why, "fri_event_rows");
        }
        const size_t words =
            (source.byte.size() + 3) / 4;
        for (size_t word = 0;
             word < words; ++word) {
            EndpointV1 packed;
            if (!PackedWordEndpoint(
                    source, 4 * word, packed)) {
                residuals.push_back(
                    "fri_prefix_word_not_same_parent_row_" +
                    std::to_string(schedule) + "_" +
                    std::to_string(word));
                return Fail(why, residuals.back());
            }
            const uint32_t absorb_lane =
                3 + static_cast<uint32_t>(word);
            AddEquality(
                out, EqualityRoleV1::FriProofSource,
                static_cast<uint32_t>(schedule),
                static_cast<uint32_t>(word),
                std::move(packed),
                CellEndpoint(FriMessageCell(
                    transcript, start, absorb_lane)));
        }
    }

    for (size_t event = 0;
         event < transcript.manifest.size();
         ++event) {
        uint32_t start = 0;
        uint32_t terminal = 0;
        if (!FindEventRows(
                transcript, static_cast<uint32_t>(event),
                start, terminal)) {
            return Fail(why, "fri_consumer_event_rows");
        }
        const auto kind =
            transcript.manifest[event].kind;
        if (kind == p2air::EventKind::Query) {
            const CellRefV1 consumer =
                consumers.events[event].query_index;
            if (consumer.column == kInvalidColumn) {
                residuals.push_back(
                    "fri_query_consumer_" +
                    std::to_string(event));
                return Fail(why, residuals.back());
            }
            AddEquality(
                out,
                EqualityRoleV1::FriVerifierConsumer,
                static_cast<uint32_t>(event), 0,
                CellEndpoint({
                    transcript.layout.query_index_col,
                    terminal}),
                CellEndpoint(consumer));
            continue;
        }

        for (uint32_t coord = 0;
             coord < 3; ++coord) {
            const CellRefV1 consumer =
                consumers.events[event].fp3.coord[coord];
            if (consumer.column == kInvalidColumn) {
                residuals.push_back(
                    "fri_fp3_consumer_" +
                    std::to_string(event) + "_" +
                    std::to_string(coord));
                return Fail(why, residuals.back());
            }
            EndpointV1 producer;
            if (kind == p2air::EventKind::OodZ1) {
                producer = CellEndpoint({
                    transcript.layout.SelectedCol(0, coord),
                    terminal});
            } else if (
                kind == p2air::EventKind::OodZ2) {
                producer = CellEndpoint({
                    transcript.layout.SelectedCol(1, coord),
                    terminal});
            } else {
                producer = PoseidonEndpoint(
                    transcript.layout.candidate[0],
                    terminal, coord);
            }
            AddEquality(
                out,
                EqualityRoleV1::FriVerifierConsumer,
                static_cast<uint32_t>(event), coord,
                std::move(producer),
                CellEndpoint(consumer));
        }
    }
    if (out.fri_source_equalities == 0 ||
        out.fri_consumer_equalities == 0 ||
        !ExactEqualityCounters(out)) {
        return Fail(why, "fri_empty_join");
    }
    if (why != nullptr) {
        *why = "stage3:p2_same_parent_join:fri_plan_ok";
    }
    return true;
}

bool BuildAirqJoinPlanV1(
    const airq::BuildResult& transcript,
    const AirqProofSourceRefsV1& sources,
    const AirqConsumerRefsV1& consumers,
    JoinPlanV1& out,
    std::vector<std::string>& residuals,
    std::string* why)
{
    out = {};
    residuals.clear();
    if (!transcript.valid) {
        return Fail(why, "airq_transcript");
    }
    const size_t domain_lanes =
        1 +
        (transcript.statement.domain_tag.size() + 3) / 4;
    uint32_t cursor =
        static_cast<uint32_t>(domain_lanes);
    ++cursor; // route version
    const uint32_t seed_start = cursor;
    cursor += 8;
    cursor += 1 +
        static_cast<uint32_t>(
            (transcript.statement.label.size() + 3) / 4);
    ++cursor; // root count
    const uint32_t root_start = cursor;
    cursor += 8;
    ++cursor; // extra count
    const uint32_t shape_start = cursor;

    for (uint32_t word = 0; word < 8; ++word) {
        if (sources.fs_seed.word[word].column ==
                kInvalidColumn ||
            sources.trace_commit_root.word[word].column ==
                kInvalidColumn) {
            residuals.push_back(
                "airq_seed_or_root_source_cells_missing");
            return Fail(why, residuals.back());
        }
        AddEquality(
            out, EqualityRoleV1::AirqProofSource,
            0, word,
            CellEndpoint(sources.fs_seed.word[word]),
            CellEndpoint(AirqMessageCell(
                transcript, seed_start + word)));
        AddEquality(
            out, EqualityRoleV1::AirqProofSource,
            1, word,
            CellEndpoint(
                sources.trace_commit_root.word[word]),
            CellEndpoint(AirqMessageCell(
                transcript, root_start + word)));
    }
    for (uint32_t word = 0; word < 3; ++word) {
        if (sources.shape[word].column ==
            kInvalidColumn) {
            residuals.push_back(
                "airq_shape_source_cells_missing");
            return Fail(why, residuals.back());
        }
        AddEquality(
            out, EqualityRoleV1::AirqProofSource,
            2, word,
            CellEndpoint(sources.shape[word]),
            CellEndpoint(AirqMessageCell(
                transcript, shape_start + word)));
    }
    for (uint32_t coord = 0; coord < 3; ++coord) {
        if (consumers.lambda.coord[coord].column ==
            kInvalidColumn) {
            residuals.push_back(
                "airq_lambda_consumer_cells_missing");
            return Fail(why, residuals.back());
        }
        AddEquality(
            out, EqualityRoleV1::AirqVerifierConsumer,
            0, coord,
            CellEndpoint({
                transcript.layout.LambdaCol(coord),
                transcript.consumer_map.terminal_row}),
            CellEndpoint(
                consumers.lambda.coord[coord]));
    }
    if (out.airq_source_equalities != 19 ||
        out.airq_consumer_equalities != 3 ||
        !ExactEqualityCounters(out)) {
        return Fail(why, "airq_equality_counter_mismatch");
    }
    if (why != nullptr) {
        *why = "stage3:p2_same_parent_join:airq_plan_ok";
    }
    return true;
}

uint32_t CountViolations(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return 1;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return 1;
    }
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint32_t violations = 0;
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
        const uint32_t next_row =
            row + 1 < cs.n_rows ? row + 1 : row;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            const bool enabled =
                constraint.kind == aq::AirKind::kEverywhere ||
                (constraint.kind == aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows) ||
                (constraint.kind == aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind == aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows);
            if (enabled &&
                !gf::IsZero(
                    constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_p2_same_parent_join
