// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v14_transcript_provenance_join.h>

#include <hash.h>

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v14_transcript_provenance_join {
namespace {

using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;
using Constraint = aq::AirConstraint<Fp3>;

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why =
            "stage3:v14_transcript_provenance_join:" +
            reason;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
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
    Constraint c;
    c.name = name;
    c.kind = kind;
    c.alg_degree = degree;
    c.eval = std::move(eval);
    cs.constraints.push_back(std::move(c));
}

void AddPreprocessed(
    AirCS& cs, uint32_t column,
    std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(
        column, std::move(values));
}

std::vector<Fp3> Selector(
    uint32_t rows,
    const std::function<bool(uint32_t)>& predicate)
{
    std::vector<Fp3> out(rows, Fp3::Zero());
    for (uint32_t row = 0; row < rows; ++row) {
        if (predicate(row)) out[row] = Fp3::One();
    }
    return out;
}

std::vector<Fp3> Slice(
    const std::vector<Fp3>& row,
    uint32_t offset, uint32_t columns)
{
    return std::vector<Fp3>(
        row.begin() + offset,
        row.begin() + offset + columns);
}

uint32_t KindSelector(
    uint32_t selector_base,
    uint32_t component,
    aq::AirKind kind)
{
    uint32_t slot = 0;
    switch (kind) {
    case aq::AirKind::kEverywhere:
        slot = 0;
        break;
    case aq::AirKind::kTransition:
        slot = 1;
        break;
    case aq::AirKind::kFirstRow:
        slot = 2;
        break;
    case aq::AirKind::kLastRow:
        slot = 3;
        break;
    }
    return selector_base + 4 * component + slot;
}

void AppendEmbeddedComponent(
    const AirCS& local,
    uint32_t offset,
    uint32_t component,
    uint32_t global_rows,
    uint32_t selector_base,
    AirCS& out)
{
    const std::array<uint32_t, 4> selectors{{
        KindSelector(
            selector_base, component,
            aq::AirKind::kEverywhere),
        KindSelector(
            selector_base, component,
            aq::AirKind::kTransition),
        KindSelector(
            selector_base, component,
            aq::AirKind::kFirstRow),
        KindSelector(
            selector_base, component,
            aq::AirKind::kLastRow),
    }};
    AddPreprocessed(
        out, selectors[0],
        Selector(
            global_rows,
            [rows = local.n_rows](uint32_t row) {
                return row < rows;
            }));
    AddPreprocessed(
        out, selectors[1],
        Selector(
            global_rows,
            [rows = local.n_rows](uint32_t row) {
                return row + 1 < rows;
            }));
    AddPreprocessed(
        out, selectors[2],
        Selector(
            global_rows,
            [](uint32_t row) {
                return row == 0;
            }));
    AddPreprocessed(
        out, selectors[3],
        Selector(
            global_rows,
            [rows = local.n_rows](uint32_t row) {
                return row + 1 == rows;
            }));

    std::set<uint32_t> fixed;
    for (const auto& [column, values] :
         local.preprocessed) {
        std::vector<Fp3> extended(
            global_rows, Fp3::Zero());
        std::copy(
            values.begin(), values.end(),
            extended.begin());
        AddPreprocessed(
            out, offset + column,
            std::move(extended));
        fixed.insert(column);
    }

    for (const auto& local_constraint :
         local.constraints) {
        const uint32_t selector =
            KindSelector(
                selector_base, component,
                local_constraint.kind);
        const auto eval = local_constraint.eval;
        const uint32_t columns = local.n_columns;
        AddConstraint(
            out,
            "stage3.provenance.component",
            aq::AirKind::kEverywhere,
            local_constraint.alg_degree + 1,
            [eval, offset, columns, selector](
                const auto& current,
                const auto& next) {
                return gf::Mul(
                    current[selector],
                    eval(
                        Slice(current, offset, columns),
                        Slice(next, offset, columns)));
            });
    }

    // A component's inactive suffix is outside its local AIR domain.  It is
    // nevertheless committed by the common parent, so force every ordinary
    // cell there to zero instead of leaving a malleable witness surface.
    const uint32_t active = selectors[0];
    for (uint32_t column = 0;
         column < local.n_columns; ++column) {
        if (fixed.count(column) != 0) continue;
        AddConstraint(
            out,
            "stage3.provenance.component_padding_zero",
            aq::AirKind::kEverywhere, 2,
            [active, column = offset + column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        current[active]),
                    current[column]);
            });
    }
}

const derived::SourceExportV1* FindSelectedExport(
    const derived::ScheduleV1& schedule,
    abi::FieldKindV1 kind,
    uint32_t coordinate)
{
    const auto found = std::find_if(
        schedule.source_exports.begin(),
        schedule.source_exports.end(),
        [&](const auto& source) {
            return source.selected_point_source &&
                source.key.kind == kind &&
                source.key.d == coordinate;
        });
    return found == schedule.source_exports.end()
        ? nullptr
        : &*found;
}

struct PublicParts {
    fused::LayoutV1 fused_layout{};
    fused::ScheduleV1 fused_schedule{};
    derived::LayoutV1 derived_layout{};
    derived::ScheduleV1 derived_schedule{};
    event_export::LayoutV1 export_layout{};
    event_export::InventoryV1 export_inventory{};
    event_export::CellMapV1 export_cells{};
    AirCS fused_cs;
    AirCS derived_cs;
    AirCS export_cs;
};

bool BuildPublicParts(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& transcript_commitment,
    const derived::BindingV1& derived_binding,
    PublicParts& out,
    std::string* why)
{
    out = {};
    if (!fused::BuildConstraintSystemV1(
            manifest, transcript_commitment,
            out.fused_cs, out.fused_layout,
            out.fused_schedule, why) ||
        !derived::BuildConstraintSystemV1(
            manifest.shape, derived_binding,
            out.derived_cs, &out.derived_layout,
            &out.derived_schedule, why) ||
        !event_export::BuildInventoryV1(
            manifest, out.export_inventory, why) ||
        !event_export::BuildConstraintSystemV1(
            out.export_inventory,
            out.export_cs, out.export_cells,
            why)) {
        return false;
    }
    return true;
}

using ByteKey =
    std::tuple<ByteSourceKindV1,
               uint32_t, uint8_t, uint8_t>;

uint256 CommitPlan(
    const PlanV1& plan,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& transcript_commitment,
    const derived::BindingV1& derived_binding)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_V14_TRANSCRIPT_PROVENANCE_JOIN_V1"};
    hash << plan.version;
    hash << plan.trace_rows;
    hash << plan.fused_offset;
    hash << plan.derived_offset;
    hash << plan.export_offset;
    hash << plan.fused_columns;
    hash << plan.derived_columns;
    hash << plan.export_columns;
    hash << plan.consumer_bit_base;
    hash << plan.consumer_mask_base;
    hash << plan.component_selector_base;
    hash << plan.dependent_zero;
    hash << plan.total_columns;
    for (gf::Fp lane : manifest.program_root) {
        hash << static_cast<uint64_t>(lane);
    }
    for (gf::Fp lane : transcript_commitment) {
        hash << static_cast<uint64_t>(lane);
    }
    for (gf::Fp lane : derived_binding.shape_commit) {
        hash << static_cast<uint64_t>(lane);
    }
    for (gf::Fp lane :
         derived_binding.ood_evaluation_commit) {
        hash << static_cast<uint64_t>(lane);
    }
    hash << static_cast<uint32_t>(
        plan.field_edges.size());
    for (const auto& edge : plan.field_edges) {
        hash << static_cast<uint8_t>(edge.kind);
        hash << edge.item;
        hash << edge.coordinate;
        hash << edge.source.column;
        hash << edge.source.row;
        hash << edge.destination.column;
        hash << edge.destination.row;
        hash << edge.carry_column;
        hash << edge.source_selector_column;
        hash << edge.destination_selector_column;
    }
    hash << static_cast<uint32_t>(
        plan.byte_sources.size());
    for (const auto& source : plan.byte_sources) {
        hash << static_cast<uint8_t>(source.kind);
        hash << source.event_or_family;
        hash << source.lane;
        hash << source.byte;
        hash << source.direct_byte;
        hash << source.byte_cell.column;
        hash << source.byte_cell.row;
        for (const auto& bit : source.bit_cell) {
            hash << bit.column;
            hash << bit.row;
        }
        hash << source.multiplicity;
        hash << source.carry_column;
        hash << source.source_selector_column;
    }
    hash << static_cast<uint32_t>(
        plan.byte_consumers.size());
    for (const auto& consumer :
         plan.byte_consumers) {
        hash << consumer.source;
        hash << consumer.event;
        hash << consumer.message_ordinal;
        hash << consumer.byte_in_message_word;
        hash << consumer.message.column;
        hash << consumer.message.row;
        hash << consumer.selector_column;
    }
    hash << plan.prior_occurrences;
    hash << plan.derived_occurrences;
    hash << plan.selected_occurrences;
    hash << plan.exported_event_lanes;
    hash << plan.selected_field_edges;
    return hash.GetHash();
}

bool SamePublicProducts(
    const occurrence::ManifestV1& manifest,
    const fused::ProductV1& v14_selection,
    const derived::ProductV1& derived_hash,
    const event_export::ProductV1& outputs)
{
    event_export::InventoryV1 expected;
    if (!event_export::BuildInventoryV1(
            manifest, expected, nullptr)) {
        return false;
    }
    const bool inventory_equal =
        outputs.inventory.exported ==
            expected.exported &&
        outputs.inventory.delegated ==
            expected.delegated &&
        outputs.inventory.prior_byte_occurrences ==
            expected.prior_byte_occurrences &&
        outputs.inventory.query_seed_field_occurrences ==
            expected.query_seed_field_occurrences &&
        outputs.inventory.unique_prior_byte_lanes ==
            expected.unique_prior_byte_lanes &&
        outputs.inventory.unique_verifier_challenge_lanes ==
            expected.unique_verifier_challenge_lanes &&
        outputs.inventory.duplicate_consumers_collapsed ==
            expected.duplicate_consumers_collapsed &&
        outputs.inventory.delegated_ood_candidate_lanes ==
            expected.delegated_ood_candidate_lanes &&
        outputs.inventory.delegated_query_candidate_lanes ==
            expected.delegated_query_candidate_lanes &&
        outputs.inventory.delegated_selected_ood_lanes ==
            expected.delegated_selected_ood_lanes &&
        outputs.inventory.delegated_derived_hash_lanes ==
            expected.delegated_derived_hash_lanes &&
        outputs.inventory.complete &&
        expected.complete;
    return
        v14_selection.valid &&
        derived_hash.valid &&
        outputs.valid &&
        v14_selection.schedule.manifest.shape ==
            manifest.shape &&
        v14_selection.schedule.manifest.program_root ==
            manifest.program_root &&
        derived_hash.schedule.shape == manifest.shape &&
        inventory_equal;
}

Fp3 ByteFromCells(
    const ByteSourceV1& source,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (source.direct_byte) {
        return columns[source.byte_cell.column]
                      [source.byte_cell.row];
    }
    Fp3 out = Fp3::Zero();
    Fp3 power = Fp3::One();
    for (uint32_t bit = 0; bit < 8; ++bit) {
        out = gf::Add(
            out,
            gf::Mul(
                power,
                columns[source.bit_cell[bit].column]
                       [source.bit_cell[bit].row]));
        power = gf::Add(power, power);
    }
    return out;
}

} // namespace

bool BuildCanonicalPlanV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    PlanV1& out,
    std::string* why)
{
    out = {};
    PublicParts parts;
    if (!manifest.valid ||
        !occurrence::ValidateCanonicalOccurrenceManifestV1(
            manifest.shape,
            manifest.canonical_program,
            manifest, why) ||
        !BuildPublicParts(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            parts, why)) {
        return Fail(why, "public_parts");
    }

    out.fused_offset = 0;
    out.fused_columns = parts.fused_cs.n_columns;
    out.derived_offset = out.fused_columns;
    out.derived_columns = parts.derived_cs.n_columns;
    out.export_offset =
        out.derived_offset + out.derived_columns;
    out.export_columns = parts.export_cs.n_columns;
    out.trace_rows = std::max({
        parts.fused_cs.n_rows,
        parts.derived_cs.n_rows,
        parts.export_cs.n_rows});
    if (!PowerOfTwo(out.trace_rows)) {
        return Fail(why, "trace_rows");
    }

    uint32_t cursor =
        out.export_offset + out.export_columns;
    out.component_selector_base = cursor;
    cursor += 12; // active/transition/first/last for three components.
    out.consumer_bit_base = cursor;
    cursor +=
        kConsumerLanesV1 *
        kConsumerBitsPerLaneV1;
    out.consumer_mask_base = cursor;
    cursor += kConsumerLanesV1;

    std::map<std::pair<uint32_t, uint8_t>,
             uint32_t> export_row;
    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    for (uint32_t row = 0;
         row < parts.export_cells.exports.size();
         ++row) {
        const auto& cell =
            parts.export_cells.exports[row];
        export_row.emplace(
            std::make_pair(cell.event, cell.lane),
            row);
        if (cell.event >=
                parts.fused_schedule.v14_event_row.size()) {
            return Fail(why, "export_event");
        }
        FieldEdgeV1 edge;
        edge.kind =
            FieldEdgeKindV1::V14OutputToExport;
        edge.item = cell.event;
        edge.coordinate = cell.lane;
        edge.source = {
            out.fused_offset +
                v14_layout.Output(cell.lane),
            parts.fused_schedule
                .v14_event_row[cell.event]};
        edge.destination = {
            out.export_offset +
                cell.v14_output_lane.column,
            cell.v14_output_lane.row};
        out.field_edges.push_back(edge);
    }
    out.exported_event_lanes =
        static_cast<uint32_t>(
            out.field_edges.size());

    const selection::LayoutV1 selection_layout;
    for (const auto& source :
         parts.derived_schedule.source_exports) {
        if (!source.selected_point_source ||
            (source.key.kind !=
                 abi::FieldKindV1::Z1 &&
             source.key.kind !=
                 abi::FieldKindV1::Z2) ||
            source.key.d >= 3) {
            continue;
        }
        FieldEdgeV1 edge;
        edge.kind =
            FieldEdgeKindV1::
                SelectionToDerivedSelectedPoint;
        edge.item =
            source.key.kind ==
                abi::FieldKindV1::Z1
            ? 0
            : 1;
        edge.coordinate = source.key.d;
        const uint32_t selection_column =
            source.key.kind ==
                abi::FieldKindV1::Z1
            ? selection_layout.SelectedZ1(
                  source.key.d)
            : selection_layout.SelectedZ2(
                  source.key.d);
        edge.source = {
            out.fused_offset +
                parts.fused_layout.Selection(
                    selection_column),
            selection::kSelectionRowV1};
        edge.destination = {
            out.derived_offset +
                source.value_column,
            source.row};
        out.field_edges.push_back(edge);
        ++out.selected_field_edges;
    }
    if (out.selected_field_edges != 6) {
        return Fail(why, "selected_field_edges");
    }

    std::map<ByteKey, uint32_t> source_index;
    const auto add_source =
        [&](ByteSourceV1 source,
            uint32_t& index) {
            const ByteKey key{
                source.kind,
                source.event_or_family,
                source.lane,
                source.byte};
            const auto found = source_index.find(key);
            if (found != source_index.end()) {
                index = found->second;
                return true;
            }
            index =
                static_cast<uint32_t>(
                    out.byte_sources.size());
            source_index.emplace(key, index);
            out.byte_sources.push_back(
                std::move(source));
            return true;
        };

    for (const auto& item :
         manifest.byte_occurrences) {
        if (!item.prior_event_output_source &&
            !item.derived_hash_source) {
            continue;
        }
        ByteSourceV1 source;
        if (item.derived_hash_source) {
            const uint32_t family =
                item.source_kind ==
                    occurrence::ByteSourceKindV1::
                        DerivedShapeCommit
                ? 0
                : 1;
            if (family >=
                    parts.derived_schedule
                        .digest_exports.size() ||
                item.derived_output_lane >= 4 ||
                item.byte_in_derived_lane >= 8) {
                return Fail(why, "derived_source");
            }
            const auto& digest =
                parts.derived_schedule
                    .digest_exports[family];
            source.kind = family == 0
                ? ByteSourceKindV1::
                    DerivedShapeCommit
                : ByteSourceKindV1::
                    DerivedOodEvaluationCommit;
            source.event_or_family = family;
            source.lane =
                item.derived_output_lane;
            source.byte =
                item.byte_in_derived_lane;
            source.direct_byte = true;
            source.byte_cell = {
                out.derived_offset +
                    digest.byte_column
                        [source.lane][source.byte],
                digest.terminal_row};
            ++out.derived_occurrences;
        } else if (
            item.selector_family !=
                occurrence::SelectorFamilyV1::None) {
            const abi::FieldKindV1 kind =
                item.selector_family ==
                    occurrence::SelectorFamilyV1::
                        OodZ1FirstAcceptable
                ? abi::FieldKindV1::Z1
                : abi::FieldKindV1::Z2;
            const auto* selected =
                FindSelectedExport(
                    parts.derived_schedule,
                    kind,
                    item.source_output_lane);
            if (selected == nullptr ||
                item.byte_in_output_lane >= 8) {
                return Fail(
                    why, "selected_source");
            }
            source.kind =
                ByteSourceKindV1::SelectedOod;
            source.event_or_family =
                static_cast<uint32_t>(
                    item.selector_family);
            source.lane =
                item.source_output_lane;
            source.byte =
                item.byte_in_output_lane;
            for (uint32_t bit = 0;
                 bit < 8; ++bit) {
                source.bit_cell[bit] = {
                    out.derived_offset +
                        parts.derived_layout.Bit(
                            selected->lane,
                            8 * source.byte + bit),
                    selected->row};
            }
            ++out.prior_occurrences;
            ++out.selected_occurrences;
        } else {
            if (item.source_event_begin !=
                    item.source_event_end ||
                item.source_event_begin ==
                    occurrence::kNoEventV1 ||
                item.source_output_lane >= 4 ||
                item.byte_in_output_lane >= 8) {
                return Fail(
                    why, "prior_source");
            }
            const auto found =
                export_row.find({
                    item.source_event_begin,
                    item.source_output_lane});
            if (found == export_row.end()) {
                return Fail(
                    why, "prior_export");
            }
            source.kind =
                ByteSourceKindV1::
                    PriorEventOutput;
            source.event_or_family =
                item.source_event_begin;
            source.lane =
                item.source_output_lane;
            source.byte =
                item.byte_in_output_lane;
            for (uint32_t bit = 0;
                 bit < 8; ++bit) {
                source.bit_cell[bit] = {
                    out.export_offset +
                        parts.export_layout.Bit(
                            8 * source.byte + bit),
                    found->second};
            }
            ++out.prior_occurrences;
        }

        uint32_t index = UINT32_MAX;
        if (!add_source(source, index)) {
            return Fail(why, "source_add");
        }
        if (item.consumer_event >=
                manifest.canonical_program.size() ||
            item.consumer_message_ordinal >=
                manifest.canonical_program[
                    item.consumer_event]
                    .message.size() ||
            item.byte_in_message_word >= 4) {
            return Fail(why, "consumer");
        }
        ByteConsumerV1 consumer;
        consumer.source = index;
        consumer.event = item.consumer_event;
        consumer.message_ordinal =
            item.consumer_message_ordinal;
        consumer.byte_in_message_word =
            item.byte_in_message_word;
        consumer.message = {
            out.fused_offset +
                item.consumer_column,
            item.consumer_row};
        out.byte_consumers.push_back(
            std::move(consumer));
        ++out.byte_sources[index].multiplicity;
    }

    for (auto& edge : out.field_edges) {
        edge.carry_column = cursor++;
        edge.source_selector_column = cursor++;
        edge.destination_selector_column = cursor++;
    }
    for (auto& source : out.byte_sources) {
        source.carry_column = cursor++;
        source.source_selector_column = cursor++;
    }
    for (auto& consumer : out.byte_consumers) {
        consumer.selector_column = cursor++;
    }
    out.dependent_zero = cursor++;
    out.total_columns = cursor;

    out.exact_manifest_rebuilt = true;
    out.exact_occurrence_multiplicities =
        out.prior_occurrences ==
            manifest
                .prior_event_output_byte_occurrences +
            manifest
                .outer_fri_seed_feedback_byte_occurrences &&
        out.derived_occurrences ==
            manifest.derived_hash_byte_occurrences &&
        std::all_of(
            out.byte_sources.begin(),
            out.byte_sources.end(),
            [](const auto& source) {
                return source.multiplicity > 0;
            });
    out.every_source_resolved =
        !out.byte_sources.empty() &&
        std::all_of(
            out.byte_sources.begin(),
            out.byte_sources.end(),
            [](const auto& source) {
                if (source.direct_byte) {
                    return
                        source.byte_cell.column !=
                            UINT32_MAX &&
                        source.byte_cell.row !=
                            UINT32_MAX;
                }
                return std::all_of(
                    source.bit_cell.begin(),
                    source.bit_cell.end(),
                    [](const auto& bit) {
                        return
                            bit.column != UINT32_MAX &&
                            bit.row != UINT32_MAX;
                    });
            });
    out.every_consumer_resolved =
        !out.byte_consumers.empty() &&
        std::all_of(
            out.byte_consumers.begin(),
            out.byte_consumers.end(),
            [&](const auto& consumer) {
                return
                    consumer.source <
                        out.byte_sources.size() &&
                    consumer.message.column <
                        out.fused_columns &&
                    consumer.message.row <
                        out.trace_rows;
            });
    out.valid =
        out.exact_manifest_rebuilt &&
        out.exact_occurrence_multiplicities &&
        out.every_source_resolved &&
        out.every_consumer_resolved &&
        out.exported_event_lanes ==
            parts.export_inventory.exported.size() &&
        out.selected_field_edges == 6;
    if (!out.valid) {
        return Fail(why, "plan");
    }
    out.plan_root = CommitPlan(
        out, manifest,
        expected_transcript_commitment,
        expected_derived_binding);
    out.valid = !out.plan_root.IsNull();
    out.note = out.valid
        ? "canonical prior-output/derived-hash V14 provenance plan"
        : "null provenance plan root";
    if (!out.valid) return Fail(why, "plan_root");
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildConstraintSystemV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    AirCS& out,
    PlanV1* plan_out,
    std::string* why)
{
    out = {};
    PlanV1 plan;
    PublicParts parts;
    if (!BuildCanonicalPlanV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            plan, why) ||
        !BuildPublicParts(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            parts, why)) {
        return false;
    }
    out.n_rows = plan.trace_rows;
    out.n_columns = plan.total_columns;
    out.preprocessed_pin_ood = true;
    AppendEmbeddedComponent(
        parts.fused_cs, plan.fused_offset,
        0, plan.trace_rows,
        plan.component_selector_base, out);
    AppendEmbeddedComponent(
        parts.derived_cs, plan.derived_offset,
        1, plan.trace_rows,
        plan.component_selector_base, out);
    AppendEmbeddedComponent(
        parts.export_cs, plan.export_offset,
        2, plan.trace_rows,
        plan.component_selector_base, out);

    for (uint32_t lane = 0;
         lane < kConsumerLanesV1; ++lane) {
        std::vector<Fp3> mask(
            plan.trace_rows, Fp3::Zero());
        for (const auto& consumer :
             plan.byte_consumers) {
            if (consumer.message_ordinal %
                    kConsumerLanesV1 ==
                lane) {
                mask[consumer.message.row] =
                    Fp3::One();
            }
        }
        AddPreprocessed(
            out,
            plan.consumer_mask_base + lane,
            std::move(mask));
        AddConstraint(
            out,
            "stage3.provenance.consumer_u32",
            aq::AirKind::kEverywhere, 2,
            [plan, lane](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                Fp3 power = Fp3::One();
                for (uint32_t bit = 0;
                     bit <
                         kConsumerBitsPerLaneV1;
                     ++bit) {
                    const uint32_t column =
                        plan.consumer_bit_base +
                        lane *
                            kConsumerBitsPerLaneV1 +
                        bit;
                    const Fp3 b = current[column];
                    value = gf::Add(
                        value,
                        gf::Mul(power, b));
                    power = gf::Add(power, power);
                }
                const uint32_t message =
                    plan.fused_offset +
                    bridge::
                        TypedSafeDirectParentLayoutV14{}
                            .Message(lane);
                return gf::Mul(
                    current[
                        plan.consumer_mask_base +
                        lane],
                    gf::Sub(
                        current[message], value));
            });
        for (uint32_t bit = 0;
             bit < kConsumerBitsPerLaneV1;
             ++bit) {
            const uint32_t column =
                plan.consumer_bit_base +
                lane *
                    kConsumerBitsPerLaneV1 +
                bit;
            AddConstraint(
                out,
                "stage3.provenance.consumer_bit",
                aq::AirKind::kEverywhere, 3,
                [plan, lane, column](
                    const auto& current,
                    const auto&) {
                    const Fp3 mask =
                        current[
                            plan.consumer_mask_base +
                            lane];
                    const Fp3 bit =
                        current[column];
                    return gf::Add(
                        gf::Mul(
                            mask,
                            gf::Mul(
                                bit,
                                gf::Sub(
                                    bit,
                                    Fp3::One()))),
                        gf::Mul(
                            gf::Sub(
                                Fp3::One(), mask),
                            bit));
                });
        }
    }

    for (const auto& edge : plan.field_edges) {
        AddPreprocessed(
            out, edge.source_selector_column,
            Selector(
                plan.trace_rows,
                [row = edge.source.row](
                    uint32_t at) {
                    return at == row;
                }));
        AddPreprocessed(
            out, edge.destination_selector_column,
            Selector(
                plan.trace_rows,
                [row = edge.destination.row](
                    uint32_t at) {
                    return at == row;
                }));
        AddConstraint(
            out,
            "stage3.provenance.field_carry",
            aq::AirKind::kTransition, 1,
            [edge](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[edge.carry_column],
                    current[edge.carry_column]);
            });
        AddConstraint(
            out,
            "stage3.provenance.field_source",
            aq::AirKind::kEverywhere, 2,
            [edge](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        edge.source_selector_column],
                    gf::Sub(
                        current[edge.carry_column],
                        current[edge.source.column]));
            });
        AddConstraint(
            out,
            "stage3.provenance.field_destination",
            aq::AirKind::kEverywhere, 2,
            [edge](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        edge.destination_selector_column],
                    gf::Sub(
                        current[edge.carry_column],
                        current[
                            edge.destination.column]));
            });
    }

    for (const auto& source : plan.byte_sources) {
        AddPreprocessed(
            out, source.source_selector_column,
            Selector(
                plan.trace_rows,
                [row = source.direct_byte
                         ? source.byte_cell.row
                         : source.bit_cell[0].row](
                    uint32_t at) {
                    return at == row;
                }));
        AddConstraint(
            out,
            "stage3.provenance.byte_carry",
            aq::AirKind::kTransition, 1,
            [source](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[source.carry_column],
                    current[source.carry_column]);
            });
        AddConstraint(
            out,
            "stage3.provenance.byte_source",
            aq::AirKind::kEverywhere, 2,
            [source](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                if (source.direct_byte) {
                    value =
                        current[
                            source.byte_cell.column];
                } else {
                    Fp3 power = Fp3::One();
                    for (uint32_t bit = 0;
                         bit < 8; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                power,
                                current[
                                    source
                                        .bit_cell[bit]
                                        .column]));
                        power =
                            gf::Add(power, power);
                    }
                }
                return gf::Mul(
                    current[
                        source
                            .source_selector_column],
                    gf::Sub(
                        current[source.carry_column],
                        value));
            });
    }
    for (const auto& consumer :
         plan.byte_consumers) {
        AddPreprocessed(
            out, consumer.selector_column,
            Selector(
                plan.trace_rows,
                [row = consumer.message.row](
                    uint32_t at) {
                    return at == row;
                }));
        const auto source =
            plan.byte_sources[consumer.source];
        AddConstraint(
            out,
            "stage3.provenance.byte_consumer",
            aq::AirKind::kEverywhere, 2,
            [plan, consumer, source](
                const auto& current,
                const auto&) {
                const uint32_t lane =
                    consumer.message_ordinal %
                    kConsumerLanesV1;
                Fp3 value = Fp3::Zero();
                Fp3 power = Fp3::One();
                for (uint32_t bit = 0;
                     bit < 8; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            power,
                            current[
                                plan.consumer_bit_base +
                                lane *
                                    kConsumerBitsPerLaneV1 +
                                8 *
                                    consumer
                                        .byte_in_message_word +
                                bit]));
                    power = gf::Add(power, power);
                }
                return gf::Mul(
                    current[
                        consumer.selector_column],
                    gf::Sub(
                        current[source.carry_column],
                        value));
            });
    }
    AddConstraint(
        out,
        "stage3.provenance.dependent_zero",
        aq::AirKind::kEverywhere, 1,
        [column = plan.dependent_zero](
            const auto& current,
            const auto&) {
            return current[column];
        });
    if (plan_out != nullptr) *plan_out = plan;
    if (why != nullptr) {
        *why =
            "stage3:v14_transcript_provenance_join:cs";
    }
    return true;
}

ProductV1 BuildProductV1(
    const occurrence::ManifestV1& manifest,
    const fused::ProductV1& v14_selection,
    const derived::ProductV1& derived_hash,
    const event_export::ProductV1& outputs)
{
    ProductV1 out;
    std::string why;
    if (!SamePublicProducts(
            manifest, v14_selection,
            derived_hash, outputs) ||
        v14_selection.expected_transcript_commitment ==
            alg_hash::Digest{} ||
        !BuildConstraintSystemV1(
            manifest,
            v14_selection
                .expected_transcript_commitment,
            derived_hash.binding,
            out.cs, &out.plan, &why)) {
        out.note = why.empty()
            ? "stage3:provenance:product_input"
            : why;
        return out;
    }
    out.program_root = manifest.program_root;
    out.transcript_commitment =
        v14_selection.expected_transcript_commitment;
    out.derived_binding = derived_hash.binding;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        out.columns[column] = values;
    }
    const auto copy_component =
        [&](const auto& source,
            uint32_t offset) {
            for (uint32_t column = 0;
                 column < source.size();
                 ++column) {
                std::copy(
                    source[column].begin(),
                    source[column].end(),
                    out.columns[
                        offset + column].begin());
            }
        };
    copy_component(
        v14_selection.columns,
        out.plan.fused_offset);
    copy_component(
        derived_hash.columns,
        out.plan.derived_offset);
    copy_component(
        outputs.columns,
        out.plan.export_offset);

    for (uint32_t lane = 0;
         lane < kConsumerLanesV1; ++lane) {
        for (uint32_t row = 0;
             row < out.cs.n_rows; ++row) {
            if (gf::IsZero(
                    out.columns[
                        out.plan.consumer_mask_base +
                        lane][row])) {
                continue;
            }
            const Fp3 raw =
                out.columns[
                    out.plan.fused_offset +
                    bridge::
                        TypedSafeDirectParentLayoutV14{}
                            .Message(lane)][row];
            if (raw.c1 != 0 || raw.c2 != 0) {
                out.note =
                    "stage3:provenance:"
                    "consumer_not_base";
                return out;
            }
            const uint64_t value =
                gf::Canonical(raw.c0);
            if (value > UINT32_MAX) {
                out.note =
                    "stage3:provenance:"
                    "consumer_not_u32";
                return out;
            }
            for (uint32_t bit = 0;
                 bit <
                     kConsumerBitsPerLaneV1;
                 ++bit) {
                out.columns[
                    out.plan.consumer_bit_base +
                    lane *
                        kConsumerBitsPerLaneV1 +
                    bit][row] =
                    U((value >> bit) & 1U);
            }
        }
    }
    for (const auto& edge : out.plan.field_edges) {
        const Fp3 value =
            out.columns[edge.source.column]
                       [edge.source.row];
        std::fill(
            out.columns[edge.carry_column].begin(),
            out.columns[edge.carry_column].end(),
            value);
    }
    for (const auto& source :
         out.plan.byte_sources) {
        const Fp3 value =
            ByteFromCells(source, out.columns);
        std::fill(
            out.columns[source.carry_column].begin(),
            out.columns[source.carry_column].end(),
            value);
    }
    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.actual_v14_outputs_bound =
        out.plan.exported_event_lanes ==
            outputs.inventory.exported.size();
    out.selected_points_bound_to_derived =
        out.plan.selected_field_edges == 6;
    out.consumer_u32_decomposition_constrained =
        true;
    out.prior_output_occurrences_bound =
        out.plan.prior_occurrences ==
            manifest
                .prior_event_output_byte_occurrences +
            manifest
                .outer_fri_seed_feedback_byte_occurrences;
    out.derived_hash_occurrences_bound =
        out.plan.derived_occurrences ==
            manifest.derived_hash_byte_occurrences;
    out.exact_multiplicities_consumed =
        out.plan.exact_occurrence_multiplicities;
    out.canonical_abi_occurrences_bound = false;
    out.protocol_constant_occurrences_bound = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.actual_v14_outputs_bound &&
        out.selected_points_bound_to_derived &&
        out.consumer_u32_decomposition_constrained &&
        out.prior_output_occurrences_bound &&
        out.derived_hash_occurrences_bound &&
        out.exact_multiplicities_consumed &&
        !out.canonical_abi_occurrences_bound &&
        !out.protocol_constant_occurrences_bound &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "all prior-output and derived-hash V14 message "
          "occurrences equality-bound; ABI and fixed-prefix "
          "relations remain separate"
        : "transcript provenance equality violation";
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
        product.canonical_abi_occurrences_bound ||
        product.protocol_constant_occurrences_bound ||
        product.recursively_consumed ||
        product.recursive_authority_ready) {
        return Fail(why, "prove_input");
    }
    const auto proved =
        aq::AirQuotientProveRows(
            product.cs, product.columns,
            fs_seed);
    if (!proved.ok ||
        !proved.division_exact) {
        return Fail(
            why, "prove:" + proved.note);
    }
    out.plan_root = product.plan.plan_root;
    out.program_root = product.program_root;
    out.transcript_commitment =
        product.transcript_commitment;
    out.derived_binding = product.derived_binding;
    out.proof = proved.proof;
    out.note =
        "prior-output/derived transcript provenance proof";
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why)
{
    PlanV1 plan;
    AirCS cs;
    if (proof.version !=
            kTranscriptProvenanceJoinVersionV1 ||
        fs_seed.IsNull() ||
        proof.program_root != manifest.program_root ||
        proof.transcript_commitment !=
            expected_transcript_commitment ||
        proof.derived_binding !=
            expected_derived_binding ||
        proof.canonical_abi_occurrences_bound ||
        proof.protocol_constant_occurrences_bound ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        !BuildConstraintSystemV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            cs, &plan, why) ||
        proof.plan_root != plan.plan_root) {
        return Fail(why, "proof_envelope");
    }
    return aq::AirQuotientVerifyRows(
        cs, proof.proof, fs_seed, why);
}

uint64_t CountViolationsV1(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows == 0) {
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
         row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] =
                columns[column][row];
            next[column] =
                columns[column]
                       [(row + 1) % cs.n_rows];
        }
        for (const auto& constraint :
             cs.constraints) {
            const bool applies =
                constraint.kind ==
                    aq::AirKind::kEverywhere ||
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
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_v14_transcript_provenance_join
