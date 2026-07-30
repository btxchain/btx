// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v14_event_output_export_air.h>

#include <algorithm>
#include <functional>
#include <map>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v14_event_output_export_air {
namespace {

using gf::Fp3;
using Kind = bridge::TypedSafeChallengeKindV13;

bool Fail(std::string* why, const char* reason)
{
    if (why != nullptr) {
        *why =
            std::string("stage3:v14_event_output_export_air:") +
            reason;
    }
    return false;
}

uint32_t NextPow2(uint32_t value)
{
    uint32_t out = 1;
    while (out < value) out <<= 1;
    return out;
}

Fp3 Base(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<
        Fp3(
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

Fp3 OneMinus(const Fp3& value)
{
    return gf::Sub(Fp3::One(), value);
}

uint8_t UseBit(ExportUseV1 use)
{
    return static_cast<uint8_t>(use);
}

} // namespace

const ExportCellV1* CellMapV1::Find(
    uint32_t event, uint8_t lane) const
{
    const auto found = std::find_if(
        exports.begin(), exports.end(),
        [&](const ExportCellV1& cell) {
            return cell.event == event &&
                cell.lane == lane;
        });
    return found == exports.end() ? nullptr : &*found;
}

bool BuildInventoryV1(
    const occurrence::ManifestV1& manifest,
    InventoryV1& out,
    std::string* why)
{
    out = {};
    std::string manifest_why;
    if (!manifest.valid ||
        !occurrence::ValidateCanonicalOccurrenceManifestV1(
            manifest.shape,
            manifest.canonical_program,
            manifest, &manifest_why)) {
        return Fail(why, "manifest");
    }
    out.manifest_rebuilt = true;

    using ProducerKey = std::pair<uint32_t, uint8_t>;
    std::map<ProducerKey, ProducerLaneV1> exported;
    using DelegatedKey = std::tuple<
        DelegatedOutputKindV1, uint32_t, uint8_t,
        occurrence::SelectorFamilyV1>;
    std::map<DelegatedKey, DelegatedLaneV1> delegated;

    const auto add_export =
        [&](uint32_t event, uint8_t lane,
            ExportUseV1 use, uint32_t consumers) {
            auto& item = exported[{event, lane}];
            item.event = event;
            item.lane = lane;
            item.uses |= UseBit(use);
            item.occurrence_consumers += consumers;
        };
    const auto add_delegated =
        [&](DelegatedOutputKindV1 kind,
            uint32_t event, uint8_t lane,
            occurrence::SelectorFamilyV1 selector,
            uint32_t consumers) {
            auto& item =
                delegated[{kind, event, lane, selector}];
            item.kind = kind;
            item.event = event;
            item.lane = lane;
            item.selector_family = selector;
            item.occurrence_consumers += consumers;
        };

    for (const auto& item : manifest.byte_occurrences) {
        if (item.prior_event_output_source) {
            ++out.prior_byte_occurrences;
            if (item.selector_family ==
                    occurrence::SelectorFamilyV1::None &&
                item.source_event_begin ==
                    item.source_event_end) {
                add_export(
                    item.source_event_begin,
                    item.source_output_lane,
                    ExportUseV1::PriorTranscriptBytes, 1);
            } else {
                if (item.source_event_begin ==
                        occurrence::kNoEventV1 ||
                    item.source_event_end <
                        item.source_event_begin) {
                    return Fail(why, "ood_candidate_range");
                }
                for (uint32_t event =
                         item.source_event_begin;
                     event <= item.source_event_end;
                     ++event) {
                    add_delegated(
                        DelegatedOutputKindV1::
                            OodCandidateToFirstAcceptableAir,
                        event, item.source_output_lane,
                        item.selector_family, 1);
                }
            }
        }
        if (item.derived_hash_source) {
            const auto kind =
                item.source_kind ==
                    occurrence::ByteSourceKindV1::
                        DerivedShapeCommit
                    ? DelegatedOutputKindV1::
                        DerivedShapeHashToHashAir
                    : DelegatedOutputKindV1::
                        DerivedOodHashToHashAir;
            add_delegated(
                kind, kNoEventV1,
                static_cast<uint8_t>(
                    item.derived_output_lane),
                occurrence::SelectorFamilyV1::None, 1);
        }
    }
    // PublicFsSeed bytes deliberately have dual identities: canonical ABI
    // and outer FriSeed feedback. ManifestV1 counts them in the ABI bucket
    // and separately in outer_fri_seed_feedback_byte_occurrences, so include
    // that second counter when auditing every prior-output occurrence here.
    if (out.prior_byte_occurrences !=
        manifest.prior_event_output_byte_occurrences +
            manifest.outer_fri_seed_feedback_byte_occurrences) {
        return Fail(why, "prior_occurrence_count");
    }

    for (const auto& item : manifest.field_occurrences) {
        ++out.query_seed_field_occurrences;
        add_export(
            item.source_event,
            item.source_output_lane,
            ExportUseV1::QuerySeedFeedback, 1);
    }
    if (out.query_seed_field_occurrences !=
        manifest.query_seed_feedback_field_occurrences) {
        return Fail(why, "field_occurrence_count");
    }

    // Outputs consumed directly by verifier arithmetic do not appear as
    // transcript byte occurrences. Add them from the canonical typed program,
    // including every fold beta exactly once.
    for (uint32_t event = 0;
         event < manifest.canonical_program.size(); ++event) {
        const Kind kind =
            manifest.canonical_program[event].kind;
        switch (kind) {
        case Kind::AirLambda:
        case Kind::BatchCoefficient:
        case Kind::DeepWeight1:
        case Kind::DeepWeight2:
        case Kind::FoldBeta:
            for (uint8_t lane = 0; lane < 3; ++lane) {
                add_export(
                    event, lane,
                    ExportUseV1::VerifierChallenge, 0);
            }
            break;
        case Kind::FriSeed:
        case Kind::QuerySeed:
            for (uint8_t lane = 0; lane < 4; ++lane) {
                add_export(
                    event, lane,
                    ExportUseV1::VerifierChallenge, 0);
            }
            break;
        case Kind::OodZ1:
        case Kind::OodZ2: {
            const auto selector =
                kind == Kind::OodZ1
                    ? occurrence::SelectorFamilyV1::
                        OodZ1FirstAcceptable
                    : occurrence::SelectorFamilyV1::
                        OodZ2FirstAcceptableDistinctFromZ1;
            for (uint8_t lane = 0; lane < 3; ++lane) {
                add_delegated(
                    DelegatedOutputKindV1::
                        OodCandidateToFirstAcceptableAir,
                    event, lane, selector, 0);
            }
            break;
        }
        case Kind::QueryCandidate:
            // Only lane0 survives the exact power-of-two reduction. The
            // V13 selection/query AIR owns its canonical decomposition and
            // proof QueryIndex equality.
            add_delegated(
                DelegatedOutputKindV1::
                    QueryCandidateToIndexAir,
                event, 0,
                occurrence::SelectorFamilyV1::None, 0);
            break;
        }
    }

    // Selected z1/z2 and the two derived hashes are not raw V14 event lanes.
    // Inventory their six/eight output lanes anyway so the exclusion is
    // complete and auditable rather than an implicit hole.
    for (const auto family : {
             occurrence::SelectorFamilyV1::
                 OodZ1FirstAcceptable,
             occurrence::SelectorFamilyV1::
                 OodZ2FirstAcceptableDistinctFromZ1}) {
        for (uint8_t lane = 0; lane < 3; ++lane) {
            add_delegated(
                DelegatedOutputKindV1::
                    SelectedOodToFirstAcceptableAir,
                kNoEventV1, lane, family, 0);
        }
    }
    for (uint8_t lane = 0; lane < 4; ++lane) {
        add_delegated(
            DelegatedOutputKindV1::
                DerivedShapeHashToHashAir,
            kNoEventV1, lane,
            occurrence::SelectorFamilyV1::None, 0);
        add_delegated(
            DelegatedOutputKindV1::
                DerivedOodHashToHashAir,
            kNoEventV1, lane,
            occurrence::SelectorFamilyV1::None, 0);
    }

    for (const auto& [key, item] : exported) {
        if (item.event >= manifest.canonical_program.size() ||
            item.lane >= 4) {
            return Fail(why, "exported_producer");
        }
        out.exported.push_back(item);
        if ((item.uses &
             UseBit(ExportUseV1::PriorTranscriptBytes)) != 0) {
            ++out.unique_prior_byte_lanes;
        }
        if ((item.uses &
             UseBit(ExportUseV1::VerifierChallenge)) != 0) {
            ++out.unique_verifier_challenge_lanes;
        }
        if (item.occurrence_consumers > 1) {
            out.duplicate_consumers_collapsed +=
                item.occurrence_consumers - 1;
        }
    }
    for (const auto& [key, item] : delegated) {
        out.delegated.push_back(item);
        switch (item.kind) {
        case DelegatedOutputKindV1::
                OodCandidateToFirstAcceptableAir:
            ++out.delegated_ood_candidate_lanes;
            break;
        case DelegatedOutputKindV1::
                QueryCandidateToIndexAir:
            ++out.delegated_query_candidate_lanes;
            break;
        case DelegatedOutputKindV1::
                SelectedOodToFirstAcceptableAir:
            ++out.delegated_selected_ood_lanes;
            break;
        case DelegatedOutputKindV1::
                DerivedShapeHashToHashAir:
        case DelegatedOutputKindV1::
                DerivedOodHashToHashAir:
            ++out.delegated_derived_hash_lanes;
            break;
        }
    }

    const uint32_t ood_candidates =
        2 * kRCFri3AlgSafeQ192K2OodCandidatesV13 * 3;
    const bool unique_exports =
        std::adjacent_find(
            out.exported.begin(), out.exported.end(),
            [](const auto& left, const auto& right) {
                return left.event == right.event &&
                    left.lane == right.lane;
            }) == out.exported.end();
    out.complete =
        out.manifest_rebuilt &&
        !out.exported.empty() &&
        unique_exports &&
        out.delegated_ood_candidate_lanes ==
            ood_candidates &&
        out.delegated_query_candidate_lanes ==
            kRCFri3AlgNumQueries &&
        out.delegated_selected_ood_lanes == 6 &&
        out.delegated_derived_hash_lanes == 8;
    out.note = out.complete
        ? "canonical unique V14 event-output inventory; "
          "OOD/query/hash outputs delegated"
        : "V14 event-output inventory incomplete";
    if (!out.complete) return Fail(why, "inventory_incomplete");
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildConstraintSystemV1(
    const InventoryV1& inventory,
    aq::AirConstraintSystem<Fp3>& out,
    CellMapV1& cell_map,
    std::string* why)
{
    out = {};
    cell_map = {};
    if (!inventory.complete ||
        inventory.exported.empty()) {
        return Fail(why, "inventory");
    }
    const LayoutV1 layout;
    out.n_rows = NextPow2(std::max<uint32_t>(
        2, static_cast<uint32_t>(
               inventory.exported.size())));
    out.n_columns = layout.End();
    out.preprocessed_pin_ood = true;
    std::vector<Fp3> active(
        out.n_rows, Fp3::Zero());
    std::vector<Fp3> expected_event(
        out.n_rows, Fp3::Zero());
    std::vector<Fp3> expected_lane(
        out.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < inventory.exported.size(); ++row) {
        active[row] = Fp3::One();
        expected_event[row] =
            Base(inventory.exported[row].event);
        expected_lane[row] =
            Base(inventory.exported[row].lane);
    }
    out.preprocessed.emplace_back(
        layout.active, std::move(active));
    out.preprocessed.emplace_back(
        layout.expected_event,
        std::move(expected_event));
    out.preprocessed.emplace_back(
        layout.expected_lane,
        std::move(expected_lane));

    for (uint32_t bit = 0; bit < kCanonicalBitsV1; ++bit) {
        AddConstraint(
            out,
            "stage3.v14_export.bit_boolean",
            aq::AirKind::kEverywhere, 3,
            [layout, bit](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 value = row[layout.Bit(bit)];
                return gf::Mul(
                    row[layout.active],
                    gf::Mul(
                        value,
                        gf::Sub(value, Fp3::One())));
            });
    }
    AddConstraint(
        out,
        "stage3.v14_export.recompose",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 expected = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < 64; ++bit) {
                expected = gf::Add(
                    expected,
                    gf::Mul(power, row[layout.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[layout.active],
                gf::Sub(row[layout.lane_value], expected));
        });
    for (uint32_t step = 0; step < kHighAndStepsV1; ++step) {
        const uint32_t first =
            32 + step * kHighAndChunkV1;
        const uint32_t last = std::min<uint32_t>(
            first + kHighAndChunkV1, 64);
        AddConstraint(
            out,
            "stage3.v14_export.high_and",
            aq::AirKind::kEverywhere, 7,
            [layout, step, first, last](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 product =
                    step == 0
                        ? Fp3::One()
                        : row[layout.HighAnd(step - 1)];
                for (uint32_t bit = first; bit < last; ++bit) {
                    product = gf::Mul(
                        product, row[layout.Bit(bit)]);
                }
                return gf::Mul(
                    row[layout.active],
                    gf::Sub(
                        row[layout.HighAnd(step)],
                        product));
            });
    }
    AddConstraint(
        out,
        "stage3.v14_export.canonical_goldilocks",
        aq::AirKind::kEverywhere, 3,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 low = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                low = gf::Add(
                    low,
                    gf::Mul(power, row[layout.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[layout.active],
                gf::Mul(
                    row[layout.HighAnd(kHighAndStepsV1 - 1)],
                    low));
        });
    for (uint32_t word = 0; word < 2; ++word) {
        AddConstraint(
            out,
            "stage3.v14_export.le32_word",
            aq::AirKind::kEverywhere, 2,
            [layout, word](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 expected = Fp3::Zero();
                Fp3 power = Fp3::One();
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    expected = gf::Add(
                        expected,
                        gf::Mul(
                            power,
                            row[layout.Bit(
                                32 * word + bit)]));
                    power = gf::Add(power, power);
                }
                const uint32_t column =
                    word == 0
                        ? layout.low_word
                        : layout.high_word;
                return gf::Mul(
                    row[layout.active],
                    gf::Sub(row[column], expected));
            });
    }
    AddConstraint(
        out,
        "stage3.v14_export.event_position",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[layout.active],
                gf::Sub(
                    row[layout.event_key],
                    row[layout.expected_event]));
        });
    AddConstraint(
        out,
        "stage3.v14_export.lane_position",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[layout.active],
                gf::Sub(
                    row[layout.lane_key],
                    row[layout.expected_lane]));
        });
    for (uint32_t column = layout.lane_value;
         column <= layout.lane_key; ++column) {
        AddConstraint(
            out,
            "stage3.v14_export.padding_zero",
            aq::AirKind::kEverywhere, 2,
            [layout, column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    OneMinus(row[layout.active]),
                    row[column]);
            });
    }
    AddConstraint(
        out,
        "stage3.v14_export.dependent_zero",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return row[layout.dependent_zero];
        });

    cell_map.exports.reserve(inventory.exported.size());
    for (uint32_t row = 0;
         row < inventory.exported.size(); ++row) {
        const auto& producer = inventory.exported[row];
        cell_map.exports.push_back({
            producer.event,
            producer.lane,
            {layout.lane_value, row},
            {layout.low_word, row},
            {layout.high_word, row},
            {layout.event_key, row},
            {layout.lane_key, row},
        });
    }
    if (why != nullptr) {
        *why = "stage3:v14_event_output_export_air:cs";
    }
    return true;
}

ProductV1 BuildProductV1(const InputV1& input)
{
    ProductV1 out;
    std::string why;
    if (!BuildInventoryV1(
            input.manifest, out.inventory, &why) ||
        input.event_output.size() !=
            input.manifest.canonical_program.size() ||
        !BuildConstraintSystemV1(
            out.inventory, out.cs,
            out.cell_map, &why)) {
        out.note = why.empty()
            ? "stage3:v14_event_output_export_air:input_shape"
            : why;
        return out;
    }
    out.trace_rows = out.cs.n_rows;
    out.active_rows =
        static_cast<uint32_t>(out.inventory.exported.size());
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : out.cs.preprocessed) {
        out.columns[column] = values;
    }

    for (uint32_t row = 0;
         row < out.inventory.exported.size(); ++row) {
        const auto& producer = out.inventory.exported[row];
        if (producer.event >= input.event_output.size() ||
            producer.lane >= 4) {
            out.note =
                "stage3:v14_event_output_export_air:producer";
            return out;
        }
        const uint64_t raw =
            input.event_output[producer.event][producer.lane];
        out.columns[out.layout.lane_value][row] = Base(raw);
        for (uint32_t bit = 0; bit < 64; ++bit) {
            out.columns[out.layout.Bit(bit)][row] =
                Base((raw >> bit) & 1U);
        }
        Fp3 high_and = Fp3::One();
        for (uint32_t step = 0;
             step < kHighAndStepsV1; ++step) {
            const uint32_t first =
                32 + step * kHighAndChunkV1;
            const uint32_t last = std::min<uint32_t>(
                first + kHighAndChunkV1, 64);
            for (uint32_t bit = first; bit < last; ++bit) {
                high_and = gf::Mul(
                    high_and,
                    out.columns[out.layout.Bit(bit)][row]);
            }
            out.columns[out.layout.HighAnd(step)][row] =
                high_and;
        }
        out.columns[out.layout.low_word][row] =
            Base(static_cast<uint32_t>(raw));
        out.columns[out.layout.high_word][row] =
            Base(static_cast<uint32_t>(raw >> 32));
        out.columns[out.layout.event_key][row] =
            Base(producer.event);
        out.columns[out.layout.lane_key][row] =
            Base(producer.lane);
    }
    out.violations =
        CountViolationsV1(out.cs, out.columns);
    for (const auto& constraint : out.cs.constraints) {
        out.max_alg_degree =
            std::max(
                out.max_alg_degree,
                constraint.alg_degree);
    }
    const auto is_preprocessed =
        [&](uint32_t column) {
            return std::any_of(
                out.cs.preprocessed.begin(),
                out.cs.preprocessed.end(),
                [column](const auto& item) {
                    return item.first == column;
                });
        };
    out.input_cells_ordinary =
        !is_preprocessed(out.layout.lane_value);
    out.word_cells_ordinary =
        !is_preprocessed(out.layout.low_word) &&
        !is_preprocessed(out.layout.high_word);
    out.canonical_goldilocks_constrained = true;
    out.le32_exports_constrained = true;
    out.event_lane_positions_constrained = true;
    // The exact cell map is ready for fusion, but this standalone leaf does
    // not pretend that a host-supplied event_output vector is already the
    // resident V14 verifier table.
    out.v14_output_equalities_executed = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.inventory.complete &&
        out.violations == 0 &&
        out.input_cells_ordinary &&
        out.word_cells_ordinary;
    out.note = out.valid
        ? "stage3:v14_event_output_export_air:valid"
        : "stage3:v14_event_output_export_air:constraint_violation";
    return out;
}

uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) return 1;
    std::vector<Fp3> current(
        cs.n_columns, Fp3::Zero());
    std::vector<Fp3> next(
        cs.n_columns, Fp3::Zero());
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            if (columns[column].size() != cs.n_rows) return 1;
            current[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            if (constraint.kind == aq::AirKind::kTransition &&
                row + 1 == cs.n_rows) {
                continue;
            }
            if (!gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_v14_event_output_export_air
