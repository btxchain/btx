// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_selection_query_air.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_v13_selection_query_air {
namespace {

using gf::Fp3;

bool Fail(std::string* why, const char* reason)
{
    if (why != nullptr) {
        *why = std::string("stage3:v13_selection_query_air:") + reason;
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

Fp3 BaseFp(gf::Fp value)
{
    return Fp3::FromFp(value);
}

void AddPreprocessed(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(column, std::move(values));
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

void PutAll(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t column,
    const Fp3& value)
{
    std::fill(columns[column].begin(), columns[column].end(), value);
}

void PutScalarDecomposition(
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t row,
    uint64_t raw)
{
    columns[layout.scalar_value][row] = Base(raw);
    for (uint32_t bit = 0; bit < kCanonicalBitsV1; ++bit) {
        columns[layout.ScalarBit(bit)][row] =
            Base((raw >> bit) & 1U);
    }
    Fp3 product = Fp3::One();
    for (uint32_t step = 0; step < kCanonicalAndStepsV1; ++step) {
        const uint32_t first =
            32 + step * kCanonicalAndChunkV1;
        const uint32_t last = std::min<uint32_t>(
            first + kCanonicalAndChunkV1,
            kCanonicalBitsV1);
        for (uint32_t bit = first; bit < last; ++bit) {
            product = gf::Mul(
                product,
                columns[layout.ScalarBit(bit)][row]);
        }
        columns[layout.ScalarAnd(step)][row] = product;
    }
}

void PutZeroTest(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t zero_column,
    uint32_t inverse_column,
    uint32_t row,
    gf::Fp value)
{
    const bool zero = gf::Canonical(value) == 0;
    columns[zero_column][row] = Base(zero ? 1 : 0);
    columns[inverse_column][row] =
        zero ? Fp3::Zero() : BaseFp(gf::Inv(value));
}

} // namespace

bool BuildConstraintSystemV1(
    uint32_t n_lde,
    uint32_t query_count,
    aq::AirConstraintSystem<Fp3>& out,
    CellMapV1& cell_map,
    std::string* why)
{
    out = {};
    cell_map = {};
    if (n_lde < 2 ||
        n_lde > kMaxProtocolLdeV1 ||
        (n_lde & (n_lde - 1)) != 0) {
        return Fail(why, "n_lde");
    }
    if (query_count == 0 ||
        query_count > kProductionQueriesV1) {
        return Fail(why, "query_count");
    }

    const LayoutV1 layout;
    out.n_rows = NextPow2(kQueryRowBaseV1 + query_count);
    out.n_columns = layout.End();
    // Only positional row selectors are preprocessed.  Dual-OOD pinning
    // avoids rebuilding one Merkle tree per selector in a fused parent.
    out.preprocessed_pin_ood = true;

    std::vector<Fp3> scalar_active(out.n_rows, Fp3::Zero());
    std::vector<Fp3> candidate_active(out.n_rows, Fp3::Zero());
    std::vector<Fp3> query_active(out.n_rows, Fp3::Zero());
    std::vector<Fp3> selection_active(out.n_rows, Fp3::Zero());
    std::array<std::vector<Fp3>, 12> candidate_slot;
    for (auto& slot : candidate_slot) {
        slot.assign(out.n_rows, Fp3::Zero());
    }
    for (uint32_t slot = 0; slot < 12; ++slot) {
        scalar_active[slot] = Fp3::One();
        candidate_active[slot] = Fp3::One();
        candidate_slot[slot][slot] = Fp3::One();
    }
    selection_active[kSelectionRowV1] = Fp3::One();
    for (uint32_t query = 0; query < query_count; ++query) {
        const uint32_t row = kQueryRowBaseV1 + query;
        scalar_active[row] = Fp3::One();
        query_active[row] = Fp3::One();
    }
    AddPreprocessed(
        out, layout.scalar_active, std::move(scalar_active));
    AddPreprocessed(
        out, layout.candidate_active, std::move(candidate_active));
    AddPreprocessed(
        out, layout.query_active, std::move(query_active));
    AddPreprocessed(
        out, layout.selection_active, std::move(selection_active));
    for (uint32_t slot = 0; slot < 12; ++slot) {
        AddPreprocessed(
            out, layout.CandidateSlot(slot),
            std::move(candidate_slot[slot]));
    }

    // Candidate output lanes have to be the same values on the canonical
    // decomposition rows and on the single selection row.
    for (uint32_t candidate = 0;
         candidate < kOodCandidatesV1; ++candidate) {
        for (uint32_t coordinate = 0;
             coordinate < kFp3CoordinatesV1; ++coordinate) {
            const uint32_t column =
                layout.Candidate(candidate, coordinate);
            AddConstraint(
                out,
                "stage3.v13_selection.candidate_stable",
                aq::AirKind::kTransition,
                1,
                [column](
                    const std::vector<Fp3>& current,
                    const std::vector<Fp3>& next) {
                    return gf::Sub(next[column], current[column]);
                });
        }
    }

    // One time-multiplexed canonical Goldilocks decoder services all twelve
    // OOD coordinates and all Q query lanes.  This is the load-bearing
    // x+p defense.
    for (uint32_t bit = 0; bit < kCanonicalBitsV1; ++bit) {
        AddConstraint(
            out,
            "stage3.v13_selection.scalar_bit_boolean",
            aq::AirKind::kEverywhere,
            3,
            [layout, bit](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 value = row[layout.ScalarBit(bit)];
                return gf::Mul(
                    row[layout.scalar_active],
                    gf::Mul(value, gf::Sub(value, Fp3::One())));
            });
    }
    AddConstraint(
        out,
        "stage3.v13_selection.scalar_recompose",
        aq::AirKind::kEverywhere,
        2,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 recomposed = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < kCanonicalBitsV1; ++bit) {
                recomposed = gf::Add(
                    recomposed,
                    gf::Mul(power, row[layout.ScalarBit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[layout.scalar_active],
                gf::Sub(row[layout.scalar_value], recomposed));
        });
    for (uint32_t step = 0;
         step < kCanonicalAndStepsV1; ++step) {
        const uint32_t first =
            32 + step * kCanonicalAndChunkV1;
        const uint32_t last = std::min<uint32_t>(
            first + kCanonicalAndChunkV1,
            kCanonicalBitsV1);
        AddConstraint(
            out,
            "stage3.v13_selection.scalar_high_and",
            aq::AirKind::kEverywhere,
            7,
            [layout, step, first, last](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 product =
                    step == 0
                        ? Fp3::One()
                        : row[layout.ScalarAnd(step - 1)];
                for (uint32_t bit = first; bit < last; ++bit) {
                    product = gf::Mul(
                        product, row[layout.ScalarBit(bit)]);
                }
                return gf::Mul(
                    row[layout.scalar_active],
                    gf::Sub(row[layout.ScalarAnd(step)], product));
            });
    }
    AddConstraint(
        out,
        "stage3.v13_selection.scalar_canonical",
        aq::AirKind::kEverywhere,
        3,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 low = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                low = gf::Add(
                    low,
                    gf::Mul(power, row[layout.ScalarBit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[layout.scalar_active],
                gf::Mul(
                    row[layout.ScalarAnd(
                        kCanonicalAndStepsV1 - 1)],
                    low));
        });
    AddConstraint(
        out,
        "stage3.v13_selection.candidate_source",
        aq::AirKind::kEverywhere,
        3,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 expected = Fp3::Zero();
            for (uint32_t slot = 0; slot < 12; ++slot) {
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        row[layout.CandidateSlot(slot)],
                        row[layout.Candidate(slot / 3, slot % 3)]));
            }
            return gf::Mul(
                row[layout.candidate_active],
                gf::Sub(row[layout.scalar_value], expected));
        });

    uint32_t domain_bits = 0;
    for (uint32_t value = n_lde; value > 1; value >>= 1) {
        ++domain_bits;
    }
    AddConstraint(
        out,
        "stage3.v13_query.low_power_of_two_bits",
        aq::AirKind::kEverywhere,
        2,
        [layout, domain_bits](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 reduced = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < domain_bits; ++bit) {
                reduced = gf::Add(
                    reduced,
                    gf::Mul(power, row[layout.ScalarBit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[layout.query_active],
                gf::Sub(row[layout.query_index], reduced));
        });
    AddConstraint(
        out,
        "stage3.v13_query.proof_tape_equality",
        aq::AirKind::kEverywhere,
        2,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[layout.query_active],
                gf::Sub(
                    row[layout.query_index],
                    row[layout.proof_tape_query_index]));
        });

    // No unconstrained padding cells in the shared scalar/query columns.
    for (uint32_t column = layout.scalar_value;
         column <= layout.ScalarAnd(kCanonicalAndStepsV1 - 1);
         ++column) {
        AddConstraint(
            out,
            "stage3.v13_selection.scalar_padding_zero",
            aq::AirKind::kEverywhere,
            2,
            [layout, column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    OneMinus(row[layout.scalar_active]),
                    row[column]);
            });
    }
    for (uint32_t column :
         {layout.query_index, layout.proof_tape_query_index}) {
        AddConstraint(
            out,
            "stage3.v13_query.padding_zero",
            aq::AirKind::kEverywhere,
            2,
            [layout, column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    OneMinus(row[layout.query_active]),
                    row[column]);
            });
    }

    // Exact nonzero extension tests for all four candidates.
    for (uint32_t candidate = 0;
         candidate < kOodCandidatesV1; ++candidate) {
        for (uint32_t ext = 0; ext < 2; ++ext) {
            const uint32_t value_column =
                layout.Candidate(candidate, ext + 1);
            const uint32_t zero_column =
                layout.ExtZero(candidate, ext);
            const uint32_t inverse_column =
                layout.ExtInverse(candidate, ext);
            AddConstraint(
                out,
                "stage3.v13_selection.ext_zero_boolean",
                aq::AirKind::kEverywhere,
                3,
                [layout, zero_column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.selection_active],
                        gf::Mul(
                            row[zero_column],
                            gf::Sub(
                                row[zero_column], Fp3::One())));
                });
            AddConstraint(
                out,
                "stage3.v13_selection.ext_zero_product",
                aq::AirKind::kEverywhere,
                3,
                [layout, value_column, zero_column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.selection_active],
                        gf::Mul(
                            row[value_column], row[zero_column]));
                });
            AddConstraint(
                out,
                "stage3.v13_selection.ext_zero_inverse",
                aq::AirKind::kEverywhere,
                3,
                [layout, value_column, zero_column, inverse_column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.selection_active],
                        gf::Sub(
                            gf::Mul(
                                row[value_column],
                                row[inverse_column]),
                            OneMinus(row[zero_column])));
                });
        }
        AddConstraint(
            out,
            "stage3.v13_selection.has_extension",
            aq::AirKind::kEverywhere,
            3,
            [layout, candidate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 expected = OneMinus(
                    gf::Mul(
                        row[layout.ExtZero(candidate, 0)],
                        row[layout.ExtZero(candidate, 1)]));
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.HasExtension(candidate)],
                        expected));
            });
    }

    // z2 acceptability additionally requires candidate != selected z1.
    for (uint32_t candidate = 0; candidate < 2; ++candidate) {
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const uint32_t value_column =
                layout.Candidate(2 + candidate, coordinate);
            const uint32_t zero_column =
                layout.DiffZero(candidate, coordinate);
            const uint32_t inverse_column =
                layout.DiffInverse(candidate, coordinate);
            AddConstraint(
                out,
                "stage3.v13_selection.diff_zero_boolean",
                aq::AirKind::kEverywhere,
                3,
                [layout, zero_column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.selection_active],
                        gf::Mul(
                            row[zero_column],
                            gf::Sub(
                                row[zero_column], Fp3::One())));
                });
            AddConstraint(
                out,
                "stage3.v13_selection.diff_zero_product",
                aq::AirKind::kEverywhere,
                3,
                [layout, value_column, zero_column, coordinate](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    const Fp3 difference = gf::Sub(
                        row[value_column],
                        row[layout.SelectedZ1(coordinate)]);
                    return gf::Mul(
                        row[layout.selection_active],
                        gf::Mul(difference, row[zero_column]));
                });
            AddConstraint(
                out,
                "stage3.v13_selection.diff_zero_inverse",
                aq::AirKind::kEverywhere,
                3,
                [layout, value_column, zero_column, inverse_column,
                 coordinate](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    const Fp3 difference = gf::Sub(
                        row[value_column],
                        row[layout.SelectedZ1(coordinate)]);
                    return gf::Mul(
                        row[layout.selection_active],
                        gf::Sub(
                            gf::Mul(
                                difference, row[inverse_column]),
                            OneMinus(row[zero_column])));
                });
        }
        AddConstraint(
            out,
            "stage3.v13_selection.distinct",
            aq::AirKind::kEverywhere,
            4,
            [layout, candidate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 equal = Fp3::One();
                for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
                    equal = gf::Mul(
                        equal,
                        row[layout.DiffZero(candidate, coordinate)]);
                }
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.Distinct(candidate)],
                        OneMinus(equal)));
            });
    }

    for (uint32_t ordinal = 0; ordinal < 2; ++ordinal) {
        AddConstraint(
            out,
            "stage3.v13_selection.z1_acceptable",
            aq::AirKind::kEverywhere,
            2,
            [layout, ordinal](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.Acceptable(0, ordinal)],
                        row[layout.HasExtension(ordinal)]));
            });
        AddConstraint(
            out,
            "stage3.v13_selection.z2_acceptable",
            aq::AirKind::kEverywhere,
            3,
            [layout, ordinal](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.Acceptable(1, ordinal)],
                        gf::Mul(
                            row[layout.HasExtension(2 + ordinal)],
                            row[layout.Distinct(ordinal)])));
            });
    }

    for (uint32_t pair = 0; pair < 2; ++pair) {
        AddConstraint(
            out,
            "stage3.v13_selection.window_not_exhausted",
            aq::AirKind::kEverywhere,
            3,
            [layout, pair](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 a0 =
                    row[layout.Acceptable(pair, 0)];
                const Fp3 a1 =
                    row[layout.Acceptable(pair, 1)];
                const Fp3 some =
                    gf::Add(a0, gf::Mul(OneMinus(a0), a1));
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(some, Fp3::One()));
            });
        AddConstraint(
            out,
            "stage3.v13_selection.first_ordinal",
            aq::AirKind::kEverywhere,
            2,
            [layout, pair](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.SelectedOrdinal(pair)],
                        OneMinus(
                            row[layout.Acceptable(pair, 0)])));
            });
    }

    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        AddConstraint(
            out,
            "stage3.v13_selection.z1_first_value",
            aq::AirKind::kEverywhere,
            3,
            [layout, coordinate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 a0 =
                    row[layout.Acceptable(0, 0)];
                const Fp3 expected = gf::Add(
                    gf::Mul(
                        a0,
                        row[layout.Candidate(0, coordinate)]),
                    gf::Mul(
                        OneMinus(a0),
                        row[layout.Candidate(1, coordinate)]));
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.SelectedZ1(coordinate)],
                        expected));
            });
        AddConstraint(
            out,
            "stage3.v13_selection.z2_first_value",
            aq::AirKind::kEverywhere,
            3,
            [layout, coordinate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 a0 =
                    row[layout.Acceptable(1, 0)];
                const Fp3 expected = gf::Add(
                    gf::Mul(
                        a0,
                        row[layout.Candidate(2, coordinate)]),
                    gf::Mul(
                        OneMinus(a0),
                        row[layout.Candidate(3, coordinate)]));
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.SelectedZ2(coordinate)],
                        expected));
            });
        AddConstraint(
            out,
            "stage3.v13_selection.z1_proof_tape_equality",
            aq::AirKind::kEverywhere,
            2,
            [layout, coordinate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.SelectedZ1(coordinate)],
                        row[layout.ProofTapeZ1(coordinate)]));
            });
        AddConstraint(
            out,
            "stage3.v13_selection.z2_proof_tape_equality",
            aq::AirKind::kEverywhere,
            2,
            [layout, coordinate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.selection_active],
                    gf::Sub(
                        row[layout.SelectedZ2(coordinate)],
                        row[layout.ProofTapeZ2(coordinate)]));
            });
    }

    // Every selection-only ordinary cell is zero away from the designated
    // selection row.  Thus no unused witness freedom survives in the chip.
    for (uint32_t column = layout.ext_zero_base;
         column < layout.scalar_active; ++column) {
        AddConstraint(
            out,
            "stage3.v13_selection.padding_zero",
            aq::AirKind::kEverywhere,
            2,
            [layout, column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    OneMinus(row[layout.selection_active]),
                    row[column]);
            });
    }
    AddConstraint(
        out,
        "stage3.v13_selection.dependent_zero",
        aq::AirKind::kEverywhere,
        1,
        [layout](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return row[layout.dependent_zero];
        });

    for (uint32_t candidate = 0;
         candidate < kOodCandidatesV1; ++candidate) {
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            cell_map.ood_candidate[candidate].coordinate[coordinate] = {
                layout.Candidate(candidate, coordinate),
                kSelectionRowV1};
        }
    }
    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        cell_map.selected_z1.coordinate[coordinate] = {
            layout.SelectedZ1(coordinate), kSelectionRowV1};
        cell_map.selected_z2.coordinate[coordinate] = {
            layout.SelectedZ2(coordinate), kSelectionRowV1};
        cell_map.proof_tape_z1.coordinate[coordinate] = {
            layout.ProofTapeZ1(coordinate), kSelectionRowV1};
        cell_map.proof_tape_z2.coordinate[coordinate] = {
            layout.ProofTapeZ2(coordinate), kSelectionRowV1};
    }
    cell_map.query.resize(query_count);
    for (uint32_t query = 0; query < query_count; ++query) {
        const uint32_t row = kQueryRowBaseV1 + query;
        cell_map.query[query] = {
            {layout.scalar_value, row},
            {layout.query_index, row},
            {layout.proof_tape_query_index, row},
        };
    }
    if (why != nullptr) {
        *why = "stage3:v13_selection_query_air:cs";
    }
    return true;
}

ProductV1 BuildProductV1(const InputV1& input)
{
    ProductV1 out;
    out.query_count =
        static_cast<uint32_t>(input.query_digest_lane0.size());
    if (input.query_digest_lane0.size() !=
        input.proof_query_index.size()) {
        out.note =
            "stage3:v13_selection_query_air:query_witness_count";
        return out;
    }
    std::string why;
    if (!BuildConstraintSystemV1(
            input.n_lde, out.query_count,
            out.cs, out.cell_map, &why)) {
        out.note = why;
        return out;
    }
    out.trace_rows = out.cs.n_rows;
    for (uint32_t value = input.n_lde; value > 1; value >>= 1) {
        ++out.domain_bits;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : out.cs.preprocessed) {
        out.columns[column] = values;
    }

    std::array<gf::Fp3, 4> candidate_fp3{};
    for (uint32_t candidate = 0; candidate < 4; ++candidate) {
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const uint64_t raw =
                input.ood_candidate[candidate].coordinate[coordinate];
            const gf::Fp value = gf::FromU64(raw);
            candidate_fp3[candidate].c0 =
                coordinate == 0 ? value : candidate_fp3[candidate].c0;
            candidate_fp3[candidate].c1 =
                coordinate == 1 ? value : candidate_fp3[candidate].c1;
            candidate_fp3[candidate].c2 =
                coordinate == 2 ? value : candidate_fp3[candidate].c2;
            PutAll(
                out.columns,
                out.layout.Candidate(candidate, coordinate),
                BaseFp(value));
            PutScalarDecomposition(
                out.layout, out.columns,
                3 * candidate + coordinate, raw);
        }
    }
    for (uint32_t query = 0; query < out.query_count; ++query) {
        const uint32_t row = kQueryRowBaseV1 + query;
        const uint64_t raw = input.query_digest_lane0[query];
        PutScalarDecomposition(
            out.layout, out.columns, row, raw);
        const uint32_t reduced =
            static_cast<uint32_t>(
                raw & uint64_t{input.n_lde - 1});
        out.columns[out.layout.query_index][row] = Base(reduced);
        out.columns[out.layout.proof_tape_query_index][row] =
            Base(input.proof_query_index[query]);
    }

    uint32_t z1_ordinal = 0;
    uint32_t z2_ordinal = 0;
    gf::Fp3 selected_z1{};
    gf::Fp3 selected_z2{};
    const std::array<gf::Fp3, 2> z1_candidates{
        candidate_fp3[0], candidate_fp3[1]};
    const std::array<gf::Fp3, 2> z2_candidates{
        candidate_fp3[2], candidate_fp3[3]};
    const bool z1_ok = Fri3AlgSafeSelectOodK2V13(
        z1_candidates, nullptr, z1_ordinal, selected_z1);
    const bool z2_ok = z1_ok &&
        Fri3AlgSafeSelectOodK2V13(
            z2_candidates, &selected_z1,
            z2_ordinal, selected_z2);
    out.selected_z1_ordinal = z1_ordinal;
    out.selected_z2_ordinal = z2_ordinal;

    const uint32_t row = kSelectionRowV1;
    for (uint32_t candidate = 0; candidate < 4; ++candidate) {
        const std::array<gf::Fp, 2> ext{
            candidate_fp3[candidate].c1,
            candidate_fp3[candidate].c2};
        for (uint32_t index = 0; index < 2; ++index) {
            PutZeroTest(
                out.columns,
                out.layout.ExtZero(candidate, index),
                out.layout.ExtInverse(candidate, index),
                row, ext[index]);
        }
        const bool has_ext =
            gf::Canonical(ext[0]) != 0 ||
            gf::Canonical(ext[1]) != 0;
        out.columns[out.layout.HasExtension(candidate)][row] =
            Base(has_ext ? 1 : 0);
    }
    if (z1_ok) {
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const gf::Fp selected =
                coordinate == 0 ? selected_z1.c0
                : coordinate == 1 ? selected_z1.c1
                                  : selected_z1.c2;
            out.columns[out.layout.SelectedZ1(coordinate)][row] =
                BaseFp(selected);
        }
    }
    for (uint32_t candidate = 0; candidate < 2; ++candidate) {
        bool any_difference = false;
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const gf::Fp lhs =
                coordinate == 0 ? candidate_fp3[2 + candidate].c0
                : coordinate == 1 ? candidate_fp3[2 + candidate].c1
                                  : candidate_fp3[2 + candidate].c2;
            const gf::Fp rhs =
                coordinate == 0 ? selected_z1.c0
                : coordinate == 1 ? selected_z1.c1
                                  : selected_z1.c2;
            const gf::Fp difference = gf::Sub(lhs, rhs);
            any_difference =
                any_difference ||
                gf::Canonical(difference) != 0;
            PutZeroTest(
                out.columns,
                out.layout.DiffZero(candidate, coordinate),
                out.layout.DiffInverse(candidate, coordinate),
                row, difference);
        }
        out.columns[out.layout.Distinct(candidate)][row] =
            Base(any_difference ? 1 : 0);
    }

    const bool acceptable_z1_0 =
        gf::Canonical(candidate_fp3[0].c1) != 0 ||
        gf::Canonical(candidate_fp3[0].c2) != 0;
    const bool acceptable_z1_1 =
        gf::Canonical(candidate_fp3[1].c1) != 0 ||
        gf::Canonical(candidate_fp3[1].c2) != 0;
    const auto acceptable_z2 =
        [&](uint32_t candidate) {
            const auto& value = candidate_fp3[2 + candidate];
            const bool has_ext =
                gf::Canonical(value.c1) != 0 ||
                gf::Canonical(value.c2) != 0;
            const bool distinct =
                !z1_ok ||
                value.c0 != selected_z1.c0 ||
                value.c1 != selected_z1.c1 ||
                value.c2 != selected_z1.c2;
            return has_ext && distinct;
        };
    const std::array<bool, 4> acceptable{
        acceptable_z1_0,
        acceptable_z1_1,
        acceptable_z2(0),
        acceptable_z2(1)};
    for (uint32_t pair = 0; pair < 2; ++pair) {
        for (uint32_t ordinal = 0; ordinal < 2; ++ordinal) {
            out.columns[out.layout.Acceptable(pair, ordinal)][row] =
                Base(acceptable[2 * pair + ordinal] ? 1 : 0);
        }
    }
    out.columns[out.layout.SelectedOrdinal(0)][row] =
        Base(z1_ordinal);
    out.columns[out.layout.SelectedOrdinal(1)][row] =
        Base(z2_ordinal);
    if (z2_ok) {
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const gf::Fp selected =
                coordinate == 0 ? selected_z2.c0
                : coordinate == 1 ? selected_z2.c1
                                  : selected_z2.c2;
            out.columns[out.layout.SelectedZ2(coordinate)][row] =
                BaseFp(selected);
        }
    }
    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        out.columns[out.layout.ProofTapeZ1(coordinate)][row] =
            Base(input.proof_tape_z1.coordinate[coordinate]);
        out.columns[out.layout.ProofTapeZ2(coordinate)][row] =
            Base(input.proof_tape_z2.coordinate[coordinate]);
    }

    out.violations = CountViolationsV1(out.cs, out.columns);
    for (const auto& constraint : out.cs.constraints) {
        out.max_alg_degree =
            std::max(out.max_alg_degree, constraint.alg_degree);
    }
    const auto proof_value_preprocessed =
        [&](uint32_t column) {
            return std::any_of(
                out.cs.preprocessed.begin(),
                out.cs.preprocessed.end(),
                [column](const auto& item) {
                    return item.first == column;
                });
        };
    out.candidates_ordinary = std::none_of(
        std::begin(out.cell_map.ood_candidate),
        std::end(out.cell_map.ood_candidate),
        [&](const auto& fp3) {
            return std::any_of(
                fp3.coordinate.begin(), fp3.coordinate.end(),
                [&](const auto& cell) {
                    return proof_value_preprocessed(cell.column);
                });
        });
    out.outputs_ordinary = true;
    for (const auto* fp3 : {
             &out.cell_map.selected_z1,
             &out.cell_map.selected_z2,
             &out.cell_map.proof_tape_z1,
             &out.cell_map.proof_tape_z2}) {
        for (const auto& cell : fp3->coordinate) {
            out.outputs_ordinary &=
                !proof_value_preprocessed(cell.column);
        }
    }
    for (const auto& query : out.cell_map.query) {
        out.outputs_ordinary &=
            !proof_value_preprocessed(
                query.v14_digest_lane0.column) &&
            !proof_value_preprocessed(
                query.reduced_index.column) &&
            !proof_value_preprocessed(
                query.proof_tape_index.column);
    }
    out.canonical_goldilocks_constrained = true;
    out.first_acceptable_constrained = true;
    out.distinct_z2_constrained = true;
    out.local_tape_equality_cells_constrained = true;
    out.query_reduction_constrained = true;
    out.production_q192 =
        out.query_count == kProductionQueriesV1;
    out.actual_v14_output_cells_bound = false;
    out.actual_proof_tape_cells_bound = false;
    out.recursive_authority = false;
    out.valid =
        z1_ok && z2_ok &&
        out.violations == 0 &&
        out.candidates_ordinary &&
        out.outputs_ordinary &&
        !out.actual_v14_output_cells_bound &&
        !out.actual_proof_tape_cells_bound &&
        !out.recursive_authority;
    out.note = out.valid
        ? "stage3:v13_selection_query_air:valid"
        : "stage3:v13_selection_query_air:constraint_violation";
    return out;
}

uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) return 1;
    std::vector<Fp3> current(cs.n_columns, Fp3::Zero());
    std::vector<Fp3> next(cs.n_columns, Fp3::Zero());
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
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

} // namespace matmul::v4::rc::stage3_v13_selection_query_air
