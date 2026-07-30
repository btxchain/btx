// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_query_sampler.h>

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_safe_v12_query_sampler {
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:safe_v12_query_sampler:" + detail;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    uint32_t bits = 0;
    while (value > 1) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

bool CanonicalSource(
    const std::vector<gf::Fp>& values)
{
    return values.size() ==
            kCandidateLanesV12 * kCandidatesV12 &&
        std::all_of(
            values.begin(), values.end(),
            [](gf::Fp value) { return value < gf::kP; });
}

void AddConstraint(
    aq::AirConstraintSystem<gf::Fp3>& cs, const char* name,
    aq::AirKind kind, uint32_t degree,
    std::function<gf::Fp3(
        const std::vector<gf::Fp3>&,
        const std::vector<gf::Fp3>&)> eval)
{
    aq::AirConstraint<gf::Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

void BuildConstraintSystem(
    uint32_t domain_bits,
    aq::AirConstraintSystem<gf::Fp3>& cs)
{
    cs = {};
    const LayoutV12 layout;
    cs.n_rows = kTraceRowsV12;
    cs.n_columns = kAirColumnsV12;
    cs.preprocessed_pin_ood = true;

    for (uint32_t bit = 0; bit < kLaneBitsV12; ++bit) {
        AddConstraint(
            cs, "stage3.safe_v12.query.bit_boolean",
            aq::AirKind::kEverywhere, 2,
            [column = layout.Bit(bit)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(row[column], gf::Fp3::One()));
            });
    }
    AddConstraint(
        cs, "stage3.safe_v12.query.full_limb_recompose",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            gf::Fp3 sum = gf::Fp3::Zero();
            gf::Fp3 power = gf::Fp3::One();
            for (uint32_t bit = 0; bit < kLaneBitsV12; ++bit) {
                sum = gf::Add(
                    sum, gf::Mul(power, row[layout.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(row[layout.Candidate(0)], sum);
        });
    for (uint32_t step = 0; step < kAndStepsV12; ++step) {
        const uint32_t first =
            kHighBitsV12 + step * kAndChunkV12;
        const uint32_t last = std::min<uint32_t>(
            first + kAndChunkV12, kLaneBitsV12);
        AddConstraint(
            cs, "stage3.safe_v12.query.high_and_chain",
            aq::AirKind::kEverywhere,
            kAndChunkV12 + 1,
            [layout, step, first, last](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                gf::Fp3 product =
                    step == 0 ? gf::Fp3::One()
                              : row[layout.And(step - 1)];
                for (uint32_t bit = first; bit < last; ++bit) {
                    product = gf::Mul(
                        product, row[layout.Bit(bit)]);
                }
                return gf::Sub(
                    row[layout.And(step)], product);
            });
    }
    AddConstraint(
        cs, "stage3.safe_v12.query.goldilocks_canonical",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            gf::Fp3 low = gf::Fp3::Zero();
            gf::Fp3 power = gf::Fp3::One();
            for (uint32_t bit = 0; bit < kHighBitsV12; ++bit) {
                low = gf::Add(
                    low, gf::Mul(power, row[layout.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                row[layout.And(kAndStepsV12 - 1)], low);
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.power_of_two_mask",
        aq::AirKind::kEverywhere, 1,
        [layout, domain_bits](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            gf::Fp3 masked = gf::Fp3::Zero();
            gf::Fp3 power = gf::Fp3::One();
            for (uint32_t bit = 0; bit < domain_bits; ++bit) {
                masked = gf::Add(
                    masked,
                    gf::Mul(power, row[layout.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(row[layout.index], masked);
        });

    for (uint32_t count = 0; count <= kQueriesV12; ++count) {
        AddConstraint(
            cs, "stage3.safe_v12.query.count_boolean",
            aq::AirKind::kEverywhere, 2,
            [column = layout.Count(count)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(row[column], gf::Fp3::One()));
            });
    }
    AddConstraint(
        cs, "stage3.safe_v12.query.count_one_hot",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            gf::Fp3 sum = gf::Fp3::Zero();
            for (uint32_t count = 0;
                 count <= kQueriesV12; ++count) {
                sum = gf::Add(sum, row[layout.Count(count)]);
            }
            return gf::Sub(sum, gf::Fp3::One());
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.count_initial",
        aq::AirKind::kFirstRow, 1,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                row[layout.Count(0)], gf::Fp3::One());
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.count_terminal_q96",
        aq::AirKind::kLastRow, 1,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                row[layout.Count(kQueriesV12)],
                gf::Fp3::One());
        });

    for (uint32_t degree = 0;
         degree <= kQueriesV12; ++degree) {
        AddConstraint(
            cs, "stage3.safe_v12.query.polynomial_initial",
            aq::AirKind::kFirstRow, 1,
            [layout, degree](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                const gf::Fp3 expected =
                    degree == 0 ? gf::Fp3::One()
                                : gf::Fp3::Zero();
                return gf::Sub(
                    row[layout.Coefficient(degree)], expected);
            });
    }
    for (uint32_t query = 0; query < kQueriesV12; ++query) {
        AddConstraint(
            cs, "stage3.safe_v12.query.output_initial",
            aq::AirKind::kFirstRow, 1,
            [column = layout.Output(query)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return row[column];
            });
    }

    AddConstraint(
        cs, "stage3.safe_v12.query.horner_leading",
        aq::AirKind::kEverywhere, 1,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                row[layout.Horner(kQueriesV12)],
                row[layout.Coefficient(kQueriesV12)]);
        });
    for (uint32_t degree = 0; degree < kQueriesV12; ++degree) {
        const uint32_t reverse_degree =
            kQueriesV12 - 1 - degree;
        AddConstraint(
            cs, "stage3.safe_v12.query.horner_step",
            aq::AirKind::kEverywhere, 2,
            [layout, reverse_degree](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                const gf::Fp3 expected = gf::Add(
                    gf::Mul(
                        row[layout.Horner(reverse_degree + 1)],
                        row[layout.index]),
                    row[layout.Coefficient(reverse_degree)]);
                return gf::Sub(
                    row[layout.Horner(reverse_degree)], expected);
            });
    }
    AddConstraint(
        cs, "stage3.safe_v12.query.active_evaluation",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                row[layout.evaluation],
                gf::Mul(
                    row[layout.active],
                    row[layout.Horner(0)]));
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.unique_inverse",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[layout.evaluation],
                    row[layout.inverse]),
                row[layout.unique]);
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.unique_zero_test",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                row[layout.evaluation],
                gf::Sub(
                    gf::Fp3::One(), row[layout.unique]));
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.unique_boolean",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                row[layout.unique],
                gf::Sub(
                    row[layout.unique], gf::Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.first_distinct_select",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            const gf::Fp3 expected = gf::Mul(
                row[layout.unique],
                gf::Sub(
                    gf::Fp3::One(),
                    row[layout.Count(kQueriesV12)]));
            return gf::Sub(row[layout.selected], expected);
        });
    AddConstraint(
        cs, "stage3.safe_v12.query.selected_boolean",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                row[layout.selected],
                gf::Sub(
                    row[layout.selected], gf::Fp3::One()));
        });

    for (uint32_t query = 0; query < kQueriesV12; ++query) {
        AddConstraint(
            cs, "stage3.safe_v12.query.write_selector",
            aq::AirKind::kEverywhere, 2,
            [layout, query](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    row[layout.Write(query)],
                    gf::Mul(
                        row[layout.selected],
                        row[layout.Count(query)]));
            });
    }
    for (uint32_t count = 0; count <= kQueriesV12; ++count) {
        AddConstraint(
            cs, "stage3.safe_v12.query.count_transition",
            aq::AirKind::kTransition, 1,
            [layout, count](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>& next) {
                gf::Fp3 expected = row[layout.Count(count)];
                if (count < kQueriesV12) {
                    expected = gf::Sub(
                        expected, row[layout.Write(count)]);
                }
                if (count > 0) {
                    expected = gf::Add(
                        expected, row[layout.Write(count - 1)]);
                }
                return gf::Sub(
                    next[layout.Count(count)], expected);
            });
    }
    for (uint32_t degree = 0;
         degree <= kQueriesV12; ++degree) {
        AddConstraint(
            cs, "stage3.safe_v12.query.polynomial_transition",
            aq::AirKind::kTransition, 3,
            [layout, degree](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>& next) {
                const gf::Fp3 current =
                    row[layout.Coefficient(degree)];
                gf::Fp3 multiplied = gf::Neg(gf::Mul(
                    row[layout.index], current));
                if (degree > 0) {
                    multiplied = gf::Add(
                        multiplied,
                        row[layout.Coefficient(degree - 1)]);
                }
                const gf::Fp3 expected = gf::Add(
                    current,
                    gf::Mul(
                        row[layout.selected],
                        gf::Sub(multiplied, current)));
                return gf::Sub(
                    next[layout.Coefficient(degree)], expected);
            });
    }
    for (uint32_t query = 0; query < kQueriesV12; ++query) {
        AddConstraint(
            cs, "stage3.safe_v12.query.output_transition",
            aq::AirKind::kTransition, 2,
            [layout, query](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>& next) {
                const gf::Fp3 current =
                    row[layout.Output(query)];
                const gf::Fp3 expected = gf::Add(
                    current,
                    gf::Mul(
                        row[layout.Write(query)],
                        gf::Sub(row[layout.index], current)));
                return gf::Sub(
                    next[layout.Output(query)], expected);
            });
    }
}

bool SameFp3Vector(
    const std::vector<gf::Fp3>& left,
    const std::vector<gf::Fp3>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (!gf::Eq(left[i], right[i])) return false;
    }
    return true;
}

bool SameColumns(
    const std::vector<std::vector<gf::Fp3>>& left,
    const std::vector<std::vector<gf::Fp3>>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t column = 0; column < left.size(); ++column) {
        if (!SameFp3Vector(left[column], right[column])) {
            return false;
        }
    }
    return true;
}

bool SamePreprocessed(
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& left,
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (left[i].first != right[i].first ||
            !SameFp3Vector(left[i].second, right[i].second)) {
            return false;
        }
    }
    return true;
}

} // namespace

bool SelectFirstDistinctV12(
    const std::vector<gf::Fp>& squeezed_lanes,
    uint32_t n_lde, std::vector<uint32_t>& selected_indices,
    std::vector<uint32_t>* selected_ordinals,
    std::string* why)
{
    selected_indices.clear();
    if (selected_ordinals != nullptr) {
        selected_ordinals->clear();
    }
    if (!CanonicalSource(squeezed_lanes) ||
        !IsPowerOfTwo(n_lde) || n_lde < 128 ||
        n_lde > (UINT32_C(1) << 31)) {
        return Fail(why, "noncanonical candidate/domain shape");
    }
    std::set<uint32_t> seen;
    for (uint32_t candidate = 0;
         candidate < kCandidatesV12 &&
         selected_indices.size() < kQueriesV12;
         ++candidate) {
        const uint64_t canonical =
            gf::Canonical(
                squeezed_lanes[kCandidateLanesV12 * candidate]);
        const uint32_t index = static_cast<uint32_t>(
            canonical & (n_lde - 1));
        if (!seen.insert(index).second) continue;
        selected_indices.push_back(index);
        if (selected_ordinals != nullptr) {
            selected_ordinals->push_back(candidate);
        }
    }
    if (selected_indices.size() != kQueriesV12) {
        return Fail(why, "bounded candidates exhausted");
    }
    return true;
}

uint32_t CountQuerySamplerViolationsV12(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (cs.n_rows == 0 || columns.size() != cs.n_columns) {
        return std::numeric_limits<uint32_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint32_t>::max();
        }
    }
    uint32_t violations = 0;
    std::vector<gf::Fp3> row(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    for (uint32_t r = 0; r < cs.n_rows; ++r) {
        const uint32_t next_row =
            r + 1 < cs.n_rows ? r + 1 : r;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            row[column] = columns[column][r];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool evaluate = true;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                break;
            case aq::AirKind::kTransition:
                evaluate = r + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                evaluate = r == 0;
                break;
            case aq::AirKind::kLastRow:
                evaluate = r + 1 == cs.n_rows;
                break;
            }
            if (evaluate &&
                !gf::IsZero(constraint.eval(row, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool BuildQuerySamplerAirV12(
    uint32_t lane, uint32_t n_lde,
    const std::vector<gf::Fp>& squeezed_lanes,
    QuerySamplerAirV12& out, std::string* why)
{
    out = {};
    if (lane >= 2 || !CanonicalSource(squeezed_lanes) ||
        !IsPowerOfTwo(n_lde) || n_lde < 128 ||
        n_lde > (UINT32_C(1) << 31)) {
        return Fail(why, "invalid sampler input");
    }
    out.lane = lane;
    out.n_lde = n_lde;
    out.domain_bits = Log2Exact(n_lde);
    BuildConstraintSystem(out.domain_bits, out.cs);
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows, gf::Fp3::Zero()));

    const LayoutV12 layout;
    std::vector<gf::Fp3> active(
        kTraceRowsV12, gf::Fp3::Zero());
    for (uint32_t row = 0; row < kCandidatesV12; ++row) {
        active[row] = gf::Fp3::One();
    }
    out.cs.preprocessed.emplace_back(layout.active, active);
    out.verifier_owned_preprocessed_columns = 1;
    out.proof_owned_preprocessed_columns = 0;

    out.source_candidates.reserve(kCandidatesV12);
    for (uint32_t candidate = 0;
         candidate < kCandidatesV12; ++candidate) {
        out.source_candidates.push_back(gf::Fp3{
            squeezed_lanes[kCandidateLanesV12 * candidate],
            squeezed_lanes[kCandidateLanesV12 * candidate + 1],
            squeezed_lanes[kCandidateLanesV12 * candidate + 2]});
    }

    std::array<gf::Fp, kQueriesV12 + 1> coefficients{};
    coefficients[0] = gf::FromU64(1);
    std::array<gf::Fp, kQueriesV12> outputs{};
    uint32_t selected_count = 0;

    for (uint32_t row = 0; row < kTraceRowsV12; ++row) {
        const bool candidate_active = row < kCandidatesV12;
        gf::Fp candidate_lanes[kCandidateLanesV12] = {0, 0, 0};
        if (candidate_active) {
            for (uint32_t lane_index = 0;
                 lane_index < kCandidateLanesV12; ++lane_index) {
                candidate_lanes[lane_index] =
                    squeezed_lanes[
                        kCandidateLanesV12 * row + lane_index];
            }
        }
        for (uint32_t lane_index = 0;
             lane_index < kCandidateLanesV12; ++lane_index) {
            out.columns[layout.Candidate(lane_index)][row] =
                gf::Fp3::FromFp(candidate_lanes[lane_index]);
        }
        const uint64_t canonical =
            gf::Canonical(candidate_lanes[0]);
        for (uint32_t bit = 0; bit < kLaneBitsV12; ++bit) {
            out.columns[layout.Bit(bit)][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    (canonical >> bit) & 1));
        }
        gf::Fp high_product = gf::FromU64(1);
        for (uint32_t step = 0; step < kAndStepsV12; ++step) {
            const uint32_t first =
                kHighBitsV12 + step * kAndChunkV12;
            const uint32_t last = std::min<uint32_t>(
                first + kAndChunkV12, kLaneBitsV12);
            for (uint32_t bit = first; bit < last; ++bit) {
                high_product = gf::Mul(
                    high_product,
                    gf::FromU64((canonical >> bit) & 1));
            }
            out.columns[layout.And(step)][row] =
                gf::Fp3::FromFp(high_product);
        }
        const uint32_t index = static_cast<uint32_t>(
            canonical & (n_lde - 1));
        out.columns[layout.index][row] =
            gf::Fp3::FromFp(gf::FromU64(index));
        out.columns[layout.active][row] = active[row];

        out.columns[layout.Count(selected_count)][row] =
            gf::Fp3::One();
        for (uint32_t degree = 0;
             degree <= kQueriesV12; ++degree) {
            out.columns[layout.Coefficient(degree)][row] =
                gf::Fp3::FromFp(coefficients[degree]);
        }
        for (uint32_t query = 0;
             query < kQueriesV12; ++query) {
            out.columns[layout.Output(query)][row] =
                gf::Fp3::FromFp(outputs[query]);
        }

        std::array<gf::Fp, kQueriesV12 + 1> horner{};
        horner[kQueriesV12] = coefficients[kQueriesV12];
        for (uint32_t step = 0; step < kQueriesV12; ++step) {
            const uint32_t degree =
                kQueriesV12 - 1 - step;
            horner[degree] = gf::Add(
                gf::Mul(horner[degree + 1], gf::FromU64(index)),
                coefficients[degree]);
        }
        for (uint32_t degree = 0;
             degree <= kQueriesV12; ++degree) {
            out.columns[layout.Horner(degree)][row] =
                gf::Fp3::FromFp(horner[degree]);
        }
        const gf::Fp evaluation =
            candidate_active ? horner[0] : 0;
        const bool unique = evaluation != 0;
        const bool selected =
            unique && selected_count < kQueriesV12;
        out.columns[layout.evaluation][row] =
            gf::Fp3::FromFp(evaluation);
        out.columns[layout.inverse][row] =
            unique
            ? gf::Fp3::FromFp(gf::Inv(evaluation))
            : gf::Fp3::Zero();
        out.columns[layout.unique][row] =
            unique ? gf::Fp3::One() : gf::Fp3::Zero();
        out.columns[layout.selected][row] =
            selected ? gf::Fp3::One() : gf::Fp3::Zero();

        if (selected) {
            out.columns[layout.Write(selected_count)][row] =
                gf::Fp3::One();
            out.selected_indices.push_back(index);
            out.selected_candidate_ordinals.push_back(row);
            outputs[selected_count] = gf::FromU64(index);
            std::array<gf::Fp, kQueriesV12 + 1> updated{};
            updated[0] = gf::Neg(gf::Mul(
                gf::FromU64(index), coefficients[0]));
            for (uint32_t degree = 1;
                 degree <= kQueriesV12; ++degree) {
                updated[degree] = gf::Sub(
                    coefficients[degree - 1],
                    gf::Mul(
                        gf::FromU64(index),
                        coefficients[degree]));
            }
            coefficients = updated;
            ++selected_count;
        }
    }

    out.selected_count = selected_count;
    out.constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
        out.max_alg_degree =
            std::max(
                out.max_alg_degree,
                constraint.alg_degree);
    }
    out.violations =
        CountQuerySamplerViolationsV12(out.cs, out.columns);
    out.source_candidate_vector_shape_canonical = true;
    out.full_limb_canonicity_constrained = true;
    out.index_range_constrained = true;
    out.first_distinct_order_constrained = true;
    out.uniqueness_constrained = true;
    out.exact_q96_exhaustion_constrained = true;
    out.selected_outputs_constrained = true;
    out.recursive_safe_source_equality_consumed = false;
    out.valid =
        out.selected_count == kQueriesV12 &&
        out.selected_indices.size() == kQueriesV12 &&
        out.selected_candidate_ordinals.size() == kQueriesV12 &&
        out.violations == 0 &&
        out.max_alg_degree <= 7 &&
        out.verifier_owned_preprocessed_columns == 1 &&
        out.proof_owned_preprocessed_columns == 0;
    out.note = out.valid
        ? "stage3:safe_v12_query_sampler:"
          "first_96_distinct_air_ok"
        : "stage3:safe_v12_query_sampler:"
          "bounded_exhaustion_or_constraint_violation";
    if (!out.valid) {
        return Fail(
            why, "bounded exhaustion or AIR violation");
    }
    return true;
}

bool SameQuerySamplerAirV12(
    const QuerySamplerAirV12& left,
    const QuerySamplerAirV12& right)
{
    if (!SameColumns(left.columns, right.columns) ||
        !SameFp3Vector(
            left.source_candidates,
            right.source_candidates) ||
        !SamePreprocessed(
            left.cs.preprocessed,
            right.cs.preprocessed) ||
        left.cs.n_rows != right.cs.n_rows ||
        left.cs.n_columns != right.cs.n_columns ||
        left.cs.constraints.size() !=
            right.cs.constraints.size() ||
        left.cs.preprocessed_pin_ood !=
            right.cs.preprocessed_pin_ood ||
        left.selected_indices != right.selected_indices ||
        left.selected_candidate_ordinals !=
            right.selected_candidate_ordinals ||
        left.lane != right.lane ||
        left.n_lde != right.n_lde ||
        left.domain_bits != right.domain_bits ||
        left.selected_count != right.selected_count ||
        left.constraints != right.constraints ||
        left.violations != right.violations ||
        left.max_alg_degree != right.max_alg_degree ||
        left.verifier_owned_preprocessed_columns !=
            right.verifier_owned_preprocessed_columns ||
        left.proof_owned_preprocessed_columns !=
            right.proof_owned_preprocessed_columns ||
        left.source_candidate_vector_shape_canonical !=
            right.source_candidate_vector_shape_canonical ||
        left.full_limb_canonicity_constrained !=
            right.full_limb_canonicity_constrained ||
        left.index_range_constrained !=
            right.index_range_constrained ||
        left.first_distinct_order_constrained !=
            right.first_distinct_order_constrained ||
        left.uniqueness_constrained !=
            right.uniqueness_constrained ||
        left.exact_q96_exhaustion_constrained !=
            right.exact_q96_exhaustion_constrained ||
        left.selected_outputs_constrained !=
            right.selected_outputs_constrained ||
        left.recursive_safe_source_equality_consumed !=
            right.recursive_safe_source_equality_consumed ||
        left.valid != right.valid ||
        left.note != right.note) {
        return false;
    }
    for (size_t i = 0; i < left.cs.constraints.size(); ++i) {
        if (left.cs.constraints[i].kind !=
                right.cs.constraints[i].kind ||
            left.cs.constraints[i].alg_degree !=
                right.cs.constraints[i].alg_degree ||
            std::string(left.cs.constraints[i].name) !=
                right.cs.constraints[i].name) {
            return false;
        }
    }
    return true;
}

bool ValidateQuerySamplerAirV12(
    uint32_t lane, uint32_t n_lde,
    const std::vector<gf::Fp>& squeezed_lanes,
    const QuerySamplerAirV12& air,
    std::string* why)
{
    if (!air.valid ||
        CountQuerySamplerViolationsV12(
            air.cs, air.columns) != 0) {
        return Fail(why, "supplied sampler AIR invalid");
    }
    QuerySamplerAirV12 expected;
    if (!BuildQuerySamplerAirV12(
            lane, n_lde, squeezed_lanes, expected, why)) {
        return false;
    }
    if (!SameQuerySamplerAirV12(air, expected)) {
        return Fail(why, "sampler AIR reconstruction mismatch");
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_safe_v12_query_sampler
