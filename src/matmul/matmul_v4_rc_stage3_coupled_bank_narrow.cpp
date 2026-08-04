// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_bank_narrow.h>

#include <hash.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;

constexpr uint32_t TERMINAL_WORDS = 18;
constexpr uint32_t TERMINAL_ROWS = 4;
constexpr uint32_t TERMINAL_VALUE_BASE = 0;
constexpr uint32_t TERMINAL_PARENT_BASE =
    TERMINAL_VALUE_BASE + TERMINAL_WORDS;
constexpr uint32_t TERMINAL_SELECTOR_BASE =
    TERMINAL_PARENT_BASE + TERMINAL_WORDS;
constexpr uint32_t TERMINAL_COLUMNS =
    TERMINAL_SELECTOR_BASE + TERMINAL_ROWS;

constexpr gf::Fp OMEGA_2_32 =
    UINT64_C(0x185629dcda58878c);

gf::Fp PowFp(gf::Fp base, uint64_t exponent)
{
    gf::Fp out = gf::FromU64(1);
    base = gf::Canonical(base);
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

gf::Fp3 PowFp3(gf::Fp3 base, uint64_t exponent)
{
    gf::Fp3 out = gf::Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

uint32_t Log2Exact(uint32_t value)
{
    if (value == 0 ||
        (value & (value - 1)) != 0) {
        return 0;
    }
    uint32_t log = 0;
    while (value > 1) {
        value >>= 1;
        ++log;
    }
    return log;
}

uint32_t NextPow2(uint64_t value)
{
    uint64_t out = 2;
    while (out < value) {
        if (out > UINT32_MAX / 2U) return 0;
        out <<= 1;
    }
    return static_cast<uint32_t>(out);
}

gf::Fp3 DomainPoint(uint32_t size, uint32_t index)
{
    const uint32_t log = Log2Exact(size);
    if (log == 0 && size != 1) return gf::Fp3::Zero();
    const gf::Fp omega = PowFp(
        OMEGA_2_32, uint64_t{1} << (32 - log));
    return gf::Fp3::FromFp(PowFp(omega, index));
}

struct ScalarLayout {
    uint32_t width{0};
    uint32_t folds{0};
    uint32_t constraints{0};
    uint32_t current{0};
    uint32_t next{0};
    uint32_t fold_even{0};
    uint32_t fold_odd{0};
    uint32_t folded{0};
    uint32_t eval_z1{0};
    uint32_t eval_z2{0};
    uint32_t expected_current{0};
    uint32_t expected_next{0};
    uint32_t expected_even{0};
    uint32_t expected_odd{0};
    uint32_t expected_eval_z1{0};
    uint32_t expected_eval_z2{0};
    uint32_t u_weight{0};
    uint32_t v1_weight{0};
    uint32_t v2_weight{0};
    uint32_t fold_x{0};
    uint32_t fold_beta{0};
    uint32_t fold_leaf_selector{0};
    uint32_t inverse_d1{0};
    uint32_t inverse_d2{0};
    uint32_t deep_weight1{0};
    uint32_t deep_weight2{0};
    uint32_t zh{0};
    uint32_t final_value{0};
    uint32_t constraint_weight{0};
    uint32_t terminal_value{0};
    uint32_t parent_value{0};
    uint32_t lane_selector{0};
    uint32_t lane_end_selector{0};
    uint32_t active{0};
    uint32_t deep_u{0};
    uint32_t deep_v1{0};
    uint32_t deep_v2{0};
    uint32_t deep_term1{0};
    uint32_t deep_term2{0};
    uint32_t deep_leaf{0};
    uint32_t constraint_eval{0};
    uint32_t end{0};

    ScalarLayout(
        uint32_t child_width,
        uint32_t n_folds,
        uint32_t n_constraints)
        : width(child_width),
          folds(n_folds),
          constraints(n_constraints)
    {
        uint32_t cursor = 0;
        current = cursor;
        cursor += width + 1;
        next = cursor;
        cursor += width;
        fold_even = cursor;
        cursor += folds;
        fold_odd = cursor;
        cursor += folds;
        folded = cursor;
        cursor += folds;
        eval_z1 = cursor;
        cursor += width + 1;
        eval_z2 = cursor;
        cursor += width + 1;
        expected_current = cursor;
        cursor += width + 1;
        expected_next = cursor;
        cursor += width;
        expected_even = cursor;
        cursor += folds;
        expected_odd = cursor;
        cursor += folds;
        expected_eval_z1 = cursor;
        cursor += width + 1;
        expected_eval_z2 = cursor;
        cursor += width + 1;
        u_weight = cursor;
        cursor += width + 1;
        v1_weight = cursor;
        cursor += width + 1;
        v2_weight = cursor;
        cursor += width + 1;
        fold_x = cursor;
        cursor += folds;
        fold_beta = cursor;
        cursor += folds;
        fold_leaf_selector = cursor;
        cursor += folds;
        inverse_d1 = cursor++;
        inverse_d2 = cursor++;
        deep_weight1 = cursor++;
        deep_weight2 = cursor++;
        zh = cursor++;
        final_value = cursor++;
        constraint_weight = cursor;
        cursor += constraints;
        terminal_value = cursor;
        cursor += TERMINAL_WORDS;
        parent_value = cursor;
        cursor += TERMINAL_WORDS;
        lane_selector = cursor;
        cursor += TERMINAL_ROWS;
        lane_end_selector = cursor;
        cursor += TERMINAL_ROWS;
        active = cursor++;
        deep_u = cursor++;
        deep_v1 = cursor++;
        deep_v2 = cursor++;
        deep_term1 = cursor++;
        deep_term2 = cursor++;
        deep_leaf = cursor++;
        constraint_eval = cursor;
        cursor += constraints;
        end = cursor;
    }
};

bool ExtractTerminalWords(
    const ar::ChildPublicInputs& pi,
    uint32_t base,
    std::array<uint32_t, TERMINAL_WORDS>& out)
{
    if (base > pi.evals_z1.size() ||
        pi.evals_z1.size() - base < TERMINAL_WORDS ||
        base > pi.evals_z2.size() ||
        pi.evals_z2.size() - base < TERMINAL_WORDS) {
        return false;
    }
    for (uint32_t word = 0; word < TERMINAL_WORDS; ++word) {
        const gf::Fp3& z1 = pi.evals_z1[base + word];
        const gf::Fp3& z2 = pi.evals_z2[base + word];
        if (!gf::Eq(z1, z2) ||
            gf::Canonical(z1.c1) != 0 ||
            gf::Canonical(z1.c2) != 0 ||
            gf::Canonical(z1.c0) >
                std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        out[word] =
            static_cast<uint32_t>(gf::Canonical(z1.c0));
    }
    return true;
}

void AddPreprocessed(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    uint32_t column,
    const std::vector<gf::Fp3>& values)
{
    cs.preprocessed.emplace_back(column, values);
}

void AddConstraint(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
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

bool BuildTerminalRelation(
    const std::array<
        std::array<uint32_t, TERMINAL_WORDS>,
        TERMINAL_ROWS>& lane_words,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    std::array<uint32_t, TERMINAL_WORDS>& parent)
{
    // Ordered rows: child0/lane0, child0/lane1,
    //               child1/lane0, child1/lane1.
    for (uint32_t word = 0; word < TERMINAL_WORDS; ++word) {
        if (lane_words[0][word] != lane_words[1][word] ||
            lane_words[2][word] != lane_words[3][word]) {
            return false;
        }
    }
    if (uint64_t{lane_words[0][0]} +
            lane_words[0][1] != lane_words[2][0]) {
        return false;
    }
    for (uint32_t word = 0; word < 8; ++word) {
        if (lane_words[0][10 + word] !=
            lane_words[2][2 + word]) {
            return false;
        }
    }
    parent[0] = lane_words[0][0];
    parent[1] = lane_words[0][1] + lane_words[2][1];
    for (uint32_t word = 0; word < 8; ++word) {
        parent[2 + word] = lane_words[0][2 + word];
        parent[10 + word] = lane_words[2][10 + word];
    }

    cs = {};
    cs.n_rows = TERMINAL_ROWS;
    cs.n_columns = TERMINAL_COLUMNS;
    cs.preprocessed_pin_ood = true;
    columns.assign(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));

    for (uint32_t word = 0; word < TERMINAL_WORDS; ++word) {
        std::vector<gf::Fp3> values(
            TERMINAL_ROWS, gf::Fp3::Zero());
        std::vector<gf::Fp3> parent_values(
            TERMINAL_ROWS,
            gf::Fp3::FromFp(
                gf::FromU64(parent[word])));
        for (uint32_t row = 0; row < TERMINAL_ROWS; ++row) {
            values[row] = gf::Fp3::FromFp(
                gf::FromU64(lane_words[row][word]));
        }
        columns[TERMINAL_VALUE_BASE + word] = values;
        columns[TERMINAL_PARENT_BASE + word] = parent_values;
        AddPreprocessed(
            cs, TERMINAL_VALUE_BASE + word, values);
        AddPreprocessed(
            cs, TERMINAL_PARENT_BASE + word,
            parent_values);
    }
    for (uint32_t selected = 0;
         selected < TERMINAL_ROWS; ++selected) {
        std::vector<gf::Fp3> selector(
            TERMINAL_ROWS, gf::Fp3::Zero());
        selector[selected] = gf::Fp3::One();
        columns[TERMINAL_SELECTOR_BASE + selected] =
            selector;
        AddPreprocessed(
            cs, TERMINAL_SELECTOR_BASE + selected,
            selector);
    }

    // Equality of the two ordered repetitions for each logical child.
    for (uint32_t word = 0; word < TERMINAL_WORDS; ++word) {
        AddConstraint(
            cs, "stage3.bank_narrow.lane_equality",
            aq::AirKind::kTransition, 2,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>& next) {
                const gf::Fp3 selector = gf::Add(
                    cur[TERMINAL_SELECTOR_BASE],
                    cur[TERMINAL_SELECTOR_BASE + 2]);
                return gf::Mul(
                    selector,
                    gf::Sub(
                        cur[TERMINAL_VALUE_BASE + word],
                        next[TERMINAL_VALUE_BASE + word]));
            });
    }

    // The two logical children form one contiguous SHA interval.
    AddConstraint(
        cs, "stage3.bank_narrow.contiguous_interval",
        aq::AirKind::kTransition, 2,
        [](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                cur[TERMINAL_SELECTOR_BASE + 1],
                gf::Sub(
                    gf::Add(
                        cur[TERMINAL_VALUE_BASE],
                        cur[TERMINAL_VALUE_BASE + 1]),
                    next[TERMINAL_VALUE_BASE]));
        });
    for (uint32_t word = 0; word < 8; ++word) {
        AddConstraint(
            cs, "stage3.bank_narrow.sha_chain",
            aq::AirKind::kTransition, 2,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>& next) {
                return gf::Mul(
                    cur[TERMINAL_SELECTOR_BASE + 1],
                    gf::Sub(
                        cur[TERMINAL_VALUE_BASE + 10 + word],
                        next[TERMINAL_VALUE_BASE + 2 + word]));
            });
    }

    // Compact public parent: first/count/H_in from child 0 and H_out from
    // child 1.  Parent columns are public/preprocessed and constant.
    for (uint32_t word = 0; word < 10; ++word) {
        if (word == 1) continue;
        AddConstraint(
            cs, "stage3.bank_narrow.parent_prefix",
            aq::AirKind::kEverywhere, 2,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[TERMINAL_SELECTOR_BASE],
                    gf::Sub(
                        cur[TERMINAL_PARENT_BASE + word],
                        cur[TERMINAL_VALUE_BASE + word]));
            });
    }
    for (uint32_t word = 0; word < 8; ++word) {
        AddConstraint(
            cs, "stage3.bank_narrow.parent_suffix",
            aq::AirKind::kEverywhere, 2,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[TERMINAL_SELECTOR_BASE + 2],
                    gf::Sub(
                        cur[TERMINAL_PARENT_BASE + 10 + word],
                        cur[TERMINAL_VALUE_BASE + 10 + word]));
            });
    }
    AddConstraint(
        cs, "stage3.bank_narrow.parent_count",
        aq::AirKind::kTransition, 2,
        [](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                cur[TERMINAL_SELECTOR_BASE + 1],
                gf::Sub(
                    cur[TERMINAL_PARENT_BASE + 1],
                    gf::Add(
                        cur[TERMINAL_VALUE_BASE + 1],
                        next[TERMINAL_VALUE_BASE + 1])));
        });
    return true;
}

bool BuildScalarRelation(
    const std::array<ar::ChildPublicInputs, TERMINAL_ROWS>& pis,
    const std::vector<ar::DualAlgAirProof>& children,
    const std::array<
        std::array<uint32_t, TERMINAL_WORDS>,
        TERMINAL_ROWS>& terminal_words,
    const std::array<uint32_t, TERMINAL_WORDS>& parent_words,
    uint32_t terminal_base,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    const uint32_t width = pis[0].child_w;
    const uint32_t folds = pis[0].n_folds;
    const uint32_t queries =
        static_cast<uint32_t>(pis[0].query_index.size());
    const uint32_t constraints =
        static_cast<uint32_t>(
            pis[0].child_constraints.size());
    if (width == 0 || folds == 0 || queries == 0 ||
        constraints == 0 || children.size() != 2 ||
        terminal_base > width + 1 ||
        width + 1 - terminal_base < TERMINAL_WORDS) {
        return false;
    }
    for (const auto& pi : pis) {
        if (!pi.ok || pi.child_w != width ||
            pi.n_folds != folds ||
            pi.query_index.size() != queries ||
            pi.child_constraints.size() != constraints ||
            pi.fri_batch_coefficients.size() != width + 1 ||
            pi.evals_z1.size() != width + 1 ||
            pi.evals_z2.size() != width + 1 ||
            pi.column_len.size() != width + 1 ||
            pi.fold_challenges.size() != folds) {
            return false;
        }
        for (uint32_t item = 0; item < constraints; ++item) {
            const auto& a = pis[0].child_constraints[item];
            const auto& b = pi.child_constraints[item];
            if (a.kind != b.kind ||
                a.alg_degree != b.alg_degree ||
                std::string(a.name ? a.name : "") !=
                    std::string(b.name ? b.name : "")) {
                return false;
            }
        }
    }

    const ScalarLayout layout(width, folds, constraints);
    const uint32_t active_rows =
        TERMINAL_ROWS * queries;
    const uint32_t trace_rows =
        NextPow2(active_rows);
    if (trace_rows == 0) return false;
    cs = {};
    cs.n_rows = trace_rows;
    cs.n_columns = layout.end;
    cs.preprocessed_pin_ood = true;
    columns.assign(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
    std::vector<bool> preprocessed(
        cs.n_columns, false);
    auto mark =
        [&](uint32_t begin, uint32_t count) {
            for (uint32_t i = 0; i < count; ++i) {
                preprocessed[begin + i] = true;
            }
        };
    mark(layout.expected_current, width + 1);
    mark(layout.expected_next, width);
    mark(layout.expected_even, folds);
    mark(layout.expected_odd, folds);
    mark(layout.expected_eval_z1, width + 1);
    mark(layout.expected_eval_z2, width + 1);
    mark(layout.u_weight, width + 1);
    mark(layout.v1_weight, width + 1);
    mark(layout.v2_weight, width + 1);
    mark(layout.fold_x, folds);
    mark(layout.fold_beta, folds);
    mark(layout.fold_leaf_selector, folds);
    mark(layout.inverse_d1, 6);
    mark(layout.constraint_weight, constraints);
    mark(layout.terminal_value, TERMINAL_WORDS);
    mark(layout.parent_value, TERMINAL_WORDS);
    mark(layout.lane_selector, TERMINAL_ROWS);
    mark(layout.lane_end_selector, TERMINAL_ROWS);
    mark(layout.active, 1);

    const gf::Fp3 inv_two =
        gf::Inv(gf::Fp3::FromFp(gf::FromU64(2)));
    const gf::Fp3 coset_shift =
        gf::Fp3::FromFp(aq::kAirCosetShift);
    for (uint32_t row = 0; row < active_rows; ++row) {
        const uint32_t lane_index = row / queries;
        const uint32_t query_index = row % queries;
        const uint32_t logical =
            lane_index / kRCFri3AlgDualNumLanes;
        const uint32_t lane =
            lane_index % kRCFri3AlgDualNumLanes;
        const auto& pi = pis[lane_index];
        const auto& batch =
            children[logical].batch.repeated.lane[lane];
        if (query_index >= batch.queries.size()) {
            return false;
        }
        const auto& query = batch.queries[query_index];
        const size_t opening_index =
            static_cast<size_t>(lane) * queries +
            query_index;
        if (opening_index >=
                children[logical].next_openings.size() ||
            children[logical].next_openings[opening_index].
                    size() != 2 ||
            query.row.values.size() != width + 1 ||
            children[logical].
                    next_openings[opening_index][0].
                    values.size() != width + 1 ||
            query.steps.size() != folds) {
            return false;
        }
        const auto& next =
            children[logical].
                next_openings[opening_index][0].values;
        for (uint32_t item = 0; item <= width; ++item) {
            columns[layout.current + item][row] =
                query.row.values[item];
            columns[layout.expected_current + item][row] =
                query.row.values[item];
            columns[layout.eval_z1 + item][row] =
                pi.evals_z1[item];
            columns[layout.eval_z2 + item][row] =
                pi.evals_z2[item];
            columns[layout.expected_eval_z1 + item][row] =
                pi.evals_z1[item];
            columns[layout.expected_eval_z2 + item][row] =
                pi.evals_z2[item];
        }
        for (uint32_t item = 0; item < width; ++item) {
            columns[layout.next + item][row] =
                next[item];
            columns[layout.expected_next + item][row] =
                next[item];
        }

        const gf::Fp3 x = DomainPoint(
            pi.child_n_lde, query.index);
        gf::Fp3 v1 = gf::Fp3::Zero();
        gf::Fp3 v2 = gf::Fp3::Zero();
        for (uint32_t item = 0; item <= width; ++item) {
            if (pi.column_len[item] > pi.child_n_coeffs) {
                return false;
            }
            const uint32_t shift =
                pi.child_n_coeffs - pi.column_len[item];
            const gf::Fp3 ux =
                gf::Mul(
                    pi.fri_batch_coefficients[item],
                    PowFp3(x, shift));
            const gf::Fp3 z1 =
                gf::Mul(
                    pi.fri_batch_coefficients[item],
                    PowFp3(pi.z1, shift));
            const gf::Fp3 z2 =
                gf::Mul(
                    pi.fri_batch_coefficients[item],
                    PowFp3(pi.z2, shift));
            columns[layout.u_weight + item][row] = ux;
            columns[layout.v1_weight + item][row] = z1;
            columns[layout.v2_weight + item][row] = z2;
            v1 = gf::Add(
                v1, gf::Mul(z1, pi.evals_z1[item]));
            v2 = gf::Add(
                v2, gf::Mul(z2, pi.evals_z2[item]));
        }
        (void)v1;
        (void)v2;
        const gf::Fp3 d1 = gf::Sub(x, pi.z1);
        const gf::Fp3 d2 = gf::Sub(x, pi.z2);
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            return false;
        }
        columns[layout.inverse_d1][row] = gf::Inv(d1);
        columns[layout.inverse_d2][row] = gf::Inv(d2);
        columns[layout.deep_weight1][row] = pi.w1;
        columns[layout.deep_weight2][row] = pi.w2;
        columns[layout.final_value][row] = pi.final_value;

        uint32_t reduced = query.index;
        for (uint32_t layer = 0; layer < folds; ++layer) {
            const auto& step = query.steps[layer];
            const uint32_t n_leaves =
                pi.child_n_lde >> layer;
            const uint32_t half = n_leaves / 2;
            if (half == 0) return false;
            const gf::Fp3 fold_x =
                DomainPoint(n_leaves, step.even_index);
            const gf::Fp3 beta =
                pi.fold_challenges[layer];
            columns[layout.fold_even + layer][row] =
                step.even;
            columns[layout.fold_odd + layer][row] =
                step.odd;
            columns[layout.expected_even + layer][row] =
                step.even;
            columns[layout.expected_odd + layer][row] =
                step.odd;
            columns[layout.fold_x + layer][row] =
                fold_x;
            columns[layout.fold_beta + layer][row] =
                beta;
            columns[
                layout.fold_leaf_selector + layer][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    reduced < half));
            const gf::Fp3 even_part =
                gf::Mul(
                    gf::Add(step.even, step.odd),
                    inv_two);
            const gf::Fp3 odd_part =
                gf::Mul(
                    gf::Sub(step.even, step.odd),
                    gf::Mul(inv_two, gf::Inv(fold_x)));
            columns[layout.folded + layer][row] =
                gf::Add(
                    even_part,
                    gf::Mul(beta, odd_part));
            reduced %= half;
        }

        const gf::Fp3 y = gf::Mul(coset_shift, x);
        const gf::Fp3 zh = gf::Sub(
            PowFp3(y, pi.child_n_rows),
            gf::Fp3::One());
        const gf::Fp3 h_last = DomainPoint(
            pi.child_n_rows, pi.child_n_rows - 1);
        const gf::Fp3 first_den =
            gf::Sub(y, gf::Fp3::One());
        const gf::Fp3 last_den =
            gf::Sub(y, h_last);
        if (gf::IsZero(first_den) ||
            gf::IsZero(last_den)) {
            return false;
        }
        const std::array<gf::Fp3, 4> selectors{
            gf::Fp3::One(),
            gf::Sub(y, h_last),
            gf::Mul(zh, gf::Inv(first_den)),
            gf::Mul(zh, gf::Inv(last_den))};
        columns[layout.zh][row] = zh;
        gf::Fp3 lambda_power = gf::Fp3::One();
        for (uint32_t item = 0;
             item < constraints; ++item) {
            const auto& constraint =
                pi.child_constraints[item];
            uint32_t selector_index = 0;
            if (constraint.kind == aq::AirKind::kTransition) {
                selector_index = 1;
            } else if (
                constraint.kind == aq::AirKind::kFirstRow) {
                selector_index = 2;
            } else if (
                constraint.kind == aq::AirKind::kLastRow) {
                selector_index = 3;
            }
            columns[
                layout.constraint_weight + item][row] =
                gf::Mul(
                    lambda_power,
                    selectors[selector_index]);
            lambda_power =
                gf::Mul(lambda_power, pi.air_lambda);
        }
        for (uint32_t word = 0;
             word < TERMINAL_WORDS; ++word) {
            columns[layout.terminal_value + word][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    terminal_words[lane_index][word]));
            columns[layout.parent_value + word][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    parent_words[word]));
        }
        columns[layout.lane_selector + lane_index][row] =
            gf::Fp3::One();
        if (query_index + 1 == queries) {
            columns[
                layout.lane_end_selector +
                lane_index][row] = gf::Fp3::One();
        }
        columns[layout.active][row] = gf::Fp3::One();

        gf::Fp3 deep_u = gf::Fp3::Zero();
        gf::Fp3 deep_v1 = gf::Fp3::Zero();
        gf::Fp3 deep_v2 = gf::Fp3::Zero();
        for (uint32_t item = 0; item <= width; ++item) {
            deep_u = gf::Add(
                deep_u, gf::Mul(
                    columns[layout.u_weight + item][row],
                    columns[layout.current + item][row]));
            deep_v1 = gf::Add(
                deep_v1, gf::Mul(
                    columns[layout.v1_weight + item][row],
                    columns[layout.eval_z1 + item][row]));
            deep_v2 = gf::Add(
                deep_v2, gf::Mul(
                    columns[layout.v2_weight + item][row],
                    columns[layout.eval_z2 + item][row]));
        }
        columns[layout.deep_u][row] = deep_u;
        columns[layout.deep_v1][row] = deep_v1;
        columns[layout.deep_v2][row] = deep_v2;
        columns[layout.deep_term1][row] = gf::Mul(
            gf::Sub(deep_u, deep_v1),
            columns[layout.inverse_d1][row]);
        columns[layout.deep_term2][row] = gf::Mul(
            gf::Sub(deep_u, deep_v2),
            columns[layout.inverse_d2][row]);
        const gf::Fp3 leaf_selector =
            columns[layout.fold_leaf_selector][row];
        columns[layout.deep_leaf][row] = gf::Add(
            gf::Mul(
                leaf_selector,
                columns[layout.fold_even][row]),
            gf::Mul(
                gf::Sub(gf::Fp3::One(), leaf_selector),
                columns[layout.fold_odd][row]));
        std::vector<gf::Fp3> current_values(width);
        std::vector<gf::Fp3> next_values(width);
        for (uint32_t item = 0; item < width; ++item) {
            current_values[item] =
                columns[layout.current + item][row];
            next_values[item] =
                columns[layout.next + item][row];
        }
        for (uint32_t item = 0; item < constraints; ++item) {
            columns[layout.constraint_eval + item][row] =
                pis[0].child_constraints[item].eval(
                    current_values, next_values);
        }
    }

    for (uint32_t column = 0;
         column < cs.n_columns; ++column) {
        if (preprocessed[column]) {
            AddPreprocessed(cs, column, columns[column]);
        }
    }

    auto bind =
        [&](uint32_t witness, uint32_t expected,
            uint32_t count, const char* name) {
            for (uint32_t item = 0; item < count; ++item) {
                AddConstraint(
                    cs, name, aq::AirKind::kEverywhere, 1,
                    [witness, expected, item](
                        const std::vector<gf::Fp3>& cur,
                        const std::vector<gf::Fp3>&) {
                        return gf::Sub(
                            cur[witness + item],
                            cur[expected + item]);
                    });
            }
        };
    bind(
        layout.current, layout.expected_current,
        width + 1, "stage3.bank_narrow.scalar.current_pin");
    bind(
        layout.next, layout.expected_next,
        width, "stage3.bank_narrow.scalar.next_pin");
    bind(
        layout.fold_even, layout.expected_even,
        folds, "stage3.bank_narrow.scalar.even_pin");
    bind(
        layout.fold_odd, layout.expected_odd,
        folds, "stage3.bank_narrow.scalar.odd_pin");
    bind(
        layout.eval_z1, layout.expected_eval_z1,
        width + 1, "stage3.bank_narrow.scalar.eval_z1_pin");
    bind(
        layout.eval_z2, layout.expected_eval_z2,
        width + 1, "stage3.bank_narrow.scalar.eval_z2_pin");

    for (uint32_t layer = 0; layer < folds; ++layer) {
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.fold_equation",
            aq::AirKind::kEverywhere, 2,
            [layout, layer](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                const gf::Fp3 x =
                    cur[layout.fold_x + layer];
                const gf::Fp3 even =
                    cur[layout.fold_even + layer];
                const gf::Fp3 odd =
                    cur[layout.fold_odd + layer];
                const gf::Fp3 lhs = gf::Mul(
                    gf::Mul(
                        gf::Fp3::FromFp(gf::FromU64(2)),
                        x),
                    cur[layout.folded + layer]);
                const gf::Fp3 rhs = gf::Add(
                    gf::Mul(x, gf::Add(even, odd)),
                    gf::Mul(
                        cur[layout.fold_beta + layer],
                        gf::Sub(even, odd)));
                return gf::Sub(lhs, rhs);
            });
    }
    for (uint32_t layer = 1; layer < folds; ++layer) {
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.deep_chain",
            aq::AirKind::kEverywhere, 2,
            [layout, layer](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                const gf::Fp3 selector =
                    cur[layout.fold_leaf_selector + layer];
                const gf::Fp3 leaf = gf::Add(
                    gf::Mul(
                        selector,
                        cur[layout.fold_even + layer]),
                    gf::Mul(
                        gf::Sub(
                            gf::Fp3::One(), selector),
                        cur[layout.fold_odd + layer]));
                return gf::Sub(
                    cur[layout.folded + layer - 1],
                    leaf);
            });
    }
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.deep_final",
        aq::AirKind::kEverywhere, 1,
        [layout, folds](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[layout.folded + folds - 1],
                cur[layout.final_value]);
        });
    auto add_deep_sum =
        [&](const char* name, uint32_t target,
            uint32_t weights, uint32_t values) {
        AddConstraint(
            cs, name, aq::AirKind::kEverywhere, 2,
            [target, weights, values, width](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                gf::Fp3 sum = gf::Fp3::Zero();
                for (uint32_t item = 0; item <= width; ++item) {
                    sum = gf::Add(
                        sum, gf::Mul(
                            cur[weights + item],
                            cur[values + item]));
                }
                return gf::Sub(cur[target], sum);
            });
    };
    add_deep_sum(
        "stage3.bank_narrow.scalar.deep_u",
        layout.deep_u, layout.u_weight, layout.current);
    add_deep_sum(
        "stage3.bank_narrow.scalar.deep_v1",
        layout.deep_v1, layout.v1_weight, layout.eval_z1);
    add_deep_sum(
        "stage3.bank_narrow.scalar.deep_v2",
        layout.deep_v2, layout.v2_weight, layout.eval_z2);
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.deep_term1",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[layout.deep_term1],
                gf::Mul(
                    gf::Sub(
                        cur[layout.deep_u],
                        cur[layout.deep_v1]),
                    cur[layout.inverse_d1]));
        });
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.deep_term2",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[layout.deep_term2],
                gf::Mul(
                    gf::Sub(
                        cur[layout.deep_u],
                        cur[layout.deep_v2]),
                    cur[layout.inverse_d2]));
        });
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.deep_leaf",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            const gf::Fp3 selector =
                cur[layout.fold_leaf_selector];
            return gf::Sub(
                cur[layout.deep_leaf],
                gf::Add(
                    gf::Mul(
                        selector, cur[layout.fold_even]),
                    gf::Mul(
                        gf::Sub(gf::Fp3::One(), selector),
                        cur[layout.fold_odd])));
        });
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.deep_identity",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[layout.deep_leaf],
                gf::Add(
                    gf::Mul(
                        cur[layout.deep_weight1],
                        cur[layout.deep_term1]),
                    gf::Mul(
                        cur[layout.deep_weight2],
                        cur[layout.deep_term2])));
        });

    for (uint32_t item = 0;
         item < pis[0].child_constraints.size(); ++item) {
        const auto child_constraint =
            pis[0].child_constraints[item];
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.constraint_eval",
            aq::AirKind::kEverywhere,
            child_constraint.alg_degree,
            [layout, width, item, child_constraint](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                std::vector<gf::Fp3> current(width);
                std::vector<gf::Fp3> next(width);
                for (uint32_t column = 0;
                     column < width; ++column) {
                    current[column] =
                        cur[layout.current + column];
                    next[column] =
                        cur[layout.next + column];
                }
                return gf::Sub(
                    cur[layout.constraint_eval + item],
                    child_constraint.eval(current, next));
            });
    }
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.per_point",
        aq::AirKind::kEverywhere, 2,
        [layout, constraints, width](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            gf::Fp3 composition = gf::Fp3::Zero();
            for (uint32_t item = 0;
                 item < constraints; ++item) {
                composition = gf::Add(
                    composition,
                    gf::Mul(
                        cur[layout.constraint_weight + item],
                        cur[layout.constraint_eval + item]));
            }
            return gf::Sub(
                composition,
                gf::Mul(
                    cur[layout.current + width],
                    cur[layout.zh]));
        });

    for (uint32_t word = 0;
         word < TERMINAL_WORDS; ++word) {
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.terminal_z1",
            aq::AirKind::kEverywhere, 2,
            [layout, terminal_base, word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        cur[layout.terminal_value + word],
                        cur[
                            layout.eval_z1 +
                            terminal_base + word]));
            });
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.terminal_z2",
            aq::AirKind::kEverywhere, 2,
            [layout, terminal_base, word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        cur[layout.terminal_value + word],
                        cur[
                            layout.eval_z2 +
                            terminal_base + word]));
            });
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.lane_equality",
            aq::AirKind::kTransition, 2,
            [layout, word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>& next) {
                const gf::Fp3 selector = gf::Add(
                    cur[layout.lane_end_selector],
                    cur[
                        layout.lane_end_selector + 2]);
                return gf::Mul(
                    selector,
                    gf::Sub(
                        cur[layout.terminal_value + word],
                        next[layout.terminal_value + word]));
            });
    }
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.contiguous",
        aq::AirKind::kTransition, 2,
        [layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                cur[layout.lane_end_selector + 1],
                gf::Sub(
                    gf::Add(
                        cur[layout.terminal_value],
                        cur[layout.terminal_value + 1]),
                    next[layout.terminal_value]));
        });
    for (uint32_t word = 0; word < 8; ++word) {
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.sha_chain",
            aq::AirKind::kTransition, 2,
            [layout, word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>& next) {
                return gf::Mul(
                    cur[layout.lane_end_selector + 1],
                    gf::Sub(
                        cur[
                            layout.terminal_value + 10 +
                            word],
                        next[
                            layout.terminal_value + 2 +
                            word]));
            });
    }
    for (uint32_t word = 0; word < 10; ++word) {
        if (word == 1) continue;
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.parent_prefix",
            aq::AirKind::kEverywhere, 2,
            [layout, word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[layout.lane_selector],
                    gf::Sub(
                        cur[layout.parent_value + word],
                        cur[layout.terminal_value + word]));
            });
    }
    AddConstraint(
        cs, "stage3.bank_narrow.scalar.parent_count",
        aq::AirKind::kTransition, 2,
        [layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                cur[layout.lane_end_selector + 1],
                gf::Sub(
                    cur[layout.parent_value + 1],
                    gf::Add(
                        cur[layout.terminal_value + 1],
                        next[layout.terminal_value + 1])));
        });
    for (uint32_t word = 0; word < 8; ++word) {
        AddConstraint(
            cs, "stage3.bank_narrow.scalar.parent_suffix",
            aq::AirKind::kEverywhere, 2,
            [layout, word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[layout.lane_selector + 2],
                    gf::Sub(
                        cur[
                            layout.parent_value + 10 +
                            word],
                        cur[
                            layout.terminal_value + 10 +
                            word]));
            });
    }
    return true;
}

struct SemanticCell {
    uint32_t family{0};
    uint32_t lane{0};
    uint32_t item{0};
    uint32_t coordinate{0};
    uint32_t consumer{0};
    gf::Fp value{0};
};

gf::Fp Coordinate(
    const gf::Fp3& value,
    uint32_t coordinate)
{
    if (coordinate == 0) return gf::Canonical(value.c0);
    if (coordinate == 1) return gf::Canonical(value.c1);
    return gf::Canonical(value.c2);
}

bool BuildV5SemanticBoundary(
    const std::array<ar::ChildPublicInputs, TERMINAL_ROWS>& pis,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t& logical_cells,
    uint256& commitment)
{
    std::vector<SemanticCell> cells;
    auto append_fp3 =
        [&](uint32_t family, uint32_t lane,
            uint32_t item, uint32_t consumer,
            const gf::Fp3& value) {
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                cells.push_back({
                    family, lane, item, coordinate,
                    consumer,
                    Coordinate(value, coordinate)});
            }
        };
    for (uint32_t lane = 0;
         lane < TERMINAL_ROWS; ++lane) {
        const auto& pi = pis[lane];
        append_fp3(1, lane, 0, 1, pi.air_lambda);
        for (uint32_t item = 0;
             item < pi.fri_batch_coefficients.size(); ++item) {
            append_fp3(
                2, lane, item, 2,
                pi.fri_batch_coefficients[item]);
        }
        append_fp3(3, lane, 0, 3, pi.z1);
        append_fp3(3, lane, 1, 3, pi.z2);
        append_fp3(4, lane, 0, 2, pi.w1);
        append_fp3(4, lane, 1, 2, pi.w2);
        for (uint32_t item = 0;
             item < pi.fold_challenges.size(); ++item) {
            append_fp3(
                5, lane, item, 4,
                pi.fold_challenges[item]);
        }
        for (uint32_t item = 0;
             item < pi.query_index.size(); ++item) {
            cells.push_back({
                6, lane, item, 0, 5,
                gf::FromU64(pi.query_index[item])});
        }
    }
    logical_cells =
        static_cast<uint32_t>(cells.size());
    const uint32_t rows = NextPow2(logical_cells);
    if (logical_cells == 0 || rows == 0) return false;
    cs = {};
    cs.n_rows = rows;
    cs.n_columns = 8;
    cs.preprocessed_pin_ood = true;
    columns.assign(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
    HashWriter hash;
    hash << "BTX_RC_STAGE3_BANK_NARROW_V5_SHA_BOUNDARY_V1";
    hash << logical_cells;
    for (uint32_t row = 0; row < logical_cells; ++row) {
        const auto& cell = cells[row];
        const std::array<uint64_t, 7> fixed{
            1, cell.value, cell.family, cell.lane,
            cell.item, cell.coordinate, cell.consumer};
        for (uint32_t column = 0;
             column < fixed.size(); ++column) {
            columns[column][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(fixed[column]));
        }
        columns[7][row] =
            gf::Fp3::FromFp(cell.value);
        hash << row << cell.family << cell.lane;
        hash << cell.item << cell.coordinate;
        hash << cell.consumer;
        hash << gf::Canonical(cell.value);
    }
    commitment = hash.GetHash();
    if (commitment.IsNull()) return false;
    for (uint32_t column = 0; column < 7; ++column) {
        AddPreprocessed(cs, column, columns[column]);
    }
    AddConstraint(
        cs, "stage3.bank_narrow.v5_sha_semantic_boundary",
        aq::AirKind::kEverywhere, 2,
        [](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0], gf::Sub(cur[7], cur[1]));
        });
    return true;
}

} // namespace

RCStage3CoupledBankNarrowExecution
BuildRCStage3CoupledBankNarrowExecution(
    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ar::DualAlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    const std::vector<uint32_t>& child_output_column_bases)
{
    RCStage3CoupledBankNarrowExecution out;
    if (child_css.size() != 2 ||
        children.size() != 2 ||
        child_fs_seeds.size() != 2 ||
        child_output_column_bases.size() != 2 ||
        child_output_column_bases[0] !=
            child_output_column_bases[1] ||
        child_fs_seeds[0].IsNull() ||
        child_fs_seeds[1].IsNull() ||
        child_fs_seeds[0] == child_fs_seeds[1]) {
        out.note =
            "stage3:coupled_bank_narrow:binary_shape_or_seed";
        return out;
    }

    std::array<
        std::array<uint32_t, TERMINAL_WORDS>,
        TERMINAL_ROWS> lane_words{};
    std::array<
        ar::ChildPublicInputs,
        TERMINAL_ROWS> lane_pis{};
    out.lanes.reserve(TERMINAL_ROWS);
    out.child_proof_commitments.reserve(2);
    for (uint32_t logical = 0; logical < 2; ++logical) {
        const uint256 commitment =
            ar::ComputeDualV5AirProofCommitment(
                children[logical]);
        if (commitment.IsNull()) {
            out.note =
                "stage3:coupled_bank_narrow:proof_commitment";
            return out;
        }
        out.child_proof_commitments.push_back(commitment);
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            fp::FoldBusComposition composition =
                fp::BuildDualV5FoldBusComposition(
                    child_css[logical],
                    children[logical],
                    child_fs_seeds[logical],
                    lane);
            RCStage3CoupledBankNarrowLane measured;
            measured.logical_child = logical;
            measured.ordered_v5_lane = lane;
            measured.active_hash_rows =
                composition.hash.program.active_rows;
            measured.trace_rows =
                composition.combined.n_rows;
            measured.hash_columns =
                fp::CanonicalHashOpeningLayout().End();
            measured.fold_bus_columns =
                composition.combined.n_columns;
            measured.constraints =
                static_cast<uint32_t>(
                    composition.combined.constraints.size());
            measured.fold_pairs = composition.fold_pairs;
            measured.violations = composition.violations;
            measured.dual_envelope_accepted =
                composition.hash.native_child_accepted;
            measured.current_row_opening =
                composition.hash.program.current_row_opening;
            measured.next_row_opening =
                composition.hash.program.next_row_opening;
            measured.trace_binding_opening =
                composition.hash.program.trace_root_opening;
            measured.every_fold_opening =
                composition.hash.program.every_fold_opening;
            measured.fold_hash_scalar_join =
                composition.direct_hash_alias &&
                composition.dual_logup_terminal &&
                composition.fold_equations;
            measured.valid = composition.valid;
            if (!measured.valid ||
                !ExtractTerminalWords(
                    composition.hash.program.public_inputs,
                    child_output_column_bases[logical],
                    lane_words[
                        logical *
                            kRCFri3AlgDualNumLanes +
                        lane])) {
                out.note =
                    composition.valid
                        ? "stage3:coupled_bank_narrow:terminal_extract"
                        : composition.note;
                return out;
            }
            lane_pis[
                logical * kRCFri3AlgDualNumLanes +
                lane] =
                composition.hash.program.public_inputs;
            out.scheduled_hash_rows += measured.trace_rows;
            out.scheduled_hash_active_rows +=
                measured.active_hash_rows;
            out.reusable_hash_columns = std::max(
                out.reusable_hash_columns,
                measured.hash_columns);
            out.reusable_fold_bus_columns = std::max(
                out.reusable_fold_bus_columns,
                measured.fold_bus_columns);
            out.lanes.push_back(measured);
        }
    }

    if (!BuildTerminalRelation(
            lane_words, out.terminal_cs,
            out.terminal_columns,
            out.parent_output_words)) {
        out.note =
            "stage3:coupled_bank_narrow:terminal_relation";
        return out;
    }
    out.terminal_violations =
        ar::CountWitnessViolationsOnH(
            out.terminal_cs, out.terminal_columns);
    out.terminal_bus_columns = out.terminal_cs.n_columns;
    if (!BuildScalarRelation(
            lane_pis, children, lane_words,
            out.parent_output_words,
            child_output_column_bases[0],
            out.scalar_cs, out.scalar_columns)) {
        out.note =
            "stage3:coupled_bank_narrow:scalar_relation";
        return out;
    }
    out.scalar_rows = out.scalar_cs.n_rows;
    out.scalar_columns_count = out.scalar_cs.n_columns;
    out.scalar_constraints =
        static_cast<uint32_t>(
            out.scalar_cs.constraints.size());
    {
        const ScalarLayout scalar_layout(
            lane_pis[0].child_w,
            lane_pis[0].n_folds,
            static_cast<uint32_t>(
                lane_pis[0].child_constraints.size()));
        out.scalar_eval_z1_column_base =
            scalar_layout.eval_z1;
        out.scalar_eval_z2_column_base =
            scalar_layout.eval_z2;
        out.scalar_terminal_column_base =
            scalar_layout.terminal_value;
        out.scalar_parent_column_base =
            scalar_layout.parent_value;
    }
    out.scalar_violations =
        ar::CountWitnessViolationsOnH(
            out.scalar_cs, out.scalar_columns);
    if (!BuildV5SemanticBoundary(
            lane_pis, out.v5_semantic_cs,
            out.v5_semantic_columns,
            out.v5_semantic_cells,
            out.v5_sha_boundary_commitment)) {
        out.note =
            "stage3:coupled_bank_narrow:v5_semantic";
        return out;
    }
    out.v5_semantic_rows = out.v5_semantic_cs.n_rows;
    out.v5_semantic_columns_count =
        out.v5_semantic_cs.n_columns;
    out.v5_semantic_violations =
        ar::CountWitnessViolationsOnH(
            out.v5_semantic_cs,
            out.v5_semantic_columns);
    out.combined_active_rows =
        out.scheduled_hash_active_rows +
        out.scalar_rows +
        out.v5_semantic_cells;
    out.combined_trace_rows =
        NextPow2(out.combined_active_rows);
    if (out.combined_trace_rows == 0) {
        out.note =
            "stage3:coupled_bank_narrow:combined_schedule";
        return out;
    }
    out.physical_column_target = std::max(
        out.reusable_fold_bus_columns,
        std::max(
            out.terminal_bus_columns,
            std::max(
                out.scalar_columns_count,
                out.v5_semantic_columns_count)));

    const fp::CompleteFixedPointScenario selected =
        fp::SelectCompleteFixedPointV1();
    out.selected_full_parent_width =
        selected.leaf.parent_width;
    if (out.selected_full_parent_width >=
        out.physical_column_target) {
        out.unexecuted_family_column_reservation =
            out.selected_full_parent_width -
            out.physical_column_target;
    }

    out.four_ordered_lanes_executed =
        out.lanes.size() == TERMINAL_ROWS &&
        std::all_of(
            out.lanes.begin(), out.lanes.end(),
            [](const auto& lane) {
                return lane.valid;
            });
    out.exact_dual_transcripts_checked =
        out.four_ordered_lanes_executed;
    out.hash_families_complete =
        out.four_ordered_lanes_executed &&
        std::all_of(
            out.lanes.begin(), out.lanes.end(),
            [](const auto& lane) {
                return lane.current_row_opening &&
                    lane.next_row_opening &&
                    lane.trace_binding_opening &&
                    lane.every_fold_opening;
            });
    out.fold_scalar_bus_complete =
        out.four_ordered_lanes_executed &&
        std::all_of(
            out.lanes.begin(), out.lanes.end(),
            [](const auto& lane) {
                return lane.fold_hash_scalar_join;
            });
    out.terminal_relation_executable =
        out.terminal_violations == 0;
    out.terminal_values_proof_derived = true;
    out.deep_dual_ood_executable =
        out.scalar_violations == 0 &&
        out.scalar_rows != 0 &&
        out.scalar_columns_count != 0;
    out.per_point_quotient_executable =
        out.deep_dual_ood_executable;
    out.scalar_openings_proof_derived =
        out.deep_dual_ood_executable;
    out.scalar_terminal_same_trace =
        out.deep_dual_ood_executable;
    out.v5_sha_semantic_boundary_executable =
        out.v5_semantic_violations == 0 &&
        out.v5_semantic_columns_count == 8 &&
        !out.v5_sha_boundary_commitment.IsNull();
    out.all_v5_consumer_cells_mapped =
        out.v5_sha_semantic_boundary_executable &&
        out.v5_semantic_cells != 0;
    out.vertical_width_under_cap =
        out.physical_column_target <
        kRCFri3AlgBatchMaxColumns;
    out.selected_full_width_under_cap =
        selected.selected_v1_topology &&
        selected.backend_shape_supported &&
        out.selected_full_parent_width <
            kRCFri3AlgBatchMaxColumns;
    out.combined_trace_within_selected =
        selected.selected_v1_topology &&
        out.combined_trace_rows <=
            selected.leaf.trace_rows;
    out.hash_terminal_single_parent_proof = false;
    out.complete_recursive_parent = false;
    out.parent_proof_emitted = false;
    out.consensus_authority = false;
    out.valid =
        out.four_ordered_lanes_executed &&
        out.hash_families_complete &&
        out.fold_scalar_bus_complete &&
        out.terminal_relation_executable &&
        out.terminal_values_proof_derived &&
        out.deep_dual_ood_executable &&
        out.per_point_quotient_executable &&
        out.scalar_openings_proof_derived &&
        out.scalar_terminal_same_trace &&
        out.v5_sha_semantic_boundary_executable &&
        out.all_v5_consumer_cells_mapped &&
        out.vertical_width_under_cap &&
        out.selected_full_width_under_cap &&
        out.combined_trace_within_selected;
    out.note =
        out.valid
            ? "stage3:coupled_bank_narrow:four_lane_hash_fold_"
              "deep_perpoint_terminal_v5_boundary_executable_"
              "parent_proof_open"
            : "stage3:coupled_bank_narrow:execution_incomplete";
    return out;
}

namespace {

struct UnifiedSegment {
    uint32_t begin{0};
    uint32_t rows{0};
    uint32_t selector_base{0};
};

uint32_t SegmentMask(
    const UnifiedSegment& segment,
    aq::AirKind kind)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return segment.selector_base;
    case aq::AirKind::kTransition:
        return segment.selector_base + 1;
    case aq::AirKind::kFirstRow:
        return segment.selector_base + 2;
    case aq::AirKind::kLastRow:
        return segment.selector_base + 3;
    }
    return segment.selector_base;
}

void AddUnifiedGatedConstraint(
    aq::AirConstraintSystem<gf::Fp3>& parent,
    const aq::AirConstraint<gf::Fp3>& source,
    uint32_t mask)
{
    aq::AirConstraint<gf::Fp3> constraint;
    constraint.name = source.name;
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = source.alg_degree + 1;
    constraint.eval =
        [source, mask](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>& next) {
            if (gf::IsZero(cur[mask])) {
                return gf::Fp3::Zero();
            }
            return gf::Mul(
                cur[mask], source.eval(cur, next));
        };
    parent.constraints.push_back(std::move(constraint));
}

bool CopyUnifiedPhase(
    const aq::AirConstraintSystem<gf::Fp3>& phase_cs,
    const std::vector<std::vector<gf::Fp3>>& phase_columns,
    uint32_t active_rows,
    const UnifiedSegment& segment,
    uint32_t fixed_base,
    uint32_t fixed_columns,
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    uint32_t copy_column_begin = 0,
    uint32_t fixed_slot_begin = 0)
{
    if (active_rows != segment.rows ||
        phase_cs.n_columns > parent_cs.n_columns ||
        phase_columns.size() != phase_cs.n_columns ||
        fixed_slot_begin > fixed_columns ||
        phase_cs.preprocessed.size() >
            fixed_columns - fixed_slot_begin ||
        copy_column_begin > phase_cs.n_columns ||
        segment.begin > parent_cs.n_rows ||
        active_rows > parent_cs.n_rows - segment.begin) {
        return false;
    }
    for (uint32_t column = copy_column_begin;
         column < phase_cs.n_columns; ++column) {
        if (phase_columns[column].size() < active_rows) {
            return false;
        }
        std::copy_n(
            phase_columns[column].begin(), active_rows,
            parent_columns[column].begin() +
                segment.begin);
    }
    for (uint32_t fixed = 0;
         fixed < phase_cs.preprocessed.size(); ++fixed) {
        const auto& [local_column, values] =
            phase_cs.preprocessed[fixed];
        if (local_column >= phase_cs.n_columns ||
            values.size() < active_rows) {
            return false;
        }
        const uint32_t public_column =
            fixed_base + fixed_slot_begin + fixed;
        std::copy_n(
            values.begin(), active_rows,
            parent_columns[public_column].begin() +
                segment.begin);
        AddConstraint(
            parent_cs,
            "stage3.bank_unified.fixed_column_pin",
            aq::AirKind::kEverywhere, 2,
            [local_column, public_column,
             mask = segment.selector_base](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[mask],
                    gf::Sub(
                        cur[local_column],
                        cur[public_column]));
            });
    }
    return true;
}

void FillUnifiedSegmentMasks(
    const UnifiedSegment& segment,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    if (segment.rows == 0) return;
    for (uint32_t row = 0; row < segment.rows; ++row) {
        const uint32_t target = segment.begin + row;
        columns[segment.selector_base][target] =
            gf::Fp3::One();
        if (row + 1 < segment.rows) {
            columns[segment.selector_base + 1][target] =
                gf::Fp3::One();
        }
    }
    columns[segment.selector_base + 2][segment.begin] =
        gf::Fp3::One();
    columns[segment.selector_base + 3]
           [segment.begin + segment.rows - 1] =
        gf::Fp3::One();
}

} // namespace

RCStage3CoupledBankStreamingLdePlan
PlanRCStage3CoupledBankStreamingLde(
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t lde_rows,
    uint32_t tile_rows)
{
    RCStage3CoupledBankStreamingLdePlan out;
    out.trace_rows = trace_rows;
    out.trace_columns = trace_columns;
    out.lde_rows = lde_rows;
    out.tile_rows = tile_rows;
    if (trace_rows == 0 || trace_columns == 0 ||
        lde_rows == 0 || tile_rows == 0 ||
        (trace_rows & (trace_rows - 1)) != 0 ||
        (lde_rows & (lde_rows - 1)) != 0 ||
        (tile_rows & (tile_rows - 1)) != 0 ||
        tile_rows > lde_rows) {
        out.note =
            "stage3:coupled_bank_streaming_lde:shape";
        return out;
    }
    const uint64_t committed_columns =
        uint64_t{trace_columns} + 1;
    if (committed_columns >
            UINT64_MAX / lde_rows) {
        out.note =
            "stage3:coupled_bank_streaming_lde:overflow";
        return out;
    }
    out.dense_lde_cells =
        committed_columns * lde_rows;

    // A row-wise commitment cannot be generated one column at a time: every
    // leaf contains all trace values.  The safe schedule is therefore:
    // (1) per-column interpolation/LDE into an external column store,
    // (2) trace row-root pass, (3) quotient row-tile pass after lambda,
    // (4) combined row-root/FRI fold pass, (5) query-path replay.  Two row
    // tiles hold current and next values; four scalar tiles cover quotient
    // accumulators, selectors and fold scratch.
    const uint64_t row_tile_cells =
        (2 * committed_columns + 4) * tile_rows;
    const uint64_t ntt_scratch_cells =
        uint64_t{2} * lde_rows;
    out.peak_live_cells =
        std::max(row_tile_cells, ntt_scratch_cells);
    out.external_work_cells =
        out.dense_lde_cells <= UINT64_MAX / 3
            ? 3 * out.dense_lde_cells
            : UINT64_MAX;
    out.passes = 5;
    out.column_store_required = true;
    out.two_pass_row_merkle_required = true;
    out.quotient_row_tiles_executable = false;
    out.fri_fold_tiles_executable = false;
    out.transcript_equivalence_proven = false;
    out.under_dense_cell_screen =
        out.peak_live_cells <= (uint64_t{1} << 28);
    out.valid = out.under_dense_cell_screen;
    out.note =
        "stage3:coupled_bank_streaming_lde:planner_only_"
        "backend_callbacks_and_root_equivalence_pending";
    return out;
}

RCStage3CoupledBankUnifiedParent
BuildRCStage3CoupledBankUnifiedParent(
    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ar::DualAlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    const std::vector<uint32_t>& child_output_column_bases)
{
    RCStage3CoupledBankUnifiedParent out;
    RCStage3CoupledBankNarrowExecution narrow =
        BuildRCStage3CoupledBankNarrowExecution(
            child_css, children, child_fs_seeds,
            child_output_column_bases);
    if (!narrow.valid || narrow.lanes.size() != 4) {
        out.note =
            "stage3:coupled_bank_unified:narrow:" +
            narrow.note;
        return out;
    }

    std::array<fp::FoldBusComposition, 4> hashes;
    hashes[0] =
        fp::BuildDualV5FoldBusComposition(
            child_css[0], children[0],
            child_fs_seeds[0], 0);
    if (!hashes[0].valid) {
        out.note =
            "stage3:coupled_bank_unified:first_hash:" +
            hashes[0].note;
        return out;
    }
    const uint32_t horizontal_lane_base =
        hashes[0].combined.n_columns;
    for (uint32_t lane_index = 1;
         lane_index < 4; ++lane_index) {
        const uint32_t logical =
            lane_index / kRCFri3AlgDualNumLanes;
        const uint32_t lane =
            lane_index % kRCFri3AlgDualNumLanes;
        hashes[lane_index] =
            fp::BuildDualV5FoldBusCompositionAtBase(
                child_css[logical], children[logical],
                child_fs_seeds[logical], lane,
                (lane_index & 1u)
                    ? horizontal_lane_base : 0);
        if (!hashes[lane_index].valid) {
            out.note =
                "stage3:coupled_bank_unified:packed_hash";
            return out;
        }
    }
    std::array<
        aq::AirConstraintSystem<gf::Fp3>, 2>
        canonical_hash_cs;
    std::string why;
    if (!fp::BuildHashOpeningConstraintSystem(
            hashes[0].hash.program,
            canonical_hash_cs[0], &why, 0) ||
        !fp::BuildHashOpeningConstraintSystem(
            hashes[1].hash.program,
            canonical_hash_cs[1], &why,
            horizontal_lane_base)) {
        out.note =
            "stage3:coupled_bank_unified:hash_cs:" + why;
        return out;
    }

    constexpr uint32_t SEGMENTS = 5;
    constexpr uint32_t MASKS_PER_SEGMENT = 4;
    constexpr uint32_t AGGREGATE_MASKS = 4;
    out.local_phase_columns =
        std::max(
            narrow.physical_column_target,
            hashes[1].combined.n_columns);
    out.fixed_columns =
        static_cast<uint32_t>(std::max({
            narrow.scalar_cs.preprocessed.size(),
            narrow.v5_semantic_cs.preprocessed.size(),
            narrow.terminal_cs.preprocessed.size(),
            2 * hashes[0].combined.preprocessed.size()}));
    out.selector_columns =
        SEGMENTS * MASKS_PER_SEGMENT +
        AGGREGATE_MASKS;
    out.carry_columns = TERMINAL_WORDS;
    const uint32_t fixed_base =
        out.local_phase_columns;
    const uint32_t selector_base =
        fixed_base + out.fixed_columns;
    const uint32_t aggregate_selector_base =
        selector_base +
        SEGMENTS * MASKS_PER_SEGMENT;
    const uint32_t carry_base =
        aggregate_selector_base +
        AGGREGATE_MASKS;
    out.parent_columns_count =
        carry_base + out.carry_columns;
    if (out.parent_columns_count >
            narrow.selected_full_parent_width) {
        out.note =
            "stage3:coupled_bank_unified:shape_cap";
        return out;
    }

    std::array<UnifiedSegment, SEGMENTS> segments{};
    uint32_t cursor = 0;
    for (uint32_t wave = 0; wave < 2; ++wave) {
        segments[wave] = {
            cursor,
            std::max(
                narrow.lanes[2 * wave].active_hash_rows,
                narrow.lanes[2 * wave + 1].active_hash_rows),
            selector_base +
                wave * MASKS_PER_SEGMENT};
        cursor += segments[wave].rows;
    }
    segments[2] = {
        cursor, narrow.scalar_rows,
        selector_base + 2 * MASKS_PER_SEGMENT};
    cursor += segments[2].rows;
    segments[3] = {
        cursor, narrow.v5_semantic_cells,
        selector_base + 3 * MASKS_PER_SEGMENT};
    cursor += segments[3].rows;
    segments[4] = {
        cursor, TERMINAL_ROWS,
        selector_base + 4 * MASKS_PER_SEGMENT};
    cursor += segments[4].rows;
    out.parent_rows = NextPow2(cursor);
    if (out.parent_rows == 0) {
        out.note =
            "stage3:coupled_bank_unified:row_cap";
        return out;
    }

    out.parent_cs = {};
    out.parent_cs.n_rows = out.parent_rows;
    out.parent_cs.n_columns =
        out.parent_columns_count;
    out.parent_cs.preprocessed_pin_ood = true;
    out.parent_columns.assign(
        out.parent_columns_count,
        std::vector<gf::Fp3>(
            out.parent_rows, gf::Fp3::Zero()));
    for (const auto& segment : segments) {
        FillUnifiedSegmentMasks(
            segment, out.parent_columns);
    }
    for (uint32_t row = segments[0].begin;
         row < segments[1].begin + segments[1].rows;
         ++row) {
        out.parent_columns[
            aggregate_selector_base][row] =
            gf::Fp3::One();
    }
    for (uint32_t wave = 0; wave < 2; ++wave) {
        const auto& segment = segments[wave];
        for (uint32_t row = 0; row < segment.rows; ++row) {
            const uint32_t target = segment.begin + row;
            if (row + 1 < segment.rows) {
                out.parent_columns[
                    aggregate_selector_base + 1][target] =
                    gf::Fp3::One();
            }
        }
    }
    out.parent_columns[
        aggregate_selector_base + 2]
        [segments[0].begin] = gf::Fp3::One();
    out.parent_columns[
        aggregate_selector_base + 3]
        [segments[1].begin + segments[1].rows - 1] =
        gf::Fp3::One();

    for (uint32_t word = 0;
         word < TERMINAL_WORDS; ++word) {
        const gf::Fp3 value =
            gf::Fp3::FromFp(gf::FromU64(
                narrow.parent_output_words[word]));
        std::fill(
            out.parent_columns[carry_base + word].begin(),
            out.parent_columns[carry_base + word].end(),
            value);
    }

    auto install_hash =
        [&](uint32_t lane_index,
            fp::FoldBusComposition& composition) {
            const uint32_t horizontal = lane_index & 1u;
            const auto& segment = segments[lane_index / 2];
            const auto& canonical =
                canonical_hash_cs[horizontal];
            if (!composition.valid ||
                composition.combined.n_columns >
                    out.local_phase_columns ||
                !CopyUnifiedPhase(
                    composition.combined,
                    composition.columns,
                    segment.rows, segment,
                    fixed_base, out.fixed_columns,
                    out.parent_cs,
                    out.parent_columns,
                    horizontal
                        ? horizontal_lane_base : 0,
                    horizontal *
                        hashes[0].combined.preprocessed.size())) {
                return false;
            }
            if (composition.combined.constraints.size() <
                canonical.constraints.size()) {
                return false;
            }
            for (size_t item =
                     canonical.constraints.size();
                 item <
                     composition.combined.constraints.size();
                 ++item) {
                const auto& constraint =
                    composition.combined.constraints[item];
                AddUnifiedGatedConstraint(
                    out.parent_cs, constraint,
                    SegmentMask(segment, constraint.kind));
            }
            return true;
        };
    for (uint32_t lane_index = 0;
         lane_index < 4; ++lane_index) {
        if (!install_hash(lane_index, hashes[lane_index])) {
            out.note =
                "stage3:coupled_bank_unified:install_hash";
            return out;
        }
    }
    for (const auto& canonical : canonical_hash_cs) {
        for (const auto& constraint :
             canonical.constraints) {
            AddUnifiedGatedConstraint(
                out.parent_cs, constraint,
                aggregate_selector_base +
                    static_cast<uint32_t>(
                        constraint.kind));
        }
    }

    auto install_phase =
        [&](uint32_t phase,
            const aq::AirConstraintSystem<gf::Fp3>& phase_cs,
            const std::vector<std::vector<gf::Fp3>>& phase_columns,
            uint32_t active_rows) {
            const auto& segment = segments[phase];
            if (!CopyUnifiedPhase(
                    phase_cs, phase_columns,
                    active_rows, segment,
                    fixed_base, out.fixed_columns,
                    out.parent_cs,
                    out.parent_columns)) {
                return false;
            }
            for (const auto& constraint :
                 phase_cs.constraints) {
                AddUnifiedGatedConstraint(
                    out.parent_cs, constraint,
                    SegmentMask(segment, constraint.kind));
            }
            return true;
        };
    if (!install_phase(
            2, narrow.scalar_cs,
            narrow.scalar_columns,
            narrow.scalar_rows) ||
        !install_phase(
            3, narrow.v5_semantic_cs,
            narrow.v5_semantic_columns,
            narrow.v5_semantic_cells) ||
        !install_phase(
            4, narrow.terminal_cs,
            narrow.terminal_columns,
            TERMINAL_ROWS)) {
        out.note =
            "stage3:coupled_bank_unified:install_phase";
        return out;
    }

    for (uint32_t word = 0;
         word < TERMINAL_WORDS; ++word) {
        AddConstraint(
            out.parent_cs,
            "stage3.bank_unified.scalar_output_carry",
            aq::AirKind::kEverywhere, 2,
            [mask = segments[2].selector_base,
             local = narrow.scalar_parent_column_base + word,
             carry = carry_base + word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[mask],
                    gf::Sub(cur[local], cur[carry]));
            });
        AddConstraint(
            out.parent_cs,
            "stage3.bank_unified.terminal_output_carry",
            aq::AirKind::kEverywhere, 2,
            [mask = segments[4].selector_base,
             local = TERMINAL_PARENT_BASE + word,
             carry = carry_base + word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[mask],
                    gf::Sub(cur[local], cur[carry]));
            });
    }
    for (uint32_t phase = 0;
         phase + 1 < SEGMENTS; ++phase) {
        for (uint32_t word = 0;
             word < TERMINAL_WORDS; ++word) {
            AddConstraint(
                out.parent_cs,
                "stage3.bank_unified.phase_transition_carry",
                aq::AirKind::kEverywhere, 2,
                [mask = segments[phase].selector_base + 3,
                 carry = carry_base + word](
                    const std::vector<gf::Fp3>& cur,
                    const std::vector<gf::Fp3>& next) {
                    return gf::Mul(
                        cur[mask],
                        gf::Sub(next[carry], cur[carry]));
                });
        }
    }

    for (uint32_t column = 0;
         column < out.fixed_columns; ++column) {
        out.parent_cs.preprocessed.emplace_back(
            fixed_base + column,
            out.parent_columns[fixed_base + column]);
    }
    for (uint32_t column = 0;
         column < out.selector_columns; ++column) {
        out.parent_cs.preprocessed.emplace_back(
            selector_base + column,
            out.parent_columns[selector_base + column]);
    }
    for (uint32_t word = 0;
         word < TERMINAL_WORDS; ++word) {
        out.parent_cs.preprocessed.emplace_back(
            carry_base + word,
            out.parent_columns[carry_base + word]);
    }

    HashWriter seed;
    seed << "BTX_RC_STAGE3_BANK_UNIFIED_PARENT_V1";
    seed << narrow.v5_sha_boundary_commitment;
    seed << out.parent_rows << out.parent_columns_count;
    for (const uint256& commitment :
         narrow.child_proof_commitments) {
        seed << commitment;
    }
    for (const uint32_t word :
         narrow.parent_output_words) {
        seed << word;
    }
    out.parent_fs_seed = seed.GetHash();
    out.parent_output_words =
        narrow.parent_output_words;
    out.v5_sha_boundary_commitment =
        narrow.v5_sha_boundary_commitment;
    if (out.parent_fs_seed.IsNull()) {
        out.note =
            "stage3:coupled_bank_unified:parent_seed";
        return out;
    }

    out.parent_constraints =
        static_cast<uint32_t>(
            out.parent_cs.constraints.size());
    for (const auto& constraint :
         out.parent_cs.constraints) {
        out.parent_max_degree = std::max(
            out.parent_max_degree,
            constraint.alg_degree);
    }
    out.quotient_len =
        out.parent_cs.QuotientLen();
    out.proof_coefficients =
        NextPow2(std::max(
            out.parent_rows, out.quotient_len));
    if (out.proof_coefficients != 0 &&
        out.proof_coefficients <=
            UINT32_MAX / kRCFriBlowup) {
        out.proof_lde =
            out.proof_coefficients * kRCFriBlowup;
        out.estimated_lde_cells =
            uint64_t{out.parent_columns_count + 1} *
            out.proof_lde;
    }

    out.violations =
        ar::CountWitnessViolationsOnH(
            out.parent_cs, out.parent_columns);
    out.one_selector_scheduled_trace = true;
    out.exact_phase_transitions =
        out.violations == 0;
    out.fixed_columns_publicly_pinned =
        out.parent_cs.preprocessed.size() ==
            out.fixed_columns +
            out.selector_columns +
            out.carry_columns;
    out.fs_public_boundary_bound =
        !out.v5_sha_boundary_commitment.IsNull() &&
        !out.parent_fs_seed.IsNull();
    out.scalar_terminal_output_carried =
        out.violations == 0;
    out.all_phase_outputs_same_trace =
        out.violations == 0;
    out.under_selected_width =
        out.parent_columns_count <=
            narrow.selected_full_parent_width;
    // A dual-Q128 parent would materialize every parent LDE column plus its
    // quotient. Keep the live prover below 2^28 extension-field cells; the
    // selected production schedule is screened, not optimistically launched.
    out.proof_resource_feasible =
        out.estimated_lde_cells != 0 &&
        out.estimated_lde_cells <=
            (uint64_t{1} << 28);
    if (out.proof_resource_feasible &&
        out.violations == 0) {
        const auto prove_begin =
            std::chrono::steady_clock::now();
        auto proved =
            aq::AirQuotientProve<
                gf::Fp3, ar::DualAlgB3>(
                out.parent_cs, out.parent_columns,
                out.parent_fs_seed, {});
        out.prove_micros =
            static_cast<uint64_t>(
                std::chrono::duration_cast<
                    std::chrono::microseconds>(
                    std::chrono::steady_clock::now() -
                    prove_begin).count());
        if (proved.ok && proved.division_exact) {
            out.parent_proof =
                std::move(proved.proof);
            out.parent_proof_emitted = true;
            const auto verify_begin =
                std::chrono::steady_clock::now();
            std::string verify_why;
            out.parent_proof_verified =
                aq::AirQuotientVerify<
                    gf::Fp3, ar::DualAlgB3>(
                    out.parent_cs, out.parent_proof,
                    out.parent_fs_seed,
                    &verify_why);
            out.verify_micros =
                static_cast<uint64_t>(
                    std::chrono::duration_cast<
                        std::chrono::microseconds>(
                        std::chrono::steady_clock::now() -
                        verify_begin).count());
        }
    }
    out.consensus_authority =
        out.parent_proof_emitted &&
        out.parent_proof_verified &&
        out.all_phase_outputs_same_trace &&
        false; // SHA derivation equations remain outside this public boundary.
    out.valid =
        out.violations == 0 &&
        out.one_selector_scheduled_trace &&
        out.exact_phase_transitions &&
        out.fixed_columns_publicly_pinned &&
        out.fs_public_boundary_bound &&
        out.scalar_terminal_output_carried &&
        out.all_phase_outputs_same_trace &&
        out.under_selected_width;
    out.note =
        out.valid
            ? out.parent_proof_verified
                ? "stage3:coupled_bank_unified:parent_proof_verified_"
                  "sha_equations_open"
                : "stage3:coupled_bank_unified:single_trace_zero_"
                  "violations_prover_resource_screened"
            : "stage3:coupled_bank_unified:constraint_failure";
    return out;
}

} // namespace matmul::v4::rc
