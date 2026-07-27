// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <algorithm>
#include <utility>

namespace matmul::v4::rc::stage3_poseidon_air {
namespace {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace gf = gkr_field;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:poseidon_air:" + message;
    return false;
}

bool IsPowerOfTwo(uint32_t n)
{
    return n >= 2 && (n & (n - 1)) == 0;
}

std::vector<aq::AirConstraint<Fp3>>
BuildConstraints(const Layout& layout, const uint32_t* selector_col)
{
    const bool selector_gated = selector_col != nullptr;
    const uint32_t selector = selector_gated ? *selector_col : 0;
    std::vector<aq::AirConstraint<Fp3>> out;
    out.reserve(kFixedConstraints + (selector_gated ? 1 : 0));

    if (selector_gated) {
        aq::AirConstraint<Fp3> c;
        c.name = "stage3.poseidon.selector.bool";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 2;
        c.eval = [selector](const std::vector<Fp3>& cur,
                            const std::vector<Fp3>&) {
            return gf::Mul(cur[selector],
                           gf::Sub(cur[selector], Fp3::One()));
        };
        out.push_back(std::move(c));
    }

    auto gate = [selector_gated, selector](const std::vector<Fp3>& cur,
                                           const Fp3& residual) {
        return !selector_gated
            ? residual
            : gf::Mul(cur[selector], residual);
    };

    for (uint32_t s = 0; s < ar::kPermSboxCells; ++s) {
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.poseidon.sbox.x2";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = selector_gated ? 3 : 2;
            c.eval = [layout, s, gate](const std::vector<Fp3>& cur,
                                       const std::vector<Fp3>&) {
                const Fp3 x = ar::PermSboxInput(layout.perm, cur, s);
                return gate(cur, gf::Sub(cur[layout.X2Col(s)],
                                         gf::Mul(x, x)));
            };
            out.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.poseidon.sbox.x4";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = selector_gated ? 3 : 2;
            c.eval = [layout, s, gate](const std::vector<Fp3>& cur,
                                       const std::vector<Fp3>&) {
                const Fp3& x2 = cur[layout.X2Col(s)];
                return gate(cur, gf::Sub(cur[layout.X4Col(s)],
                                         gf::Mul(x2, x2)));
            };
            out.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.poseidon.sbox.x6";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = selector_gated ? 3 : 2;
            c.eval = [layout, s, gate](const std::vector<Fp3>& cur,
                                       const std::vector<Fp3>&) {
                return gate(
                    cur,
                    gf::Sub(cur[layout.X6Col(s)],
                            gf::Mul(cur[layout.X4Col(s)],
                                    cur[layout.X2Col(s)])));
            };
            out.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.poseidon.sbox.output";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = selector_gated ? 3 : 2;
            c.eval = [layout, s, gate](const std::vector<Fp3>& cur,
                                       const std::vector<Fp3>&) {
                const Fp3 x = ar::PermSboxInput(layout.perm, cur, s);
                return gate(
                    cur,
                    gf::Sub(cur[layout.perm.SboxCol(s)],
                            gf::Mul(cur[layout.X6Col(s)], x)));
            };
            out.push_back(std::move(c));
        }
    }
    return out;
}

uint32_t MaxDegree(const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(out, constraint.alg_degree);
    }
    return out;
}

} // namespace

bool Layout::IsCanonical(std::string* why) const
{
    if (x2_base != perm.End() ||
        x4_base != x2_base + ar::kPermSboxCells ||
        x6_base != x4_base + ar::kPermSboxCells ||
        End() - perm.base != kFixedColumns) {
        return Fail(why, "noncanonical_layout");
    }
    return true;
}

Layout CanonicalLayout(uint32_t base)
{
    Layout out;
    out.perm = ar::PermLayout{base};
    out.x2_base = out.perm.End();
    out.x4_base = out.x2_base + ar::kPermSboxCells;
    out.x6_base = out.x4_base + ar::kPermSboxCells;
    return out;
}

std::vector<aq::AirConstraint<Fp3>>
BuildFixedConstraints(const Layout& layout)
{
    return BuildConstraints(layout, nullptr);
}

std::vector<aq::AirConstraint<Fp3>>
BuildSelectorGatedConstraints(const Layout& layout, uint32_t selector_col)
{
    return BuildConstraints(layout, &selector_col);
}

Witness BuildWitness(const Layout& layout, const alg_hash::State& input)
{
    Witness out;
    out.row.assign(layout.End(), Fp3::Zero());
    const ar::PermWitness flattened = ar::BuildPermWitness(input);
    ar::WritePermWitness(layout.perm, flattened, out.row);
    for (uint32_t s = 0; s < ar::kPermSboxCells; ++s) {
        const Fp3 x = ar::PermSboxInput(layout.perm, out.row, s);
        const Fp3 x2 = gf::Mul(x, x);
        const Fp3 x4 = gf::Mul(x2, x2);
        const Fp3 x6 = gf::Mul(x4, x2);
        out.row[layout.X2Col(s)] = x2;
        out.row[layout.X4Col(s)] = x4;
        out.row[layout.X6Col(s)] = x6;
    }
    out.output = flattened.output;
    return out;
}

bool BuildFixedSystem(uint32_t n_rows,
                      aq::AirConstraintSystem<Fp3>& out,
                      std::string* why)
{
    if (!IsPowerOfTwo(n_rows)) return Fail(why, "bad_row_count");
    const Layout layout = CanonicalLayout();
    out = {};
    out.n_rows = n_rows;
    out.n_columns = layout.End();
    out.constraints = BuildFixedConstraints(layout);
    return true;
}

bool BuildSelectorGatedSystem(uint32_t n_rows,
                              const std::vector<Fp3>& selector_values,
                              aq::AirConstraintSystem<Fp3>& out,
                              std::string* why)
{
    if (!IsPowerOfTwo(n_rows)) return Fail(why, "bad_row_count");
    if (selector_values.size() != n_rows) {
        return Fail(why, "selector_length_mismatch");
    }
    for (const Fp3& value : selector_values) {
        if (!gf::Eq(value, Fp3::Zero()) &&
            !gf::Eq(value, Fp3::One())) {
            return Fail(why, "nonboolean_selector");
        }
    }

    const Layout layout = CanonicalLayout();
    const uint32_t selector_col = layout.End();
    out = {};
    out.n_rows = n_rows;
    out.n_columns = selector_col + 1;
    out.constraints =
        BuildSelectorGatedConstraints(layout, selector_col);
    out.preprocessed.push_back({selector_col, selector_values});
    return true;
}

Measurement Measure(uint32_t n_rows)
{
    Measurement out;
    out.sboxes = ar::kPermSboxCells;
    out.base_columns = ar::kPermCellsPerPerm;
    out.auxiliary_columns =
        kSboxAuxColumnsPerSbox * ar::kPermSboxCells;
    out.fixed_columns = kFixedColumns;
    out.selector_gated_columns = kSelectorGatedColumns;
    out.fixed_constraints = kFixedConstraints;
    out.selector_gated_constraints = kSelectorGatedConstraints;
    out.n_rows = n_rows;

    aq::AirConstraintSystem<Fp3> fixed;
    if (BuildFixedSystem(n_rows, fixed)) {
        out.fixed_max_degree = MaxDegree(fixed);
        out.fixed_composed_degree = fixed.MaxComposedDegreeBound();
        out.fixed_quotient_len = fixed.QuotientLen();
    }

    aq::AirConstraintSystem<Fp3> gated;
    if (BuildSelectorGatedSystem(
            n_rows, std::vector<Fp3>(n_rows, Fp3::One()), gated)) {
        out.selector_gated_max_degree = MaxDegree(gated);
        out.selector_gated_composed_degree =
            gated.MaxComposedDegreeBound();
        out.selector_gated_quotient_len = gated.QuotientLen();
    }
    return out;
}

} // namespace matmul::v4::rc::stage3_poseidon_air
