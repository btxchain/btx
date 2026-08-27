// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gated_ctl_alias.h>

#include <hash.h>

#include <limits>
#include <tuple>

namespace matmul::v4::rc::gated_ctl_alias {
namespace {

using gf::Fp3;
using CS = aq::AirConstraintSystem<Fp3>;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:gated_ctl_alias:" + detail;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

bool Canonical(const Fp3& value)
{
    for (const auto lane : {value.c0, value.c1, value.c2}) {
        if (gf::Canonical(lane) >= gf::kP) return false;
    }
    return true;
}

bool ValidChallenges(const RCStage3CtlChallenges& challenges)
{
    return Canonical(challenges.gamma1) &&
        Canonical(challenges.gamma2) &&
        Canonical(challenges.alpha1) &&
        Canonical(challenges.alpha2) &&
        !gf::IsZero(challenges.gamma1) &&
        !gf::IsZero(challenges.gamma2) &&
        !gf::Eq(challenges.gamma1, challenges.gamma2) &&
        !gf::Eq(challenges.alpha1, challenges.alpha2);
}

void Add(
    CS& cs,
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

void CopyFamily(const CS& source, uint32_t offset, CS& destination)
{
    for (const auto& source_constraint : source.constraints) {
        aq::AirConstraint<Fp3> copied;
        copied.name = source_constraint.name;
        copied.kind = source_constraint.kind;
        copied.alg_degree = source_constraint.alg_degree;
        const auto eval = source_constraint.eval;
        const uint32_t width = source.n_columns;
        copied.eval =
            [offset, width, eval](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                std::vector<Fp3> local_current(
                    current.begin() + offset,
                    current.begin() + offset + width);
                std::vector<Fp3> local_next(
                    next.begin() + offset,
                    next.begin() + offset + width);
                return eval(local_current, local_next);
            };
        destination.constraints.push_back(std::move(copied));
    }
    for (const auto& [column, values] : source.preprocessed) {
        destination.preprocessed.push_back({offset + column, values});
    }
    for (const auto& [column, root] : source.preprocessed_roots) {
        destination.preprocessed_roots.push_back({offset + column, root});
    }
}

Fp3 Compress(
    const std::vector<Fp3>& row,
    uint32_t base,
    uint32_t value_column,
    const Fp3& gamma)
{
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    return gf::Add(
        row[base + col::NAMESPACE],
        gf::Add(
            gf::Mul(gamma, row[base + col::STAGE]),
            gf::Add(
                gf::Mul(gamma2, row[base + col::ADDRESS]),
                gf::Mul(gamma3, row[value_column]))));
}

} // namespace

bool BuildConstraintSystemV1(
    const CS& relation,
    const SpecV1& spec,
    CS& out,
    LayoutV1& layout,
    std::string* why)
{
    out = {};
    layout = {};
    if (spec.version != kVersionV1 ||
        !PowerOfTwo(relation.n_rows) ||
        relation.n_columns == 0 ||
        relation.constraints.empty() ||
        spec.source_column >= relation.n_columns ||
        spec.selector_column >= relation.n_columns ||
        (spec.sign != 1 && spec.sign != -1) ||
        spec.addresses.size() != relation.n_rows ||
        !ValidChallenges(spec.challenges) ||
        !Canonical(spec.expected_terminal.alpha1_sum) ||
        !Canonical(spec.expected_terminal.alpha2_sum) ||
        relation.n_columns >
            std::numeric_limits<uint32_t>::max() - col::NUM_COLUMNS) {
        return Fail(why, "shape_or_public_input");
    }

    layout.version = kVersionV1;
    layout.relation_columns = relation.n_columns;
    layout.ctl_base = relation.n_columns;
    layout.total_columns = relation.n_columns + col::NUM_COLUMNS;
    layout.source_column = spec.source_column;
    layout.selector_column = spec.selector_column;

    out.n_rows = relation.n_rows;
    out.n_columns = layout.total_columns;
    out.preprocessed_pin_ood = true;
    CopyFamily(relation, 0, out);

    std::vector<Fp3> namespace_column(
        relation.n_rows, gf::FromU64_3(spec.namespace_id));
    std::vector<Fp3> stage_column(
        relation.n_rows, gf::FromU64_3(spec.stage));
    std::vector<Fp3> address_column(
        relation.n_rows, Fp3::Zero());
    for (uint32_t row = 0; row < relation.n_rows; ++row) {
        address_column[row] = gf::FromU64_3(spec.addresses[row]);
    }
    out.preprocessed.push_back(
        {layout.ctl_base + col::NAMESPACE, std::move(namespace_column)});
    out.preprocessed.push_back(
        {layout.ctl_base + col::STAGE, std::move(stage_column)});
    out.preprocessed.push_back(
        {layout.ctl_base + col::ADDRESS, std::move(address_column)});

    const uint32_t base = layout.ctl_base;
    const uint32_t selector = spec.selector_column;
    const uint32_t value = spec.source_column;
    const Fp3 sign = gf::FromSigned3(spec.sign);

    Add(
        out, "gated_ctl.selector_boolean",
        aq::AirKind::kEverywhere, 2,
        [selector](const std::vector<Fp3>& row,
                   const std::vector<Fp3>&) {
            return gf::Mul(
                row[selector],
                gf::Sub(row[selector], Fp3::One()));
        });
    Add(
        out, "gated_ctl.multiplicity_alias",
        aq::AirKind::kEverywhere, 1,
        [base, selector, sign](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Sub(
                row[base + col::MULTIPLICITY],
                gf::Mul(sign, row[selector]));
        });

    const auto add_inverse_lane =
        [&](const char* active_name,
            const char* inactive_name,
            uint32_t inverse_column,
            Fp3 gamma,
            Fp3 alpha) {
            Add(
                out, active_name,
                aq::AirKind::kEverywhere, 3,
                [base, selector, value,
                 inverse_column, gamma, alpha](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    const Fp3 denominator =
                        gf::Sub(
                            alpha,
                            Compress(row, base, value, gamma));
                    return gf::Mul(
                        row[selector],
                        gf::Sub(
                            gf::Mul(
                                row[base + inverse_column],
                                denominator),
                            Fp3::One()));
                });
            Add(
                out, inactive_name,
                aq::AirKind::kEverywhere, 2,
                [base, selector, inverse_column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Sub(Fp3::One(), row[selector]),
                        row[base + inverse_column]);
                });
        };
    add_inverse_lane(
        "gated_ctl.inverse1.active",
        "gated_ctl.inverse1.inactive_zero",
        col::INVERSE1,
        spec.challenges.gamma1,
        spec.challenges.alpha1);
    add_inverse_lane(
        "gated_ctl.inverse2.active",
        "gated_ctl.inverse2.inactive_zero",
        col::INVERSE2,
        spec.challenges.gamma2,
        spec.challenges.alpha2);

    for (const auto& lane :
         {std::tuple<
              uint32_t, uint32_t, uint32_t,
              const char*, const char*, const char*, const char*>{
              col::INVERSE1, col::TERM1, col::RUNNING1,
              "gated_ctl.lane1.term",
              "gated_ctl.lane1.first",
              "gated_ctl.lane1.transition",
              "gated_ctl.lane1.last"},
          std::tuple<
              uint32_t, uint32_t, uint32_t,
              const char*, const char*, const char*, const char*>{
              col::INVERSE2, col::TERM2, col::RUNNING2,
              "gated_ctl.lane2.term",
              "gated_ctl.lane2.first",
              "gated_ctl.lane2.transition",
              "gated_ctl.lane2.last"}}) {
        // AppleClang 16 + OpenMP cannot capture structured bindings in lambdas.
        const uint32_t inverse{std::get<0>(lane)};
        const uint32_t term{std::get<1>(lane)};
        const uint32_t running{std::get<2>(lane)};
        const char* const term_name{std::get<3>(lane)};
        const char* const first_name{std::get<4>(lane)};
        const char* const transition_name{std::get<5>(lane)};
        const char* const last_name{std::get<6>(lane)};
        Add(
            out,
            term_name,
            aq::AirKind::kEverywhere, 2,
            [base, inverse, term](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    row[base + term],
                    gf::Mul(
                        row[base + col::MULTIPLICITY],
                        row[base + inverse]));
            });
        Add(
            out,
            first_name,
            aq::AirKind::kFirstRow, 1,
            [base, running](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return row[base + running];
            });
        Add(
            out,
            transition_name,
            aq::AirKind::kTransition, 1,
            [base, term, running](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[base + running],
                    gf::Add(
                        row[base + running],
                        row[base + term]));
            });
        const Fp3 expected =
            running == col::RUNNING1
            ? spec.expected_terminal.alpha1_sum
            : spec.expected_terminal.alpha2_sum;
        Add(
            out,
            last_name,
            aq::AirKind::kLastRow, 1,
            [base, term, running, expected](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    gf::Add(
                        row[base + running],
                        row[base + term]),
                    expected);
            });
    }

    layout.base_column_indices.reserve(
        relation.n_columns + 4);
    for (uint32_t column = 0;
         column < relation.n_columns;
         ++column) {
        layout.base_column_indices.push_back(column);
    }
    for (uint32_t column = col::NAMESPACE;
         column <= col::MULTIPLICITY;
         ++column) {
        layout.base_column_indices.push_back(base + column);
    }
    return true;
}

WitnessV1 BuildWitnessV1(
    const std::vector<std::vector<Fp3>>& relation_columns,
    const SpecV1& spec,
    const LayoutV1& layout)
{
    WitnessV1 out;
    if (spec.version != kVersionV1 ||
        layout.version != kVersionV1 ||
        relation_columns.size() != layout.relation_columns ||
        relation_columns.empty() ||
        spec.source_column != layout.source_column ||
        spec.selector_column != layout.selector_column ||
        spec.addresses.size() != relation_columns.front().size() ||
        (spec.sign != 1 && spec.sign != -1) ||
        !ValidChallenges(spec.challenges)) {
        out.note = "stage3:gated_ctl_alias:witness_shape";
        return out;
    }
    const uint32_t rows =
        static_cast<uint32_t>(relation_columns.front().size());
    if (!PowerOfTwo(rows)) {
        out.note = "stage3:gated_ctl_alias:witness_rows";
        return out;
    }
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            out.note = "stage3:gated_ctl_alias:witness_column_rows";
            return out;
        }
    }
    out.columns = relation_columns;
    out.columns.resize(
        layout.total_columns,
        std::vector<Fp3>(rows, Fp3::Zero()));
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    const Fp3 sign = gf::FromSigned3(spec.sign);
    for (uint32_t row = 0; row < rows; ++row) {
        const Fp3 selector =
            relation_columns[spec.selector_column][row];
        if (!gf::Eq(selector, Fp3::Zero()) &&
            !gf::Eq(selector, Fp3::One())) {
            out.columns.clear();
            out.note = "stage3:gated_ctl_alias:witness_selector";
            return out;
        }
        const uint32_t base = layout.ctl_base;
        out.columns[base + col::NAMESPACE][row] =
            gf::FromU64_3(spec.namespace_id);
        out.columns[base + col::STAGE][row] =
            gf::FromU64_3(spec.stage);
        out.columns[base + col::ADDRESS][row] =
            gf::FromU64_3(spec.addresses[row]);
        out.columns[base + col::MULTIPLICITY][row] =
            gf::Mul(sign, selector);
        out.columns[base + col::RUNNING1][row] = running1;
        out.columns[base + col::RUNNING2][row] = running2;
        if (gf::Eq(selector, Fp3::Zero())) continue;

        RCStage3CtlEvent event{
            spec.namespace_id,
            spec.stage,
            spec.addresses[row],
            spec.sign};
        const Fp3 value =
            relation_columns[spec.source_column][row];
        const Fp3 d1 = gf::Sub(
            spec.challenges.alpha1,
            CompressRCStage3CtlTuple(
                event, value, spec.challenges.gamma1));
        const Fp3 d2 = gf::Sub(
            spec.challenges.alpha2,
            CompressRCStage3CtlTuple(
                event, value, spec.challenges.gamma2));
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            out.columns.clear();
            out.note = "stage3:gated_ctl_alias:challenge_collision";
            return out;
        }
        const Fp3 inv1 = gf::Inv(d1);
        const Fp3 inv2 = gf::Inv(d2);
        const Fp3 term1 = gf::Mul(sign, inv1);
        const Fp3 term2 = gf::Mul(sign, inv2);
        out.columns[base + col::INVERSE1][row] = inv1;
        out.columns[base + col::INVERSE2][row] = inv2;
        out.columns[base + col::TERM1][row] = term1;
        out.columns[base + col::TERM2][row] = term2;
        running1 = gf::Add(running1, term1);
        running2 = gf::Add(running2, term2);
    }
    out.terminal = {running1, running2};
    out.valid = true;
    out.note = "stage3:gated_ctl_alias:witness_ok";
    return out;
}

bool BuildPrechallengeColumnsV1(
    const std::vector<std::vector<Fp3>>& relation_columns,
    const SpecV1& spec,
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (relation_columns.empty() ||
        relation_columns.size() != layout.relation_columns ||
        spec.addresses.size() != relation_columns.front().size() ||
        (spec.sign != 1 && spec.sign != -1)) {
        return Fail(why, "prechallenge_shape");
    }
    const uint32_t rows =
        static_cast<uint32_t>(relation_columns.front().size());
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            return Fail(why, "prechallenge_rows");
        }
    }
    out = relation_columns;
    out.resize(
        layout.total_columns,
        std::vector<Fp3>(rows, Fp3::Zero()));
    const Fp3 sign = gf::FromSigned3(spec.sign);
    for (uint32_t row = 0; row < rows; ++row) {
        out[layout.ctl_base + col::NAMESPACE][row] =
            gf::FromU64_3(spec.namespace_id);
        out[layout.ctl_base + col::STAGE][row] =
            gf::FromU64_3(spec.stage);
        out[layout.ctl_base + col::ADDRESS][row] =
            gf::FromU64_3(spec.addresses[row]);
        out[layout.ctl_base + col::MULTIPLICITY][row] =
            gf::Mul(
                sign,
                relation_columns[spec.selector_column][row]);
    }
    return true;
}

uint256 ComputeTraceCommitmentV1(
    const CS& combined,
    const LayoutV1& layout,
    const std::vector<uint256>& ordered_base_roots)
{
    if (layout.version != kVersionV1 ||
        ordered_base_roots.size() !=
            layout.base_column_indices.size() ||
        combined.n_columns != layout.total_columns ||
        !PowerOfTwo(combined.n_rows)) {
        return {};
    }
    HashWriter hash;
    hash << std::string{"BTX_RC_STAGE3_GATED_CTL_R0_V1"}
         << kVersionV1
         << combined.n_rows
         << combined.n_columns
         << static_cast<uint32_t>(
                layout.base_column_indices.size());
    for (uint32_t i = 0;
         i < layout.base_column_indices.size();
         ++i) {
        if (ordered_base_roots[i].IsNull()) return {};
        hash << layout.base_column_indices[i]
             << ordered_base_roots[i];
    }
    return hash.GetHash();
}

} // namespace matmul::v4::rc::gated_ctl_alias
