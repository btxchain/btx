// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_terminal_fold_parent.h>

#include <hash.h>

#include <algorithm>
#include <bit>
#include <limits>
#include <numeric>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_v13_terminal_fold_parent {
namespace {

using Digest = alg_hash::Digest;
using Fp3 = gf::Fp3;
using State = alg_hash::State;

struct EdgeV1 {
    uint32_t source_row{0};
    uint32_t sink_row{0};
    uint32_t sink_lane{0};
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v13_terminal_fold_parent:" + detail;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value < 2) return 2;
    if (value > (UINT32_MAX >> 1)) return 0;
    return std::bit_ceil(value);
}

uint32_t Log2Exact(uint32_t value)
{
    if (!PowerOfTwo(value)) return 0;
    return std::countr_zero(value);
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
    cs.constraints.push_back(
        std::move(constraint));
}

uint256 CommitPlan(const PublicPlanV1& plan)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_V13_TERMINAL_FOLD_PARENT_PLAN_V1"};
    hash << plan.version;
    hash << plan.blowup;
    hash << plan.fold_count;
    hash << plan.real_rows;
    hash << plan.trace_rows;
    hash << plan.internal_edges;
    hash << plan.hash.n_columns;
    hash << plan.hash.input_pin_base;
    hash << plan.hash.output_pin_base;
    return hash.GetHash();
}

bool SamePlan(const PublicPlanV1& plan)
{
    return plan.version == kVersionV1 &&
        PowerOfTwo(plan.blowup) &&
        plan.fold_count != 0 &&
        plan.real_rows == 2 * plan.blowup - 1 &&
        plan.trace_rows ==
            NextPowerOfTwo(plan.real_rows) &&
        plan.internal_edges ==
            2 * (plan.blowup - 1) &&
        plan.hash.n_columns ==
            mf::CanonicalHashLayoutV1().n_columns &&
        plan.hash.input_pin_base ==
            mf::CanonicalHashLayoutV1().input_pin_base &&
        plan.hash.output_pin_base ==
            mf::CanonicalHashLayoutV1().output_pin_base &&
        plan.plan_root == CommitPlan(plan) &&
        !plan.plan_root.IsNull() &&
        plan.proof_values_excluded &&
        plan.exact_tree_schedule &&
        plan.valid;
}

LayoutV1 CanonicalLayout(
    const PublicPlanV1& plan)
{
    LayoutV1 out;
    out.hash = plan.hash;
    uint32_t column = out.hash.n_columns;
    out.final_value_base = column;
    column += kFinalValueCoordinatesV1;
    out.final_value_limb_base = column;
    column += kFinalValueLimbsV1;
    out.final_value_bit_base = column;
    column += kFinalValueCoordinatesV1 * 64;
    out.terminal_root_limb_base = column;
    column += kTerminalRootLimbsV1;
    out.terminal_root_bit_base = column;
    column += kTerminalRootCoordinatesV1 * 64;
    out.edge_carrier_base = column;
    column +=
        plan.internal_edges *
        kTerminalRootCoordinatesV1;
    out.leaf_selector = column++;
    out.node_selector = column++;
    out.padding_selector = column++;
    out.root_selector = column++;
    out.leaf_index = column++;
    out.edge_source_selector_base = column;
    column += plan.internal_edges;
    out.edge_sink_selector_base = column;
    column += plan.internal_edges;
    out.acceptance = column++;
    out.n_columns = column;
    return out;
}

State LeafInput(const Fp3& value, uint32_t index)
{
    State input{};
    input[0] = gf::Canonical(value.c0);
    input[1] = gf::Canonical(value.c1);
    input[2] = gf::Canonical(value.c2);
    input[3] = gf::FromU64(index);
    input[4] =
        alg_hash::GetAlgHashConstants().leaf_domain;
    return input;
}

State NodeInput(
    const Digest& left,
    const Digest& right)
{
    State input{};
    for (uint32_t lane = 0;
         lane < kTerminalRootCoordinatesV1;
         ++lane) {
        input[lane] = left[lane];
        input[kTerminalRootCoordinatesV1 + lane] =
            right[lane];
    }
    input[8] =
        alg_hash::GetAlgHashConstants().node_domain;
    return input;
}

Digest DigestFrom(const State& state)
{
    return {state[0], state[1], state[2], state[3]};
}

uint64_t U64(const Fp3& value)
{
    return gf::Canonical(value.c0);
}

void WriteU64Bits(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t bit_base,
    uint32_t row,
    uint64_t value)
{
    for (uint32_t bit = 0; bit < 64; ++bit) {
        columns[bit_base + bit][row] =
            gf::FromU64_3((value >> bit) & 1U);
    }
}

bool IsPreprocessed(
    const aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column)
{
    return std::any_of(
        cs.preprocessed.begin(),
        cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
}

std::optional<tape::SourceAddressCellV1>
FindTapeCell(
    const tape::ProductV1& product,
    abi::SourceKeyV1 key)
{
    const auto it = std::find_if(
        product.source_cells.begin(),
        product.source_cells.end(),
        [&key](const auto& cell) {
            return cell.key == key;
        });
    if (it == product.source_cells.end()) {
        return std::nullopt;
    }
    return *it;
}

abi::SourceKeyV1 FinalValueKey(
    uint32_t coordinate, uint32_t limb)
{
    abi::SourceKeyV1 key;
    key.kind = abi::FieldKindV1::FinalValue;
    key.d = coordinate;
    key.limb = static_cast<uint8_t>(limb);
    return key;
}

abi::SourceKeyV1 TerminalRootKey(
    uint32_t fold_count,
    uint32_t coordinate,
    uint32_t limb)
{
    abi::SourceKeyV1 key;
    key.kind = abi::FieldKindV1::FoldRoot;
    key.a = fold_count;
    key.d = coordinate;
    key.limb = static_cast<uint8_t>(limb);
    return key;
}

} // namespace

PublicPlanV1 BuildPublicPlanV1(
    const tape::PublicShapeV1& shape)
{
    PublicPlanV1 out;
    out.blowup = kRCFriBlowup;
    out.fold_count = Log2Exact(shape.n_coeffs);
    if (!PowerOfTwo(shape.trace_rows) ||
        !PowerOfTwo(shape.n_coeffs) ||
        shape.trace_rows > shape.n_coeffs ||
        shape.quotient_len == 0 ||
        shape.quotient_len > shape.n_coeffs ||
        shape.trace_columns < 2 ||
        shape.base_column_indices.empty() ||
        out.fold_count == 0 ||
        !PowerOfTwo(out.blowup)) {
        out.note =
            "stage3:v13_terminal_fold_parent:"
            "public_shape";
        return out;
    }
    out.real_rows = 2 * out.blowup - 1;
    out.trace_rows =
        NextPowerOfTwo(out.real_rows);
    out.internal_edges =
        2 * (out.blowup - 1);
    out.hash = mf::CanonicalHashLayoutV1();
    out.proof_values_excluded = true;
    out.exact_tree_schedule = true;
    out.plan_root = CommitPlan(out);
    out.valid =
        out.trace_rows != 0 &&
        out.hash.n_columns != 0 &&
        !out.plan_root.IsNull();
    out.note = out.valid
        ? "stage3:v13_terminal_fold_parent:"
          "public_terminal_tree_plan"
        : "stage3:v13_terminal_fold_parent:"
          "plan_invalid";
    return out;
}

ProductV1 BuildProductV1(
    const PublicPlanV1& plan,
    const abi::DecodedV1& decoded)
{
    ProductV1 out;
    out.plan = plan;
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_terminal_fold_parent:" +
                detail;
            return out;
        };
    if (!SamePlan(plan) ||
        !decoded.canonical ||
        !decoded.complete ||
        !decoded.addresses_unique ||
        !decoded.semantic_keys_unique) {
        return fail("plan_or_abi");
    }
    const auto& batch =
        decoded.envelope.split.batch;
    if (batch.blowup != plan.blowup ||
        batch.n_coeffs == 0 ||
        Log2Exact(batch.n_coeffs) !=
            plan.fold_count ||
        batch.fold_layers.size() !=
            plan.fold_count + 1 ||
        batch.fold_layers.back().n_leaves !=
            plan.blowup) {
        return fail("proof_shape");
    }

    out.layout = CanonicalLayout(plan);
    std::string why;
    if (!stage3_poseidon_air::BuildFixedSystem(
            plan.trace_rows, out.cs, &why)) {
        return fail("poseidon_cs:" + why);
    }
    out.cs.n_columns = out.layout.n_columns;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.hash_input_pin",
            aq::AirKind::kEverywhere, 1,
            [layout = out.layout, lane](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    current[
                        layout.hash.poseidon.perm.
                            InputCol(lane)],
                    current[
                        layout.hash.InputPin(lane)]);
            });
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen;
         ++lane) {
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.hash_output_pin",
            aq::AirKind::kEverywhere, 1,
            [layout = out.layout, lane](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    air_recurse::PermOutputLane(
                        layout.hash.poseidon.perm,
                        current, lane),
                    current[
                        layout.hash.OutputPin(lane)]);
            });
    }

    std::vector<State> inputs(plan.trace_rows);
    std::vector<State> outputs(plan.trace_rows);
    std::vector<EdgeV1> edges;
    edges.reserve(plan.internal_edges);
    std::vector<uint32_t> level_rows;
    level_rows.reserve(plan.blowup);
    for (uint32_t index = 0;
         index < plan.blowup; ++index) {
        const uint32_t row =
            static_cast<uint32_t>(level_rows.size());
        inputs[row] =
            LeafInput(batch.final_value, index);
        outputs[row] = inputs[row];
        alg_hash::Permute(outputs[row]);
        level_rows.push_back(row);
    }
    uint32_t cursor = plan.blowup;
    while (level_rows.size() > 1) {
        std::vector<uint32_t> next;
        next.reserve(level_rows.size() / 2);
        for (uint32_t node = 0;
             node < level_rows.size();
             node += 2) {
            if (cursor >= plan.real_rows) {
                return fail("tree_cursor");
            }
            const uint32_t row = cursor++;
            inputs[row] = NodeInput(
                DigestFrom(outputs[level_rows[node]]),
                DigestFrom(
                    outputs[level_rows[node + 1]]));
            outputs[row] = inputs[row];
            alg_hash::Permute(outputs[row]);
            for (uint32_t child = 0;
                 child < 2; ++child) {
                edges.push_back({
                    level_rows[node + child],
                    row,
                    child *
                        kTerminalRootCoordinatesV1});
            }
            next.push_back(row);
        }
        level_rows = std::move(next);
    }
    if (cursor != plan.real_rows ||
        level_rows.size() != 1 ||
        level_rows[0] + 1 !=
            plan.real_rows ||
        edges.size() !=
            plan.internal_edges) {
        return fail("tree_schedule");
    }
    for (uint32_t row = plan.real_rows;
         row < plan.trace_rows; ++row) {
        outputs[row] = inputs[row];
        alg_hash::Permute(outputs[row]);
    }

    for (uint32_t row = 0;
         row < plan.trace_rows; ++row) {
        const auto witness =
            stage3_poseidon_air::BuildWitness(
                out.layout.hash.poseidon,
                inputs[row]);
        if (witness.row.size() !=
                out.layout.hash.poseidon.End() ||
            witness.output != outputs[row]) {
            return fail("poseidon_witness");
        }
        for (uint32_t column = 0;
             column < witness.row.size();
             ++column) {
            out.columns[column][row] =
                witness.row[column];
        }
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashT;
             ++lane) {
            out.columns[
                out.layout.hash.InputPin(lane)][row] =
                Fp3::FromFp(inputs[row][lane]);
        }
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashDigestLen;
             ++lane) {
            out.columns[
                out.layout.hash.OutputPin(lane)][row] =
                Fp3::FromFp(outputs[row][lane]);
        }
    }

    for (uint32_t coordinate = 0;
         coordinate <
             kFinalValueCoordinatesV1;
         ++coordinate) {
        const Fp3 value = Fp3::FromFp(
            coordinate == 0
                ? batch.final_value.c0
                : coordinate == 1
                    ? batch.final_value.c1
                    : batch.final_value.c2);
        out.columns[
            out.layout.FinalValue(
                coordinate)].assign(
                    plan.trace_rows, value);
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.final_value_carry",
            aq::AirKind::kTransition, 1,
            [column =
                 out.layout.FinalValue(
                     coordinate)](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column], current[column]);
            });
        const uint64_t raw = U64(value);
        for (uint32_t limb = 0;
             limb < kU32LimbsPerFieldV1;
             ++limb) {
            const uint32_t column =
                out.layout.FinalValueLimb(
                    coordinate, limb);
            out.columns[column][0] =
                gf::FromU64_3(
                    static_cast<uint32_t>(
                        raw >> (32 * limb)));
            out.abi_consumers.final_value[
                coordinate *
                    kU32LimbsPerFieldV1 +
                limb] = {column, 0};
        }
        WriteU64Bits(
            out.columns,
            out.layout.FinalValueBit(
                coordinate, 0),
            0, raw);
        for (uint32_t bit = 0;
             bit < 64; ++bit) {
            AddConstraint(
                out.cs,
                "stage3.v13_terminal.final_value_bit",
                aq::AirKind::kFirstRow, 2,
                [column =
                     out.layout.FinalValueBit(
                         coordinate, bit)](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[column],
                        gf::Sub(
                            current[column],
                            Fp3::One()));
                });
        }
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.final_value_limb_low",
            aq::AirKind::kFirstRow, 1,
            [layout = out.layout, coordinate](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            gf::FromU64_3(weight),
                            current[
                                layout.FinalValueBit(
                                    coordinate, bit)]));
                    weight <<= 1;
                }
                return gf::Sub(
                    current[
                        layout.FinalValueLimb(
                            coordinate, 0)],
                    value);
            });
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.final_value_limb_high",
            aq::AirKind::kFirstRow, 1,
            [layout = out.layout, coordinate](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 32;
                     bit < 64; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            gf::FromU64_3(weight),
                            current[
                                layout.FinalValueBit(
                                    coordinate, bit)]));
                    weight <<= 1;
                }
                return gf::Sub(
                    current[
                        layout.FinalValueLimb(
                            coordinate, 1)],
                    value);
            });
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.final_value_recompose",
            aq::AirKind::kFirstRow, 1,
            [layout = out.layout, coordinate](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    current[
                        layout.FinalValue(
                            coordinate)],
                    gf::Add(
                        current[
                            layout.FinalValueLimb(
                                coordinate, 0)],
                        gf::Mul(
                            gf::FromU64_3(
                                uint64_t{1} << 32),
                            current[
                                layout.FinalValueLimb(
                                    coordinate, 1)])));
            });
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.leaf_final_value",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, coordinate](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[layout.leaf_selector],
                    gf::Sub(
                        current[
                            layout.hash.InputPin(
                                coordinate)],
                        current[
                            layout.FinalValue(
                                coordinate)]));
            });
    }

    const uint32_t root_row =
        plan.real_rows - 1;
    const auto& claimed_root =
        batch.fold_layers.back().root;
    for (uint32_t coordinate = 0;
         coordinate <
             kTerminalRootCoordinatesV1;
         ++coordinate) {
        const uint64_t raw =
            gf::Canonical(claimed_root[coordinate]);
        for (uint32_t limb = 0;
             limb < kU32LimbsPerFieldV1;
             ++limb) {
            const uint32_t column =
                out.layout.TerminalRootLimb(
                    coordinate, limb);
            out.columns[column][root_row] =
                gf::FromU64_3(
                    static_cast<uint32_t>(
                        raw >> (32 * limb)));
            const CellRefV1 ref{column, root_row};
            out.abi_consumers.terminal_root[
                coordinate *
                    kU32LimbsPerFieldV1 +
                limb] = ref;
            out.outputs.terminal_root[
                coordinate *
                    kU32LimbsPerFieldV1 +
                limb] = ref;
        }
        WriteU64Bits(
            out.columns,
            out.layout.TerminalRootBit(
                coordinate, 0),
            root_row, raw);
        for (uint32_t bit = 0;
             bit < 64; ++bit) {
            AddConstraint(
                out.cs,
                "stage3.v13_terminal.root_bit",
                aq::AirKind::kEverywhere, 3,
                [layout = out.layout,
                 coordinate, bit](
                    const auto& current,
                    const auto&) {
                    const Fp3 value =
                        current[
                            layout.TerminalRootBit(
                                coordinate, bit)];
                    return gf::Mul(
                        current[
                            layout.root_selector],
                        gf::Mul(
                            value,
                            gf::Sub(
                                value,
                                Fp3::One())));
                });
        }
        for (uint32_t limb = 0;
             limb < kU32LimbsPerFieldV1;
             ++limb) {
            AddConstraint(
                out.cs,
                "stage3.v13_terminal.root_limb",
                aq::AirKind::kEverywhere, 2,
                [layout = out.layout,
                 coordinate, limb](
                    const auto& current,
                    const auto&) {
                    Fp3 value = Fp3::Zero();
                    uint64_t weight = 1;
                    for (uint32_t bit = 0;
                         bit < 32; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                gf::FromU64_3(weight),
                                current[
                                    layout.TerminalRootBit(
                                        coordinate,
                                        limb * 32 + bit)]));
                        weight <<= 1;
                    }
                    return gf::Mul(
                        current[
                            layout.root_selector],
                        gf::Sub(
                            current[
                                layout.TerminalRootLimb(
                                    coordinate, limb)],
                            value));
                });
        }
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.root_recompose",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, coordinate](
                const auto& current,
                const auto&) {
                const Fp3 limbs =
                    gf::Add(
                        current[
                            layout.TerminalRootLimb(
                                coordinate, 0)],
                        gf::Mul(
                            gf::FromU64_3(
                                uint64_t{1} << 32),
                            current[
                                layout.TerminalRootLimb(
                                    coordinate, 1)]));
                return gf::Mul(
                    current[layout.root_selector],
                    gf::Sub(
                        current[
                            layout.hash.OutputPin(
                                coordinate)],
                        limbs));
            });
    }

    std::vector<Fp3> leaf_selector(
        plan.trace_rows, Fp3::Zero());
    std::vector<Fp3> node_selector(
        plan.trace_rows, Fp3::Zero());
    std::vector<Fp3> padding_selector(
        plan.trace_rows, Fp3::Zero());
    std::vector<Fp3> root_selector(
        plan.trace_rows, Fp3::Zero());
    std::vector<Fp3> leaf_index(
        plan.trace_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < plan.trace_rows; ++row) {
        if (row < plan.blowup) {
            leaf_selector[row] = Fp3::One();
            leaf_index[row] =
                gf::FromU64_3(row);
        } else if (row < plan.real_rows) {
            node_selector[row] = Fp3::One();
        } else {
            padding_selector[row] =
                Fp3::One();
        }
    }
    root_selector[root_row] =
        Fp3::One();
    const std::array<
        std::pair<uint32_t, std::vector<Fp3>>, 5>
        public_columns{{
            {out.layout.leaf_selector,
             std::move(leaf_selector)},
            {out.layout.node_selector,
             std::move(node_selector)},
            {out.layout.padding_selector,
             std::move(padding_selector)},
            {out.layout.root_selector,
             std::move(root_selector)},
            {out.layout.leaf_index,
             std::move(leaf_index)},
        }};
    for (const auto& [column, values] :
         public_columns) {
        out.columns[column] = values;
        out.cs.preprocessed.emplace_back(
            column, values);
    }
    AddConstraint(
        out.cs,
        "stage3.v13_terminal.leaf_index",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](
            const auto& current,
            const auto&) {
            return gf::Mul(
                current[layout.leaf_selector],
                gf::Sub(
                    current[
                        layout.hash.InputPin(3)],
                    current[layout.leaf_index]));
        });
    for (uint32_t lane = 4;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        const Fp3 expected =
            lane == 4
            ? Fp3::FromFp(
                  alg_hash::GetAlgHashConstants()
                      .leaf_domain)
            : Fp3::Zero();
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.leaf_constant",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout,
             lane, expected](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        layout.leaf_selector],
                    gf::Sub(
                        current[
                            layout.hash.InputPin(
                                lane)],
                        expected));
            });
    }
    for (uint32_t lane = 8;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        const Fp3 expected =
            lane == 8
            ? Fp3::FromFp(
                  alg_hash::GetAlgHashConstants()
                      .node_domain)
            : Fp3::Zero();
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.node_constant",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout,
             lane, expected](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        layout.node_selector],
                    gf::Sub(
                        current[
                            layout.hash.InputPin(
                                lane)],
                        expected));
            });
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        AddConstraint(
            out.cs,
            "stage3.v13_terminal.padding_zero",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, lane](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        layout.padding_selector],
                    current[
                        layout.hash.InputPin(
                            lane)]);
            });
    }

    for (uint32_t edge = 0;
         edge < edges.size(); ++edge) {
        const EdgeV1& item = edges[edge];
        std::vector<Fp3> source_selector(
            plan.trace_rows, Fp3::Zero());
        std::vector<Fp3> sink_selector(
            plan.trace_rows, Fp3::Zero());
        source_selector[item.source_row] =
            Fp3::One();
        sink_selector[item.sink_row] =
            Fp3::One();
        out.columns[
            out.layout.EdgeSourceSelector(
                edge)] = source_selector;
        out.columns[
            out.layout.EdgeSinkSelector(
                edge)] = sink_selector;
        out.cs.preprocessed.emplace_back(
            out.layout.EdgeSourceSelector(
                edge),
            std::move(source_selector));
        out.cs.preprocessed.emplace_back(
            out.layout.EdgeSinkSelector(
                edge),
            std::move(sink_selector));
        for (uint32_t coordinate = 0;
             coordinate <
                 kTerminalRootCoordinatesV1;
             ++coordinate) {
            const uint32_t carrier =
                out.layout.EdgeCarrier(
                    edge, coordinate);
            out.columns[carrier].assign(
                plan.trace_rows,
                Fp3::FromFp(
                    outputs[item.source_row]
                        [coordinate]));
            AddConstraint(
                out.cs,
                "stage3.v13_terminal.edge_carry",
                aq::AirKind::kTransition, 1,
                [carrier](
                    const auto& current,
                    const auto& next) {
                    return gf::Sub(
                        next[carrier],
                        current[carrier]);
                });
            AddConstraint(
                out.cs,
                "stage3.v13_terminal.edge_source",
                aq::AirKind::kEverywhere, 2,
                [layout = out.layout,
                 edge, coordinate, carrier](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[
                            layout.EdgeSourceSelector(
                                edge)],
                        gf::Sub(
                            current[carrier],
                            current[
                                layout.hash.OutputPin(
                                    coordinate)]));
                });
            AddConstraint(
                out.cs,
                "stage3.v13_terminal.edge_sink",
                aq::AirKind::kEverywhere, 2,
                [layout = out.layout,
                 edge, item,
                 coordinate, carrier](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[
                            layout.EdgeSinkSelector(
                                edge)],
                        gf::Sub(
                            current[carrier],
                            current[
                                layout.hash.InputPin(
                                    item.sink_lane +
                                    coordinate)]));
                });
        }
    }

    out.columns[out.layout.acceptance][0] =
        Fp3::One();
    AddConstraint(
        out.cs,
        "stage3.v13_terminal.acceptance",
        aq::AirKind::kFirstRow, 1,
        [column = out.layout.acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[column], Fp3::One());
        });
    out.outputs.acceptance = {
        out.layout.acceptance, 0};

    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.public_plan_rebuilt =
        SamePlan(plan);
    out.all_hash_inputs_constrained = true;
    out.every_internal_edge_constrained =
        edges.size() ==
            plan.internal_edges;
    out.final_value_decomposition_constrained =
        true;
    out.terminal_root_decomposition_constrained =
        true;
    out.no_proof_values_preprocessed = true;
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        (void)values;
        if (column <
                out.layout.leaf_selector ||
            column ==
                out.layout.acceptance) {
            out.no_proof_values_preprocessed =
                false;
            break;
        }
    }
    out.actual_proof_tape_aliased = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.public_plan_rebuilt &&
        out.all_hash_inputs_constrained &&
        out.every_internal_edge_constrained &&
        out.final_value_decomposition_constrained &&
        out.terminal_root_decomposition_constrained &&
        out.no_proof_values_preprocessed &&
        !out.actual_proof_tape_aliased &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v13_terminal_fold_parent:"
          "terminal_tree_executable;"
          "literal_proof_tape_alias_pending"
        : "stage3:v13_terminal_fold_parent:"
          "product_invalid";
    return out;
}

bool AppendLiteralAliasesV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const std::vector<
        std::pair<CellRefV1, CellRefV1>>& aliases,
    LiteralAliasAttachmentV1& out,
    std::string* why)
{
    out = {};
    if (parent_cs.n_rows < 2 ||
        parent_cs.n_columns !=
            parent_columns.size() ||
        aliases.empty() ||
        !parent_cs.preprocessed_roots.empty() ||
        !parent_cs
             .preprocessed_row_group_roots
             .empty()) {
        return Fail(
            why, "literal_alias_input");
    }
    for (const auto& column :
         parent_columns) {
        if (column.size() !=
            parent_cs.n_rows) {
            return Fail(
                why,
                "literal_alias_parent_shape");
        }
    }
    out.original_columns =
        parent_cs.n_columns;
    const uint32_t carrier_base =
        parent_cs.n_columns;
    const uint32_t selector_base =
        carrier_base +
        static_cast<uint32_t>(
            aliases.size());
    const uint64_t appended64 =
        uint64_t{aliases.size()} * 3;
    if (appended64 >
            std::numeric_limits<uint32_t>::
                max() -
                parent_cs.n_columns) {
        return Fail(
            why, "literal_alias_columns");
    }
    const uint32_t appended =
        static_cast<uint32_t>(
            appended64);
    parent_columns.resize(
        parent_cs.n_columns + appended,
        std::vector<Fp3>(
            parent_cs.n_rows,
            Fp3::Zero()));
    parent_cs.n_columns += appended;
    for (uint32_t ordinal = 0;
         ordinal < aliases.size();
         ++ordinal) {
        const auto [source, sink] =
            aliases[ordinal];
        if (source.column >=
                out.original_columns ||
            sink.column >=
                out.original_columns ||
            source.row >= parent_cs.n_rows ||
            sink.row >= parent_cs.n_rows ||
            IsPreprocessed(
                parent_cs,
                source.column) ||
            IsPreprocessed(
                parent_cs,
                sink.column)) {
            return Fail(
                why,
                "literal_alias_endpoint");
        }
        const uint32_t carrier =
            carrier_base + ordinal;
        const uint32_t source_selector =
            selector_base +
            2 * ordinal;
        const uint32_t sink_selector =
            source_selector + 1;
        const Fp3 value =
            parent_columns[
                source.column][source.row];
        parent_columns[carrier].assign(
            parent_cs.n_rows, value);
        parent_columns[
            source_selector][source.row] =
            Fp3::One();
        parent_columns[
            sink_selector][sink.row] =
            Fp3::One();
        parent_cs.preprocessed.emplace_back(
            source_selector,
            parent_columns[
                source_selector]);
        parent_cs.preprocessed.emplace_back(
            sink_selector,
            parent_columns[
                sink_selector]);
        AddConstraint(
            parent_cs,
            "stage3.v13_terminal_parent.alias_carry",
            aq::AirKind::kTransition, 1,
            [carrier](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[carrier],
                    current[carrier]);
            });
        AddConstraint(
            parent_cs,
            "stage3.v13_terminal_parent.alias_source",
            aq::AirKind::kEverywhere, 2,
            [carrier, source_selector,
             source_column = source.column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[source_selector],
                    gf::Sub(
                        current[carrier],
                        current[source_column]));
            });
        AddConstraint(
            parent_cs,
            "stage3.v13_terminal_parent.alias_sink",
            aq::AirKind::kEverywhere, 2,
            [carrier, sink_selector,
             sink_column = sink.column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[sink_selector],
                    gf::Sub(
                        current[carrier],
                        current[sink_column]));
            });
    }
    out.literal_aliases =
        static_cast<uint32_t>(
            aliases.size());
    out.appended_carriers =
        out.literal_aliases;
    out.constraints =
        3 * out.literal_aliases;
    out.violations =
        CountViolationsV1(
            parent_cs, parent_columns);
    out.endpoints_ordinary = true;
    out.selectors_only_preprocessed =
        true;
    out.cross_row_transport_constrained =
        out.literal_aliases != 0;
    out.global_r0_pending =
        parent_cs
            .preprocessed_row_group_roots
            .empty();
    out.valid =
        out.violations == 0 &&
        out.endpoints_ordinary &&
        out.selectors_only_preprocessed &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending;
    out.note = out.valid
        ? "stage3:v13_terminal_fold_parent:"
          "literal_aliases_appended;"
          "global_r0_pending"
        : "stage3:v13_terminal_fold_parent:"
          "literal_alias_invalid";
    if (!out.valid) {
        return Fail(
            why,
            "literal_alias_violations");
    }
    if (why != nullptr) {
        *why = out.note;
    }
    return true;
}

bool AppendProofTapeAliasesV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const tape::ProductV1& tape_product,
    const composer::ChildAttachmentV1& tape_attachment,
    const ProductV1& terminal_product,
    const composer::ChildAttachmentV1& terminal_attachment,
    ParentAliasAttachmentV1& out,
    std::string* why)
{
    out = {};
    if (!tape_product.valid ||
        !terminal_product.valid ||
        !tape_attachment.valid ||
        !terminal_attachment.valid ||
        tape_attachment.semantic_child_columns !=
            tape_product.cs.n_columns ||
        terminal_attachment.semantic_child_columns !=
            terminal_product.cs.n_columns ||
        parent_cs.n_rows < 2 ||
        parent_cs.n_columns !=
            parent_columns.size() ||
        !parent_cs.preprocessed_roots.empty() ||
        !parent_cs.preprocessed_row_group_roots.empty()) {
        return Fail(why, "alias_input");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "parent_shape");
        }
    }
    out.original_columns = parent_cs.n_columns;
    out.terminal_consumers =
        terminal_product.abi_consumers;
    out.terminal_outputs =
        terminal_product.outputs;
    const auto shift =
        [&terminal_attachment](
            CellRefV1 ref) {
            ref.column =
                terminal_attachment.ParentColumn(
                    ref.column);
            return ref;
        };
    for (auto& ref :
         out.terminal_consumers.final_value) {
        ref = shift(ref);
    }
    for (auto& ref :
         out.terminal_consumers.terminal_root) {
        ref = shift(ref);
    }
    out.terminal_outputs.acceptance =
        shift(out.terminal_outputs.acceptance);
    for (auto& ref :
         out.terminal_outputs.terminal_root) {
        ref = shift(ref);
    }

    std::vector<
        std::pair<CellRefV1, CellRefV1>>
        aliases;
    aliases.reserve(
        kFinalValueLimbsV1 +
        kTerminalRootLimbsV1);
    for (uint32_t coordinate = 0;
         coordinate <
             kFinalValueCoordinatesV1;
         ++coordinate) {
        for (uint32_t limb = 0;
             limb <
                 kU32LimbsPerFieldV1;
             ++limb) {
            const auto source =
                FindTapeCell(
                    tape_product,
                    FinalValueKey(
                        coordinate, limb));
            if (!source.has_value()) {
                return Fail(
                    why, "final_value_source");
            }
            const CellRefV1 source_ref{
                tape_attachment.ParentColumn(
                    source->value_column),
                source->row};
            const uint32_t ordinal =
                coordinate *
                    kU32LimbsPerFieldV1 +
                limb;
            out.tape_final_value[ordinal] =
                source_ref;
            aliases.emplace_back(
                source_ref,
                out.terminal_consumers
                    .final_value[ordinal]);
        }
    }
    for (uint32_t coordinate = 0;
         coordinate <
             kTerminalRootCoordinatesV1;
         ++coordinate) {
        for (uint32_t limb = 0;
             limb <
                 kU32LimbsPerFieldV1;
             ++limb) {
            const auto source =
                FindTapeCell(
                    tape_product,
                    TerminalRootKey(
                        terminal_product.plan
                            .fold_count,
                        coordinate, limb));
            if (!source.has_value()) {
                return Fail(
                    why, "terminal_root_source");
            }
            const CellRefV1 source_ref{
                tape_attachment.ParentColumn(
                    source->value_column),
                source->row};
            const uint32_t ordinal =
                coordinate *
                    kU32LimbsPerFieldV1 +
                limb;
            out.tape_terminal_root[ordinal] =
                source_ref;
            aliases.emplace_back(
                source_ref,
                out.terminal_consumers
                    .terminal_root[ordinal]);
        }
    }

    LiteralAliasAttachmentV1 literal;
    if (!AppendLiteralAliasesV1(
            parent_cs, parent_columns,
            aliases, literal, why)) {
        return false;
    }
    out.appended_carriers =
        literal.appended_carriers;
    out.literal_aliases =
        literal.literal_aliases;
    out.final_value_aliases =
        kFinalValueLimbsV1;
    out.terminal_root_aliases =
        kTerminalRootLimbsV1;
    out.constraints =
        literal.constraints;
    out.violations =
        literal.violations;
    out.actual_tape_value_cells_referenced =
        out.literal_aliases ==
            kFinalValueLimbsV1 +
                kTerminalRootLimbsV1;
    out.actual_terminal_cells_referenced =
        out.actual_tape_value_cells_referenced;
    out.aliases_are_ordinary_columns =
        literal.endpoints_ordinary;
    out.selectors_only_preprocessed =
        literal.selectors_only_preprocessed;
    out.cross_row_transport_constrained =
        literal
            .cross_row_transport_constrained;
    out.global_r0_pending =
        literal.global_r0_pending;
    out.valid =
        out.violations == 0 &&
        out.actual_tape_value_cells_referenced &&
        out.actual_terminal_cells_referenced &&
        out.aliases_are_ordinary_columns &&
        out.selectors_only_preprocessed &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending;
    out.note = out.valid
        ? "stage3:v13_terminal_fold_parent:"
          "literal_proof_tape_aliases_appended;"
          "global_r0_pending"
        : "stage3:v13_terminal_fold_parent:"
          "alias_invalid";
    if (!out.valid) {
        return Fail(why, "alias_violations");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return UINT64_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT64_MAX;
        }
    }
    uint64_t violations = 0;
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
        std::vector<Fp3> current(
            cs.n_columns);
        std::vector<Fp3> next(
            cs.n_columns);
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][
                    row + 1 < cs.n_rows
                    ? row + 1
                    : row];
        }
        for (const auto& constraint :
             cs.constraints) {
            bool applies = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                applies = true;
                break;
            case aq::AirKind::kTransition:
                applies =
                    row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                applies = row == 0;
                break;
            case aq::AirKind::kLastRow:
                applies =
                    row + 1 == cs.n_rows;
                break;
            }
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

} // namespace matmul::v4::rc::stage3_v13_terminal_fold_parent
