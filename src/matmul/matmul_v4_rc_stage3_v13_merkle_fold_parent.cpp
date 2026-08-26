// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_parent.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_v13_terminal_fold_parent.h>

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v13_merkle_fold_parent {
namespace {

using Fp3 = gf::Fp3;
using Fp = gf::Fp;
namespace ar = air_recurse;
namespace cb = constraint_bytecode;

constexpr Fp kOmega2_32 =
    UINT64_C(0x185629dcda58878c);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_merkle_fold_parent:" +
            detail;
    }
    return false;
}

abi::SourceKeyV1 Key(
    abi::FieldKindV1 kind,
    uint32_t a = 0,
    uint32_t b = 0,
    uint32_t c = 0,
    uint32_t d = 0,
    uint8_t limb = 0)
{
    return {kind, a, b, c, d, limb};
}

std::optional<uint32_t> Address(
    const abi::DecodedV1& decoded,
    abi::SourceKeyV1 key)
{
    return abi::FindSourceAddressV1(
        decoded.sources, key);
}

std::optional<std::array<uint32_t, 2>>
FieldCoordinate(
    const abi::DecodedV1& decoded,
    abi::SourceKeyV1 key,
    uint32_t coordinate)
{
    std::array<uint32_t, 2> out{};
    key.d = coordinate;
    for (uint32_t limb = 0; limb < 2; ++limb) {
        key.limb = static_cast<uint8_t>(limb);
        const auto address =
            Address(decoded, key);
        if (!address.has_value()) {
            return std::nullopt;
        }
        out[limb] = *address;
    }
    return out;
}

std::optional<std::vector<uint32_t>>
FieldAddresses(
    const abi::DecodedV1& decoded,
    abi::SourceKeyV1 key,
    uint32_t coordinates)
{
    std::vector<uint32_t> out;
    out.reserve(
        size_t{coordinates} * 2);
    for (uint32_t coordinate = 0;
         coordinate < coordinates;
         ++coordinate) {
        const auto addresses =
            FieldCoordinate(
                decoded, key,
                coordinate);
        if (!addresses.has_value()) {
            return std::nullopt;
        }
        out.push_back((*addresses)[0]);
        out.push_back((*addresses)[1]);
    }
    return out;
}

bool CanonicalAddress(
    const abi::DecodedV1& decoded,
    uint32_t address)
{
    return address < decoded.sources.size() &&
        decoded.sources[address].address == address;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fp PowBase(Fp base, uint64_t exponent)
{
    Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp OmegaForSize(uint32_t size)
{
    if (size < 2 ||
        (size & (size - 1)) != 0) {
        return 0;
    }
    const uint32_t log =
        std::countr_zero(size);
    return PowBase(
        kOmega2_32,
        uint64_t{1} << (32 - log));
}

Fp3 Basis(uint32_t coordinate)
{
    if (coordinate == 0) {
        return {1, 0, 0};
    }
    if (coordinate == 1) {
        return {0, 1, 0};
    }
    return {0, 0, 1};
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

uint32_t BcConstant(
    std::vector<cb::Instruction>& instructions,
    const Fp3& value)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Constant;
    instruction.constant = value;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(
        instructions.size() - 1);
}

uint32_t BcCurrent(
    std::vector<cb::Instruction>& instructions,
    uint32_t column)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Current;
    instruction.lhs = column;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(
        instructions.size() - 1);
}

uint32_t BcNext(
    std::vector<cb::Instruction>& instructions,
    uint32_t column)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Next;
    instruction.lhs = column;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(
        instructions.size() - 1);
}

uint32_t BcBinary(
    std::vector<cb::Instruction>& instructions,
    cb::Opcode opcode,
    uint32_t lhs,
    uint32_t rhs)
{
    cb::Instruction instruction;
    instruction.opcode = opcode;
    instruction.lhs = lhs;
    instruction.rhs = rhs;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(
        instructions.size() - 1);
}

uint32_t BcAdd(
    std::vector<cb::Instruction>& instructions,
    uint32_t lhs,
    uint32_t rhs)
{
    return BcBinary(
        instructions, cb::Opcode::Add,
        lhs, rhs);
}

uint32_t BcSub(
    std::vector<cb::Instruction>& instructions,
    uint32_t lhs,
    uint32_t rhs)
{
    return BcBinary(
        instructions, cb::Opcode::Sub,
        lhs, rhs);
}

uint32_t BcMul(
    std::vector<cb::Instruction>& instructions,
    uint32_t lhs,
    uint32_t rhs)
{
    return BcBinary(
        instructions, cb::Opcode::Mul,
        lhs, rhs);
}

struct PendingCanonicalConstraintV1 {
    uint32_t constraint_index{UINT32_MAX};
    cb::Program program{};
};

cb::Program BcProgram(
    aq::AirKind kind,
    uint32_t degree,
    std::vector<cb::Instruction> instructions)
{
    cb::Program out;
    out.version =
        cb::kConstraintBytecodeVersion;
    out.role =
        RCStage3RelationRole::CompositionLink;
    out.kind = kind;
    out.declared_degree = degree;
    out.instructions =
        std::move(instructions);
    return out;
}

void QueueCanonicalConstraintV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    cb::Program program,
    std::vector<PendingCanonicalConstraintV1>&
        pending)
{
    PendingCanonicalConstraintV1 item;
    item.constraint_index =
        static_cast<uint32_t>(
            cs.constraints.size() - 1U);
    item.program = std::move(program);
    pending.push_back(std::move(item));
}

uint32_t BcRecomposeU32(
    std::vector<cb::Instruction>& instructions,
    uint32_t bit_base)
{
    uint32_t value =
        BcConstant(instructions, Fp3::Zero());
    uint64_t weight = 1;
    for (uint32_t bit = 0; bit < 32; ++bit) {
        value = BcAdd(
            instructions, value,
            BcMul(
                instructions,
                BcConstant(
                    instructions, U(weight)),
                BcCurrent(
                    instructions,
                    bit_base + bit)));
        weight <<= 1;
    }
    return value;
}

struct AffineFormV1 {
    Fp3 constant{};
    std::vector<std::pair<uint32_t, Fp3>>
        terms;
};

AffineFormV1 RecoverPermOutputV1(
    const ar::PermLayout& layout,
    uint32_t lane)
{
    std::vector<Fp3> row(
        layout.End(), Fp3::Zero());
    AffineFormV1 out;
    out.constant =
        ar::PermOutputLane(
            layout, row, lane);
    for (uint32_t column = 0;
         column < layout.End(); ++column) {
        row[column] = Fp3::One();
        const Fp3 coefficient =
            gf::Sub(
                ar::PermOutputLane(
                    layout, row, lane),
                out.constant);
        row[column] = Fp3::Zero();
        if (!gf::IsZero(coefficient)) {
            out.terms.emplace_back(
                column, coefficient);
        }
    }
    return out;
}

uint32_t BcAffine(
    std::vector<cb::Instruction>& instructions,
    const AffineFormV1& form)
{
    uint32_t value =
        BcConstant(
            instructions, form.constant);
    for (const auto& [column, coefficient] :
         form.terms) {
        value = BcAdd(
            instructions, value,
            BcMul(
                instructions,
                BcConstant(
                    instructions,
                    coefficient),
                BcCurrent(
                    instructions, column)));
    }
    return value;
}

bool BuildTypedHashInputProgramV1(
    const HashLaneExpressionV1& expression,
    uint32_t selector,
    uint32_t input,
    uint32_t source_low,
    uint32_t source_high,
    uint32_t prior_column,
    uint32_t derived_column,
    uint32_t select_bit_column,
    cb::Program& out)
{
    out = {};
    out.version =
        cb::kConstraintBytecodeVersion;
    out.role =
        RCStage3RelationRole::CompositionLink;
    out.kind = aq::AirKind::kEverywhere;
    out.declared_degree =
        expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingLeft ||
            expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingRight
        ? 3U
        : 2U;
    auto& instructions = out.instructions;
    const auto current =
        [&instructions](uint32_t column) {
            return BcCurrent(
                instructions, column);
        };
    const auto abi_value =
        [&]() -> std::optional<uint32_t> {
            if (source_low == UINT32_MAX) {
                return std::nullopt;
            }
            const uint32_t low =
                current(source_low);
            if (expression.kind ==
                    HashLaneExpressionKindV1::
                        AbiU32 ||
                expression.kind ==
                    HashLaneExpressionKindV1::
                        PriorOutputPlusAbiU32) {
                return low;
            }
            if (source_high == UINT32_MAX) {
                return std::nullopt;
            }
            return BcAdd(
                instructions, low,
                BcMul(
                    instructions,
                    BcConstant(
                        instructions,
                        U(uint64_t{1} << 32)),
                    current(source_high)));
        };

    uint32_t expected = UINT32_MAX;
    switch (expression.kind) {
    case HashLaneExpressionKindV1::Constant:
        expected =
            BcConstant(
                instructions,
                expression.constant);
        break;
    case HashLaneExpressionKindV1::AbiU32:
    case HashLaneExpressionKindV1::
        AbiFpCoordinate: {
        const auto value = abi_value();
        if (!value.has_value()) return false;
        expected = *value;
        break;
    }
    case HashLaneExpressionKindV1::PriorOutput:
        if (prior_column == UINT32_MAX) {
            return false;
        }
        expected = current(prior_column);
        break;
    case HashLaneExpressionKindV1::
        PriorOutputPlusConstant:
        if (prior_column == UINT32_MAX) {
            return false;
        }
        expected = BcAdd(
            instructions,
            current(prior_column),
            BcConstant(
                instructions,
                expression.constant));
        break;
    case HashLaneExpressionKindV1::
        PriorOutputPlusAbiU32:
    case HashLaneExpressionKindV1::
        PriorOutputPlusAbiFpCoordinate: {
        if (prior_column == UINT32_MAX) {
            return false;
        }
        const auto value = abi_value();
        if (!value.has_value()) return false;
        expected = BcAdd(
            instructions,
            current(prior_column), *value);
        break;
    }
    case HashLaneExpressionKindV1::
        DerivedNextIndex:
        if (derived_column == UINT32_MAX) {
            return false;
        }
        expected = current(derived_column);
        break;
    case HashLaneExpressionKindV1::
        PriorOutputPlusDerivedNextIndex:
        if (prior_column == UINT32_MAX ||
            derived_column == UINT32_MAX) {
            return false;
        }
        expected = BcAdd(
            instructions,
            current(prior_column),
            current(derived_column));
        break;
    case HashLaneExpressionKindV1::
        SelectPriorOrSiblingLeft:
    case HashLaneExpressionKindV1::
        SelectPriorOrSiblingRight: {
        if (prior_column == UINT32_MAX ||
            select_bit_column == UINT32_MAX) {
            return false;
        }
        const auto sibling = abi_value();
        if (!sibling.has_value()) return false;
        const uint32_t prior =
            current(prior_column);
        const uint32_t bit =
            current(select_bit_column);
        expected =
            expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingLeft
            ? BcAdd(
                  instructions, prior,
                  BcMul(
                      instructions, bit,
                      BcSub(
                          instructions,
                          *sibling, prior)))
            : BcAdd(
                  instructions, *sibling,
                  BcMul(
                      instructions, bit,
                      BcSub(
                          instructions,
                          prior, *sibling)));
        break;
    }
    case HashLaneExpressionKindV1::Unresolved:
        return false;
    }
    BcMul(
        instructions,
        current(selector),
        BcSub(
            instructions,
            current(input), expected));
    return true;
}

bool InstallCanonicalConstraintsV1(
    uint32_t n_rows,
    uint32_t n_columns,
    std::vector<PendingCanonicalConstraintV1>& pending,
    aq::AirConstraintSystem<Fp3>& cs,
    std::string* why)
{
    if (pending.empty()) {
        return false;
    }
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = n_columns;
    table.next_width = n_columns;
    table.challenge_width = 0;
    table.programs.reserve(pending.size());
    for (uint32_t ordinal = 0;
         ordinal < pending.size();
         ++ordinal) {
        auto& item = pending[ordinal];
        if (item.constraint_index >=
                cs.constraints.size()) {
            return false;
        }
        item.program.constraint_ordinal =
            ordinal;
        item.program.current_width =
            n_columns;
        item.program.next_width =
            n_columns;
        item.program.challenge_width = 0;
        std::string program_why;
        if (!cb::ValidateProgram(
                item.program,
                &program_why)) {
            if (why != nullptr) {
                *why =
                    "typed_hash_program_" +
                    std::to_string(ordinal) +
                    ":" + program_why;
            }
            return false;
        }
        table.programs.push_back(
            std::move(item.program));
    }
    aq::AirConstraintSystem<Fp3> canonical;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            table, n_rows, canonical, why) ||
        canonical.constraints.size() !=
            pending.size()) {
        return false;
    }
    std::vector<Fp3> differential_current(
        n_columns);
    std::vector<Fp3> differential_next(
        n_columns);
    for (uint32_t column = 0;
         column < n_columns;
         ++column) {
        differential_current[column] =
            Fp3{
                gf::FromU64(
                    1 + uint64_t{17} * column),
                gf::FromU64(
                    3 + uint64_t{29} * column),
                gf::FromU64(
                    5 + uint64_t{43} * column)};
        differential_next[column] =
            Fp3{
                gf::FromU64(
                    7 + uint64_t{47} * column),
                gf::FromU64(
                    11 + uint64_t{53} * column),
                gf::FromU64(
                    13 + uint64_t{61} * column)};
    }
    for (uint32_t ordinal = 0;
         ordinal < pending.size();
         ++ordinal) {
        const uint32_t index =
            pending[ordinal]
                .constraint_index;
        const auto& native =
            cs.constraints[index];
        const auto& rebuilt =
            canonical.constraints[ordinal];
        if (native.kind != rebuilt.kind ||
            native.alg_degree !=
                rebuilt.alg_degree ||
            !gf::Eq(
                native.eval(
                    differential_current,
                    differential_next),
                rebuilt.eval(
                    differential_current,
                    differential_next))) {
            if (why != nullptr) {
                *why =
                    "typed_hash_bytecode_differential_" +
                    std::to_string(ordinal);
            }
            return false;
        }
        auto rebuilt_constraint =
            std::move(
                canonical.constraints[ordinal]);
        rebuilt_constraint.name =
            native.name;
        cs.constraints[index] =
            std::move(rebuilt_constraint);
    }
    return true;
}

bool IsPinColumn(
    const mf::HashLayoutV1& layout,
    uint32_t column)
{
    return
        (column >= layout.input_pin_base &&
         column <
             layout.input_pin_base +
                 alg_hash::kAlgHashT) ||
        (column >= layout.output_pin_base &&
         column <
             layout.output_pin_base +
                 alg_hash::kAlgHashDigestLen);
}

uint64_t SourceValue(
    const abi::DecodedV1& decoded,
    uint32_t address)
{
    return decoded.sources[address].value;
}

HashLaneExpressionV1 ConstantExpression(
    uint32_t row, uint32_t lane,
    Fp3 constant)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::Constant;
    out.constant = constant;
    out.resolved = true;
    return out;
}

HashLaneExpressionV1 AbiU32Expression(
    uint32_t row, uint32_t lane,
    uint32_t address)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::AbiU32;
    out.source_addresses[0] = address;
    out.resolved = true;
    return out;
}

HashLaneExpressionV1 AbiFpExpression(
    uint32_t row, uint32_t lane,
    std::array<uint32_t, 2> addresses)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::
            AbiFpCoordinate;
    out.source_addresses = addresses;
    out.resolved = true;
    return out;
}

HashLaneExpressionV1 PriorExpression(
    uint32_t row, uint32_t lane,
    uint32_t prior_row, uint32_t prior_lane)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::PriorOutput;
    out.prior_task_row = prior_row;
    out.prior_output_lane = prior_lane;
    out.resolved = prior_row < row;
    return out;
}

HashLaneExpressionV1 AddPrior(
    HashLaneExpressionV1 absorbed,
    uint32_t prior_row)
{
    absorbed.prior_task_row = prior_row;
    absorbed.prior_output_lane =
        absorbed.lane;
    switch (absorbed.kind) {
    case HashLaneExpressionKindV1::Constant:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusConstant;
        break;
    case HashLaneExpressionKindV1::AbiU32:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusAbiU32;
        break;
    case HashLaneExpressionKindV1::
        AbiFpCoordinate:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusAbiFpCoordinate;
        break;
    case HashLaneExpressionKindV1::
        DerivedNextIndex:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusDerivedNextIndex;
        break;
    default:
        absorbed.resolved = false;
        break;
    }
    absorbed.resolved =
        absorbed.resolved &&
        prior_row < absorbed.task_row;
    return absorbed;
}

struct AbsorbWordV1 {
    HashLaneExpressionKindV1 kind{
        HashLaneExpressionKindV1::Unresolved};
    std::array<uint32_t, 2> addresses{
        UINT32_MAX, UINT32_MAX};
    uint32_t selector_address{UINT32_MAX};
    Fp3 constant{};
    bool resolved{false};
};

HashLaneExpressionV1 MaterializeWord(
    const AbsorbWordV1& word,
    uint32_t row, uint32_t lane)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind = word.kind;
    out.source_addresses = word.addresses;
    out.selector_address =
        word.selector_address;
    out.constant = word.constant;
    out.resolved = word.resolved;
    return out;
}

std::optional<std::vector<AbsorbWordV1>>
RowLeafWords(
    const abi::DecodedV1& decoded,
    const mf::HashTaskV1& task)
{
    if (task.query >=
            decoded.envelope.split.batch
                .queries.size() ||
        task.group > 4) {
        return std::nullopt;
    }
    std::vector<AbsorbWordV1> out;
    const uint32_t query = task.query;
    uint32_t value_count = 0;
    abi::FieldKindV1 kind{};
    uint32_t group = task.group;
    if (group < 3) {
        value_count = static_cast<uint32_t>(
            decoded.envelope.split.batch
                .queries[query]
                .group_rows[group]
                .values.size());
        kind =
            abi::FieldKindV1::QueryRowValue;
    } else {
        const uint32_t next_group = group - 3;
        if (query >=
                decoded.envelope.split
                    .next_trace_group_rows
                    .size() ||
            next_group >= 2) {
            return std::nullopt;
        }
        value_count = static_cast<uint32_t>(
            decoded.envelope.split
                .next_trace_group_rows[query]
                [next_group].values.size());
        kind =
            abi::FieldKindV1::NextRowValue;
        group = next_group;
    }
    for (uint32_t value = 0;
         value < value_count; ++value) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            const auto addresses =
                FieldCoordinate(
                    decoded,
                    Key(kind, query, group, value),
                    coordinate);
            if (!addresses.has_value()) {
                return std::nullopt;
            }
            AbsorbWordV1 word;
            word.kind =
                HashLaneExpressionKindV1::
                    AbiFpCoordinate;
            word.addresses = *addresses;
            word.resolved = true;
            out.push_back(word);
        }
    }
    const auto query_address =
        Address(
            decoded,
            Key(
                abi::FieldKindV1::QueryIndex,
                query));
    if (!query_address.has_value()) {
        return std::nullopt;
    }
    AbsorbWordV1 index;
    if (task.group < 3) {
        index.kind =
            HashLaneExpressionKindV1::AbiU32;
        index.addresses[0] = *query_address;
    } else {
        index.kind =
            HashLaneExpressionKindV1::
                DerivedNextIndex;
        index.selector_address =
            *query_address;
    }
    index.resolved = true;
    out.push_back(index);
    AbsorbWordV1 delimiter;
    delimiter.kind =
        HashLaneExpressionKindV1::Constant;
    delimiter.constant = Fp3::One();
    delimiter.resolved = true;
    out.push_back(delimiter);
    while (out.size() %
               alg_hash::kAlgHashRate !=
           0) {
        AbsorbWordV1 zero;
        zero.kind =
            HashLaneExpressionKindV1::Constant;
        zero.constant = Fp3::Zero();
        zero.resolved = true;
        out.push_back(zero);
    }
    return out;
}

uint32_t PathIndexAddress(
    const abi::DecodedV1& decoded,
    const mf::HashTaskV1& task)
{
    if (task.group <= 4) {
        const auto address =
            Address(
                decoded,
                Key(
                    abi::FieldKindV1::
                        QueryIndex,
                    task.query));
        return address.value_or(UINT32_MAX);
    }
    if (task.group == 5 ||
        task.group == 6) {
        const auto kind =
            task.group == 5
            ? abi::FieldKindV1::
                  QueryStepEvenIndex
            : abi::FieldKindV1::
                  QueryStepOddIndex;
        const auto address =
            Address(
                decoded,
                Key(
                    kind, task.query,
                    task.fold));
        return address.value_or(UINT32_MAX);
    }
    return UINT32_MAX;
}

bool UsesDerivedNextIndex(
    const mf::HashTaskV1& task)
{
    return task.group == 3 ||
        task.group == 4;
}

} // namespace

TypedHashPlanV1 BuildTypedHashPlanV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    TypedHashPlanV1 out;
    out.task_rows =
        static_cast<uint32_t>(
            shard.hash_tasks.size());
    out.expected_input_lanes =
        out.task_rows * alg_hash::kAlgHashT;
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "hash_plan:" + detail;
            return out;
        };
    if (!decoded.canonical ||
        !decoded.complete ||
        !decoded.addresses_unique ||
        !decoded.semantic_keys_unique ||
        !shard.valid ||
        shard.hash_real_rows !=
            out.task_rows ||
        out.task_rows == 0) {
        return fail("input");
    }

    using PathKey =
        std::tuple<uint32_t, uint32_t, uint32_t>;
    std::map<PathKey, uint32_t>
        last_path_output;
    std::vector<std::vector<uint32_t>>
        terminal_levels(1);
    std::map<uint32_t, uint32_t>
        terminal_node_ordinal;
    std::set<std::pair<uint32_t, uint32_t>>
        lane_owners;
    bool prior_order = true;
    bool addresses_canonical = true;

    const auto append =
        [&](HashLaneExpressionV1 expression) {
            prior_order =
                prior_order &&
                (expression.prior_task_row ==
                     UINT32_MAX ||
                 expression.prior_task_row <
                     expression.task_row);
            for (uint32_t address :
                 expression.source_addresses) {
                if (address != UINT32_MAX) {
                    addresses_canonical =
                        addresses_canonical &&
                        CanonicalAddress(
                            decoded, address);
                }
            }
            if (expression.selector_address !=
                UINT32_MAX) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded,
                        expression
                            .selector_address);
            }
            lane_owners.emplace(
                expression.task_row,
                expression.lane);
            out.resolved_input_lanes +=
                expression.resolved ? 1 : 0;
            out.inputs.push_back(
                std::move(expression));
        };

    for (uint32_t row = 0;
         row < out.task_rows; ++row) {
        const auto& task =
            shard.hash_tasks[row];
        std::array<HashLaneExpressionV1,
                   alg_hash::kAlgHashT>
            expressions;
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashT;
             ++lane) {
            expressions[lane].task_row = row;
            expressions[lane].lane = lane;
        }

        if (task.kind ==
            mf::HashTaskKindV1::RowLeaf) {
            const auto words =
                RowLeafWords(decoded, task);
            if (!words.has_value() ||
                task.level *
                        alg_hash::kAlgHashRate >=
                    words->size()) {
                return fail("row_leaf_words");
            }
            const bool chained =
                task.level != 0;
            if (chained) {
                if (row == 0) {
                    return fail(
                        "row_leaf_prior");
                }
                const auto& prior =
                    shard.hash_tasks[row - 1];
                if (prior.kind !=
                        mf::HashTaskKindV1::
                            RowLeaf ||
                    prior.query != task.query ||
                    prior.group != task.group ||
                    prior.level + 1 !=
                        task.level) {
                    return fail(
                        "row_leaf_chain");
                }
            }
            for (uint32_t lane = 0;
                 lane <
                     alg_hash::kAlgHashRate;
                 ++lane) {
                const uint32_t offset =
                    task.level *
                        alg_hash::kAlgHashRate +
                    lane;
                auto expression =
                    MaterializeWord(
                        (*words)[offset],
                        row, lane);
                if (chained) {
                    expression =
                        AddPrior(
                            std::move(
                                expression),
                            row - 1);
                }
                expressions[lane] =
                    std::move(expression);
            }
            for (uint32_t lane =
                     alg_hash::kAlgHashRate;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                expressions[lane] =
                    chained
                    ? PriorExpression(
                          row, lane,
                          row - 1, lane)
                    : ConstantExpression(
                          row, lane,
                          Fp3::Zero());
            }
            last_path_output[
                PathKey{
                    task.query,
                    task.group,
                    task.fold}] = row;
        } else if (
            task.kind ==
            mf::HashTaskKindV1::FoldLeaf) {
            const bool terminal =
                task.group == 7;
            if (!terminal &&
                task.group > 1) {
                return fail(
                    "fold_leaf_group");
            }
            const auto value_addresses =
                FieldAddresses(
                    decoded,
                    terminal
                    ? Key(
                          abi::FieldKindV1::
                              FinalValue)
                    : Key(
                          task.group == 0
                          ? abi::FieldKindV1::
                                QueryStepEven
                          : abi::FieldKindV1::
                                QueryStepOdd,
                          task.query,
                          task.fold),
                    3);
            if (!value_addresses.has_value()) {
                return fail(
                    "fold_leaf_value_sources");
            }
            std::vector<uint32_t>
                expected_sources =
                    *value_addresses;
            uint32_t index_address =
                UINT32_MAX;
            if (!terminal) {
                const auto index =
                    Address(
                        decoded,
                        Key(
                            task.group == 0
                            ? abi::FieldKindV1::
                                  QueryStepEvenIndex
                            : abi::FieldKindV1::
                                  QueryStepOddIndex,
                            task.query,
                            task.fold));
                if (!index.has_value()) {
                    return fail(
                        "fold_leaf_index_source");
                }
                index_address = *index;
                expected_sources.push_back(
                    index_address);
            }
            if (task.source_addresses !=
                expected_sources) {
                return fail(
                    "fold_leaf_source_schema");
            }
            for (uint32_t coordinate = 0;
                 coordinate < 3;
                 ++coordinate) {
                expressions[coordinate] =
                    AbiFpExpression(
                        row, coordinate,
                        {(*value_addresses)[
                             2 * coordinate],
                         (*value_addresses)[
                             2 * coordinate +
                             1]});
            }
            expressions[3] =
                terminal
                ? ConstantExpression(
                      row, 3,
                      U(terminal_levels[0]
                            .size()))
                : AbiU32Expression(
                      row, 3,
                      index_address);
            expressions[4] =
                ConstantExpression(
                    row, 4,
                    Fp3::FromFp(
                        alg_hash::
                            GetAlgHashConstants()
                            .leaf_domain));
            for (uint32_t lane = 5;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                expressions[lane] =
                    ConstantExpression(
                        row, lane,
                        Fp3::Zero());
            }
            if (terminal) {
                terminal_levels[0]
                    .push_back(row);
            } else {
                // FoldLeaf records use group 0/1 for even/odd, while
                // their MerkleNode consumers use the disjoint path groups
                // 5/6.  Normalize the leaf key to the consumer namespace so
                // an independently valid path cannot be detached from its
                // exact leaf.
                const uint32_t path_group =
                    task.group == 0 ? 5U : 6U;
                last_path_output[
                    PathKey{
                        task.query,
                        path_group,
                        task.fold}] = row;
            }
        } else if (
            task.kind ==
            mf::HashTaskKindV1::
                MerkleNode) {
            if (task.group == 7) {
                const uint32_t level =
                    task.level;
                if (level + 1 >=
                    terminal_levels.size()) {
                    terminal_levels.resize(
                        level + 2);
                }
                const uint32_t ordinal =
                    terminal_node_ordinal[
                        level]++;
                if (2 * ordinal + 1 >=
                    terminal_levels[level]
                        .size()) {
                    return fail(
                        "terminal_tree_edge");
                }
                const uint32_t left =
                    terminal_levels[level]
                        [2 * ordinal];
                const uint32_t right =
                    terminal_levels[level]
                        [2 * ordinal + 1];
                for (uint32_t lane = 0;
                     lane < 4; ++lane) {
                    expressions[lane] =
                        PriorExpression(
                            row, lane,
                            left, lane);
                    expressions[4 + lane] =
                        PriorExpression(
                            row, 4 + lane,
                            right, lane);
                }
                terminal_levels[level + 1]
                    .push_back(row);
                expressions[8] =
                    ConstantExpression(
                        row, 8,
                        Fp3::FromFp(
                            alg_hash::
                                GetAlgHashConstants()
                                .node_domain));
                for (uint32_t lane = 9;
                     lane <
                         alg_hash::kAlgHashT;
                     ++lane) {
                    expressions[lane] =
                        ConstantExpression(
                            row, lane,
                            Fp3::Zero());
                }
                if (task.source_addresses
                        .size() == 8) {
                    const auto root_addresses =
                        FieldAddresses(
                            decoded,
                            Key(
                                abi::FieldKindV1::
                                    FoldRoot,
                                static_cast<uint32_t>(
                                    decoded.envelope
                                        .split.batch
                                        .fold_challenges
                                        .size())),
                            4);
                    if (!root_addresses.has_value() ||
                        task.source_addresses !=
                            *root_addresses) {
                        return fail(
                            "terminal_root_schema");
                    }
                    for (uint32_t lane = 0;
                         lane < 4; ++lane) {
                        out.outputs.push_back({
                            row, lane,
                            {(*root_addresses)[
                                 2 * lane],
                             (*root_addresses)[
                                 2 * lane + 1]}});
                    }
                } else if (
                    !task.source_addresses
                         .empty()) {
                    return fail(
                        "terminal_root_sources");
                }
            } else {
                const PathKey key{
                    task.query,
                    task.group,
                    task.fold};
                const auto prior_it =
                    last_path_output.find(key);
                if (prior_it ==
                    last_path_output.end()) {
                    return fail(
                        "path_prior");
                }
                const uint32_t prior =
                    prior_it->second;
                abi::SourceKeyV1 sibling_key;
                abi::SourceKeyV1 root_key;
                uint32_t path_width = 0;
                const uint64_t n_lde64 =
                    uint64_t{
                        decoded.envelope.split
                            .batch.n_coeffs} *
                    decoded.envelope.split
                        .batch.blowup;
                if (n_lde64 == 0 ||
                    n_lde64 > UINT32_MAX) {
                    return fail(
                        "path_width");
                }
                const uint32_t n_lde =
                    static_cast<uint32_t>(
                        n_lde64);
                if (task.group <= 2) {
                    sibling_key = Key(
                        abi::FieldKindV1::
                            QueryRowSibling,
                        task.query,
                        task.group,
                        task.level);
                    root_key = Key(
                        abi::FieldKindV1::
                            GroupRoot,
                        task.group);
                    path_width = n_lde;
                } else if (
                    task.group <= 4) {
                    sibling_key = Key(
                        abi::FieldKindV1::
                            NextRowSibling,
                        task.query,
                        task.group - 3,
                        task.level);
                    root_key = Key(
                        abi::FieldKindV1::
                            GroupRoot,
                        task.group - 3);
                    path_width = n_lde;
                } else if (
                    task.group <= 6 &&
                    task.fold < 32) {
                    sibling_key = Key(
                        task.group == 5
                        ? abi::FieldKindV1::
                              QueryStepEvenSibling
                        : abi::FieldKindV1::
                              QueryStepOddSibling,
                        task.query,
                        task.fold,
                        task.level);
                    root_key = Key(
                        abi::FieldKindV1::
                            FoldRoot,
                        task.fold);
                    path_width =
                        n_lde >> task.fold;
                } else {
                    return fail(
                        "path_group");
                }
                if (path_width < 2 ||
                    (path_width &
                     (path_width - 1)) != 0) {
                    return fail(
                        "path_width");
                }
                const auto sibling_addresses =
                    FieldAddresses(
                        decoded,
                        sibling_key, 4);
                if (!sibling_addresses
                         .has_value()) {
                    return fail(
                        "path_sibling_schema");
                }
                const uint32_t path_depth =
                    std::countr_zero(
                        path_width);
                const bool final_node =
                    task.level + 1 ==
                        path_depth;
                std::vector<uint32_t>
                    expected_sources =
                        *sibling_addresses;
                std::optional<
                    std::vector<uint32_t>>
                    root_addresses;
                if (final_node) {
                    root_addresses =
                        FieldAddresses(
                            decoded,
                            root_key, 4);
                    if (!root_addresses
                             .has_value()) {
                        return fail(
                            "path_root_schema");
                    }
                    expected_sources.insert(
                        expected_sources.end(),
                        root_addresses->begin(),
                        root_addresses->end());
                }
                if (task.source_addresses !=
                    expected_sources) {
                    return fail(
                        "path_source_schema");
                }
                const uint32_t selector =
                    PathIndexAddress(
                        decoded, task);
                if (selector == UINT32_MAX) {
                    return fail(
                        "path_index");
                }
                for (uint32_t lane = 0;
                     lane < 4; ++lane) {
                    const std::array<uint32_t, 2>
                        sibling{
                            (*sibling_addresses)[
                                2 * lane],
                            (*sibling_addresses)[
                                2 * lane + 1]};
                    auto left =
                        AbiFpExpression(
                            row, lane,
                            sibling);
                    left.kind =
                        HashLaneExpressionKindV1::
                            SelectPriorOrSiblingLeft;
                    left.prior_task_row = prior;
                    left.prior_output_lane = lane;
                    left.selector_address =
                        selector;
                    left.selector_bit =
                        static_cast<uint8_t>(
                            task.level);
                    expressions[lane] =
                        std::move(left);
                    auto right =
                        AbiFpExpression(
                            row, 4 + lane,
                            sibling);
                    right.kind =
                        HashLaneExpressionKindV1::
                            SelectPriorOrSiblingRight;
                    right.prior_task_row =
                        prior;
                    right.prior_output_lane =
                        lane;
                    right.selector_address =
                        selector;
                    right.selector_bit =
                        static_cast<uint8_t>(
                            task.level);
                    expressions[4 + lane] =
                        std::move(right);
                }
                expressions[8] =
                    ConstantExpression(
                        row, 8,
                        Fp3::FromFp(
                            alg_hash::
                                GetAlgHashConstants()
                                .node_domain));
                for (uint32_t lane = 9;
                     lane <
                         alg_hash::kAlgHashT;
                     ++lane) {
                    expressions[lane] =
                        ConstantExpression(
                            row, lane,
                            Fp3::Zero());
                }
                if (final_node) {
                    for (uint32_t lane = 0;
                         lane < 4; ++lane) {
                        out.outputs.push_back({
                            row, lane,
                            {(*root_addresses)[
                                 2 * lane],
                             (*root_addresses)[
                                 2 * lane +
                                 1]}});
                    }
                }
                last_path_output[key] = row;
            }
        } else {
            return fail(
                "unsupported_task_kind");
        }
        for (auto& expression :
             expressions) {
            if (UsesDerivedNextIndex(task) &&
                (expression.kind ==
                     HashLaneExpressionKindV1::
                         SelectPriorOrSiblingLeft ||
                 expression.kind ==
                     HashLaneExpressionKindV1::
                         SelectPriorOrSiblingRight)) {
                // The selector address is still the canonical query
                // index.  The constraint builder derives the next-row
                // index bits before selecting the path orientation.
                expression
                    .selector_is_derived_next =
                    true;
            }
            append(std::move(expression));
        }
    }

    for (const auto& output : out.outputs) {
        addresses_canonical =
            addresses_canonical &&
            output.task_row <
                out.task_rows &&
            output.lane <
                alg_hash::kAlgHashDigestLen &&
            CanonicalAddress(
                decoded,
                output.source_addresses[0]) &&
            CanonicalAddress(
                decoded,
                output.source_addresses[1]);
    }
    out.output_aliases =
        static_cast<uint32_t>(
            out.outputs.size());
    const uint32_t fold_count =
        static_cast<uint32_t>(
            decoded.envelope.split.batch
                .fold_challenges.size());
    out.expected_output_aliases =
        alg_hash::kAlgHashDigestLen *
        (1 +
         shard.query_count *
             (5 + 2 * fold_count));
    out.every_input_lane_resolved =
        out.resolved_input_lanes ==
            out.expected_input_lanes;
    out.every_prior_precedes_consumer =
        prior_order;
    out.every_source_address_canonical =
        addresses_canonical;
    out.lane_ownership_unique =
        lane_owners.size() ==
            out.expected_input_lanes;
    out.output_inventory_complete =
        out.output_aliases ==
            out.expected_output_aliases;
    out.valid =
        out.every_input_lane_resolved &&
        out.every_prior_precedes_consumer &&
        out.every_source_address_canonical &&
        out.lane_ownership_unique &&
        out.output_inventory_complete;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "typed_hash_lane_plan"
        : "stage3:v13_merkle_fold_parent:"
          "hash_plan_incomplete:resolved=" +
              std::to_string(
                  out.resolved_input_lanes) +
              "/" +
              std::to_string(
                  out.expected_input_lanes) +
              ":prior=" +
              std::to_string(
                  out.every_prior_precedes_consumer) +
              ":canonical=" +
              std::to_string(
                  out.every_source_address_canonical) +
              ":unique=" +
              std::to_string(
                  out.lane_ownership_unique) +
              ":outputs=" +
              std::to_string(
                  out.output_aliases) +
              "/" +
              std::to_string(
                  out.expected_output_aliases);
    return out;
}

OrdinaryHashProductV1 BuildOrdinaryHashProductV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    OrdinaryHashProductV1 out;
    out.plan =
        BuildTypedHashPlanV1(
            decoded, shard);
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "ordinary_hash:" + detail;
            return out;
        };
    if (!out.plan.valid ||
        shard.hash_cs.n_rows !=
            shard.hash_trace_rows ||
        shard.hash_columns.size() !=
            shard.hash_cs.n_columns) {
        return fail(
            std::string{"input:"} +
            out.plan.note +
            ":resolved=" +
            std::to_string(
                out.plan.resolved_input_lanes) +
            "/" +
            std::to_string(
                out.plan.expected_input_lanes) +
            ":outputs=" +
            std::to_string(
                out.plan.output_aliases) +
            ":rows=" +
            std::to_string(
                shard.hash_cs.n_rows) +
            "/" +
            std::to_string(
                shard.hash_trace_rows) +
            ":columns=" +
            std::to_string(
                shard.hash_columns.size()) +
            "/" +
            std::to_string(
                shard.hash_cs.n_columns));
    }
    out.cs = shard.hash_cs;
    out.columns = shard.hash_columns;
    const uint32_t first_relation_constraint =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    out.cs.preprocessed.erase(
        std::remove_if(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&shard](const auto& item) {
                return IsPinColumn(
                    shard.hash_layout,
                    item.first);
            }),
    out.cs.preprocessed.end());
    out.cs.preprocessed_pin_ood = false;
    std::vector<PendingCanonicalConstraintV1>
        canonical_constraints;
    canonical_constraints.reserve(
        out.plan.inputs.size() + 1024U);

    const auto append_column =
        [&out](std::vector<Fp3> values) {
            const uint32_t column =
                out.cs.n_columns++;
            out.columns.push_back(
                std::move(values));
            return column;
        };
    const auto constant_column =
        [&out, &append_column](Fp3 value) {
            return append_column(
                std::vector<Fp3>(
                    out.cs.n_rows, value));
        };
    const auto add_public =
        [&out, &append_column](
            std::vector<Fp3> values) {
            const uint32_t column =
                append_column(values);
            out.cs.preprocessed.emplace_back(
                column, std::move(values));
            return column;
        };

    std::set<uint32_t> source_addresses;
    std::set<uint32_t> index_addresses;
    std::set<uint32_t> derived_addresses;
    std::set<std::pair<uint32_t, uint32_t>>
        prior_outputs;
    for (const auto& expression :
         out.plan.inputs) {
        for (uint32_t address :
             expression.source_addresses) {
            if (address != UINT32_MAX) {
                source_addresses.insert(
                    address);
            }
        }
        if (expression.selector_address !=
            UINT32_MAX) {
            source_addresses.insert(
                expression.selector_address);
            index_addresses.insert(
                expression.selector_address);
            if (expression
                    .selector_is_derived_next ||
                expression.kind ==
                    HashLaneExpressionKindV1::
                        DerivedNextIndex ||
                expression.kind ==
                    HashLaneExpressionKindV1::
                        PriorOutputPlusDerivedNextIndex) {
                derived_addresses.insert(
                    expression.selector_address);
            }
        }
        if (expression.prior_task_row !=
            UINT32_MAX) {
            prior_outputs.emplace(
                expression.prior_task_row,
                expression.prior_output_lane);
        }
    }
    for (const auto& alias :
         out.plan.outputs) {
        source_addresses.insert(
            alias.source_addresses[0]);
        source_addresses.insert(
            alias.source_addresses[1]);
    }

    std::map<uint32_t, uint32_t>
        source_columns;
    for (uint32_t address :
         source_addresses) {
        if (!CanonicalAddress(
                decoded, address)) {
            return fail(
                "source_address");
        }
        const uint32_t column =
            constant_column(
                U(SourceValue(
                    decoded, address)));
        source_columns[address] = column;
        out.source_carriers.push_back(
            {address,
             decoded.sources[address].key,
             {column, 0}});
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_source_carry",
            aq::AirKind::kTransition, 1,
            [column](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
        std::vector<cb::Instruction> program;
        BcSub(
            program,
            BcNext(program, column),
            BcCurrent(program, column));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kTransition,
                1, std::move(program)),
            canonical_constraints);
    }

    std::map<uint32_t, uint32_t>
        index_bit_bases;
    for (uint32_t address :
         index_addresses) {
        const uint32_t base =
            out.cs.n_columns;
        index_bit_bases[address] = base;
        const uint32_t raw =
            static_cast<uint32_t>(
                SourceValue(
                    decoded, address));
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t column =
                constant_column(
                    U((raw >> bit) & 1U));
            AddConstraint(
                out.cs,
                "stage3.v13_merkle_fold.hash_index_bit",
                aq::AirKind::kEverywhere, 2,
                [column](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[column],
                        gf::Sub(
                            current[column],
                            Fp3::One()));
                });
            std::vector<cb::Instruction> program;
            const uint32_t value =
                BcCurrent(program, column);
            BcMul(
                program, value,
                BcSub(
                    program, value,
                    BcConstant(
                        program, Fp3::One())));
            QueueCanonicalConstraintV1(
                out.cs,
                BcProgram(
                    aq::AirKind::kEverywhere,
                    2, std::move(program)),
                canonical_constraints);
        }
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_index_recompose",
            aq::AirKind::kEverywhere, 1,
            [base,
             source =
                 source_columns.at(address)](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(weight),
                            current[base + bit]));
                    weight <<= 1;
                }
                return gf::Sub(
                    current[source], value);
            });
        std::vector<cb::Instruction> program;
        BcSub(
            program,
            BcCurrent(program, source_columns.at(address)),
            BcRecomposeU32(program, base));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                1, std::move(program)),
            canonical_constraints);
    }

    struct DerivedIndexV1 {
        uint32_t value{UINT32_MAX};
        uint32_t bit_base{UINT32_MAX};
        uint32_t wrap{UINT32_MAX};
    };
    std::map<uint32_t, DerivedIndexV1>
        derived;
    const auto& split =
        decoded.envelope.split;
    const uint64_t n_lde64 =
        uint64_t{
            split.batch.n_coeffs} *
        split.batch.blowup;
    if (n_lde64 == 0 ||
        n_lde64 > UINT32_MAX ||
        (n_lde64 &
         (n_lde64 - 1)) != 0 ||
        split.trace_rows == 0 ||
        n_lde64 % split.trace_rows != 0) {
        return fail(
            "derived_index_shape");
    }
    const uint32_t n_lde =
        static_cast<uint32_t>(
            n_lde64);
    const uint32_t stride =
        n_lde / split.trace_rows;
    const uint32_t domain_bits =
        std::countr_zero(n_lde);
    for (uint32_t address :
         derived_addresses) {
        const uint32_t query =
            static_cast<uint32_t>(
                SourceValue(
                    decoded, address));
        if (query >= n_lde) {
            return fail(
                "query_out_of_domain");
        }
        const uint64_t sum =
            uint64_t{query} + stride;
        const bool wraps =
            sum >= n_lde;
        const uint32_t next =
            static_cast<uint32_t>(
                wraps
                ? sum - n_lde
                : sum);
        DerivedIndexV1 item;
        item.value =
            constant_column(U(next));
        item.wrap =
            constant_column(
                wraps
                ? Fp3::One()
                : Fp3::Zero());
        item.bit_base =
            out.cs.n_columns;
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t column =
                constant_column(
                    U((next >> bit) & 1U));
            AddConstraint(
                out.cs,
                "stage3.v13_merkle_fold.next_index_bit",
                aq::AirKind::kEverywhere, 2,
                [column](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[column],
                        gf::Sub(
                            current[column],
                            Fp3::One()));
                });
            std::vector<cb::Instruction> bit_program;
            const uint32_t bit_value =
                BcCurrent(
                    bit_program, column);
            BcMul(
                bit_program, bit_value,
                BcSub(
                    bit_program, bit_value,
                    BcConstant(
                        bit_program,
                        Fp3::One())));
            QueueCanonicalConstraintV1(
                out.cs,
                BcProgram(
                    aq::AirKind::kEverywhere,
                    2,
                    std::move(bit_program)),
                canonical_constraints);
            if (bit >= domain_bits) {
                AddConstraint(
                    out.cs,
                    "stage3.v13_merkle_fold.next_index_range",
                    aq::AirKind::kEverywhere, 1,
                    [column](
                        const auto& current,
                        const auto&) {
                        return current[column];
                    });
                std::vector<cb::Instruction>
                    range_program;
                BcCurrent(
                    range_program, column);
                QueueCanonicalConstraintV1(
                    out.cs,
                    BcProgram(
                        aq::AirKind::kEverywhere,
                        1,
                        std::move(range_program)),
                    canonical_constraints);
                const uint32_t query_bit =
                    index_bit_bases.at(
                        address) + bit;
                AddConstraint(
                    out.cs,
                    "stage3.v13_merkle_fold.query_index_range",
                    aq::AirKind::kEverywhere, 1,
                    [query_bit](
                        const auto& current,
                        const auto&) {
                        return current[
                            query_bit];
                    });
                std::vector<cb::Instruction>
                    query_range_program;
                BcCurrent(
                    query_range_program,
                    query_bit);
                QueueCanonicalConstraintV1(
                    out.cs,
                    BcProgram(
                        aq::AirKind::kEverywhere,
                        1,
                        std::move(
                            query_range_program)),
                    canonical_constraints);
            }
        }
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.next_index_recompose",
            aq::AirKind::kEverywhere, 1,
            [item](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(weight),
                            current[
                                item.bit_base +
                                bit]));
                    weight <<= 1;
                }
                return gf::Sub(
                    current[item.value],
                    value);
            });
        std::vector<cb::Instruction>
            recompose_program;
        BcSub(
            recompose_program,
            BcCurrent(
                recompose_program, item.value),
            BcRecomposeU32(
                recompose_program,
                item.bit_base));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                1,
                std::move(recompose_program)),
            canonical_constraints);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.next_index_wrap_boolean",
            aq::AirKind::kEverywhere, 2,
            [column = item.wrap](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[column],
                    gf::Sub(
                        current[column],
                        Fp3::One()));
            });
        std::vector<cb::Instruction> wrap_program;
        const uint32_t wrap_value =
            BcCurrent(
                wrap_program, item.wrap);
        BcMul(
            wrap_program, wrap_value,
            BcSub(
                wrap_program, wrap_value,
                BcConstant(
                    wrap_program,
                    Fp3::One())));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                2, std::move(wrap_program)),
            canonical_constraints);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.next_index_add",
            aq::AirKind::kEverywhere, 1,
            [query =
                 source_columns.at(address),
             item, stride, n_lde](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    gf::Add(
                        current[query],
                        U(stride)),
                    gf::Add(
                        current[item.value],
                        gf::Mul(
                            U(n_lde),
                            current[
                                item.wrap])));
            });
        std::vector<cb::Instruction> add_program;
        BcSub(
            add_program,
            BcAdd(
                add_program,
                BcCurrent(
                    add_program,
                    source_columns.at(address)),
                BcConstant(
                    add_program, U(stride))),
            BcAdd(
                add_program,
                BcCurrent(
                    add_program, item.value),
                BcMul(
                    add_program,
                    BcConstant(
                        add_program, U(n_lde)),
                    BcCurrent(
                        add_program,
                        item.wrap))));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                1, std::move(add_program)),
            canonical_constraints);
        derived[address] = item;
    }

    std::vector<uint32_t> task_selectors(
        out.plan.task_rows);
    for (uint32_t row = 0;
         row < out.plan.task_rows; ++row) {
        std::vector<Fp3> selector(
            out.cs.n_rows, Fp3::Zero());
        selector[row] = Fp3::One();
        task_selectors[row] =
            add_public(std::move(selector));
    }
    std::vector<Fp3> padding_selector(
        out.cs.n_rows, Fp3::Zero());
    for (uint32_t row =
             out.plan.task_rows;
         row < out.cs.n_rows; ++row) {
        padding_selector[row] =
            Fp3::One();
    }
    const uint32_t padding_column =
        add_public(
            std::move(
                padding_selector));

    struct PriorCarrierV1 {
        uint32_t value{UINT32_MAX};
        uint32_t source_selector{
            UINT32_MAX};
    };
    std::map<std::pair<uint32_t, uint32_t>,
             PriorCarrierV1>
        priors;
    for (const auto& key :
         prior_outputs) {
        const uint32_t row{key.first};
        const uint32_t lane{key.second};
        if (row >= out.plan.task_rows ||
            lane >=
                alg_hash::kAlgHashT) {
            return fail(
                "prior_key");
        }
        PriorCarrierV1 item;
        item.value =
            constant_column(
                Fp3::FromFp(
                    shard.hash_tasks[row]
                        .output[lane]));
        std::vector<Fp3> selector(
            out.cs.n_rows, Fp3::Zero());
        selector[row] = Fp3::One();
        item.source_selector =
            add_public(
                std::move(selector));
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.prior_output_carry",
            aq::AirKind::kTransition, 1,
            [column = item.value](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
        std::vector<cb::Instruction> carry_program;
        BcSub(
            carry_program,
            BcNext(carry_program, item.value),
            BcCurrent(
                carry_program, item.value));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kTransition,
                1, std::move(carry_program)),
            canonical_constraints);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.prior_output_source",
            aq::AirKind::kEverywhere, 2,
            [item, lane,
             perm =
                 shard.hash_layout
                     .poseidon.perm](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        item.source_selector],
                    gf::Sub(
                        current[item.value],
                        ar::PermOutputLane(
                            perm, current,
                            lane)));
            });
        std::vector<cb::Instruction> source_program;
        BcMul(
            source_program,
            BcCurrent(
                source_program,
                item.source_selector),
            BcSub(
                source_program,
                BcCurrent(
                    source_program, item.value),
                BcAffine(
                    source_program,
                    RecoverPermOutputV1(
                        shard.hash_layout
                            .poseidon.perm,
                        lane))));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                2, std::move(source_program)),
            canonical_constraints);
        priors[key] = item;
    }

    for (const auto& expression :
         out.plan.inputs) {
        const uint32_t selector =
            task_selectors[
                expression.task_row];
        const uint32_t input =
            shard.hash_layout.InputPin(
                expression.lane);
        const uint32_t source_low =
            expression.source_addresses[0] !=
                UINT32_MAX
            ? source_columns.at(
                  expression
                      .source_addresses[0])
            : UINT32_MAX;
        const uint32_t source_high =
            expression.source_addresses[1] !=
                UINT32_MAX
            ? source_columns.at(
                  expression
                      .source_addresses[1])
            : UINT32_MAX;
        const uint32_t prior_column =
            expression.prior_task_row !=
                UINT32_MAX
            ? priors.at({
                  expression.prior_task_row,
                  expression
                      .prior_output_lane})
                  .value
            : UINT32_MAX;
        const uint32_t derived_column =
            expression.selector_address !=
                    UINT32_MAX &&
                derived.contains(
                    expression
                        .selector_address)
            ? derived.at(
                  expression
                      .selector_address)
                  .value
            : UINT32_MAX;
        uint32_t select_bit_column =
            UINT32_MAX;
        if (expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingLeft ||
            expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingRight) {
            select_bit_column =
                expression
                    .selector_is_derived_next
                ? derived.at(
                      expression
                          .selector_address)
                      .bit_base +
                      expression.selector_bit
                : index_bit_bases.at(
                      expression
                          .selector_address) +
                      expression.selector_bit;
        }
        const uint32_t constraint_index =
            static_cast<uint32_t>(
                out.cs.constraints.size());
        const uint32_t typed_degree =
            expression.kind ==
                    HashLaneExpressionKindV1::
                        SelectPriorOrSiblingLeft ||
                expression.kind ==
                    HashLaneExpressionKindV1::
                        SelectPriorOrSiblingRight
            ? 3U
            : 2U;
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.typed_hash_input",
            aq::AirKind::kEverywhere,
            typed_degree,
            [expression, selector, input,
             source_low, source_high,
             prior_column, derived_column,
             select_bit_column](
                const auto& current,
                const auto&) {
                Fp3 expected =
                    Fp3::Zero();
                const auto abi_value =
                    [&]() {
                        if (expression.kind ==
                                HashLaneExpressionKindV1::
                                    AbiU32 ||
                            expression.kind ==
                                HashLaneExpressionKindV1::
                                    PriorOutputPlusAbiU32) {
                            return current[
                                source_low];
                        }
                        return gf::Add(
                            current[source_low],
                            gf::Mul(
                                U(uint64_t{1}
                                  << 32),
                                current[
                                    source_high]));
                    };
                switch (expression.kind) {
                case HashLaneExpressionKindV1::
                    Constant:
                    expected =
                        expression.constant;
                    break;
                case HashLaneExpressionKindV1::
                    AbiU32:
                case HashLaneExpressionKindV1::
                    AbiFpCoordinate:
                    expected =
                        abi_value();
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutput:
                    expected =
                        current[prior_column];
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutputPlusConstant:
                    expected = gf::Add(
                        current[prior_column],
                        expression.constant);
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutputPlusAbiU32:
                case HashLaneExpressionKindV1::
                    PriorOutputPlusAbiFpCoordinate:
                    expected = gf::Add(
                        current[prior_column],
                        abi_value());
                    break;
                case HashLaneExpressionKindV1::
                    DerivedNextIndex:
                    expected =
                        current[derived_column];
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutputPlusDerivedNextIndex:
                    expected = gf::Add(
                        current[prior_column],
                        current[derived_column]);
                    break;
                case HashLaneExpressionKindV1::
                    SelectPriorOrSiblingLeft:
                case HashLaneExpressionKindV1::
                    SelectPriorOrSiblingRight: {
                    const Fp3 prior =
                        current[prior_column];
                    const Fp3 sibling =
                        abi_value();
                    const Fp3 bit =
                        current[
                            select_bit_column];
                    expected =
                        expression.kind ==
                            HashLaneExpressionKindV1::
                                SelectPriorOrSiblingLeft
                        ? gf::Add(
                              prior,
                              gf::Mul(
                                  bit,
                                  gf::Sub(
                                      sibling,
                                      prior)))
                        : gf::Add(
                              sibling,
                              gf::Mul(
                                  bit,
                                  gf::Sub(
                                      prior,
                                      sibling)));
                    break;
                }
                case HashLaneExpressionKindV1::
                    Unresolved:
                    expected =
                        gf::Add(
                            current[input],
                            Fp3::One());
                    break;
                }
                return gf::Mul(
                    current[selector],
                    gf::Sub(
                        current[input],
                        expected));
            });
        PendingCanonicalConstraintV1 pending;
        pending.constraint_index =
            constraint_index;
        if (!BuildTypedHashInputProgramV1(
                expression, selector, input,
                source_low, source_high,
                prior_column, derived_column,
                select_bit_column,
                pending.program)) {
            return fail(
                "typed_hash_bytecode");
        }
        canonical_constraints.push_back(
            std::move(pending));
    }
    for (const auto& alias :
         out.plan.outputs) {
        const uint32_t selector =
            task_selectors[
                alias.task_row];
        const uint32_t output =
            shard.hash_layout.OutputPin(
                alias.lane);
        const uint32_t low =
            source_columns.at(
                alias.source_addresses[0]);
        const uint32_t high =
            source_columns.at(
                alias.source_addresses[1]);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_root_output",
            aq::AirKind::kEverywhere, 2,
            [selector, output, low, high](
                const auto& current,
                const auto&) {
                const Fp3 expected =
                    gf::Add(
                        current[low],
                        gf::Mul(
                            U(uint64_t{1} << 32),
                            current[high]));
                return gf::Mul(
                    current[selector],
                    gf::Sub(
                        current[output],
                        expected));
            });
        std::vector<cb::Instruction> output_program;
        BcMul(
            output_program,
            BcCurrent(
                output_program, selector),
            BcSub(
                output_program,
                BcCurrent(
                    output_program, output),
                BcAdd(
                    output_program,
                    BcCurrent(
                        output_program, low),
                    BcMul(
                        output_program,
                        BcConstant(
                            output_program,
                            U(uint64_t{1}
                              << 32)),
                        BcCurrent(
                            output_program,
                            high)))));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                2, std::move(output_program)),
            canonical_constraints);
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        const uint32_t input =
            shard.hash_layout.InputPin(lane);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_padding_input",
            aq::AirKind::kEverywhere, 2,
            [padding_column, input](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[padding_column],
                    current[input]);
            });
        std::vector<cb::Instruction> padding_program;
        BcMul(
            padding_program,
            BcCurrent(
                padding_program,
                padding_column),
            BcCurrent(
                padding_program, input));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                2, std::move(padding_program)),
            canonical_constraints);
    }
    const uint32_t acceptance =
        append_column(
            std::vector<Fp3>(
                out.cs.n_rows,
                Fp3::Zero()));
    out.columns[acceptance][0] =
        Fp3::One();
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.hash_acceptance",
        aq::AirKind::kFirstRow, 1,
        [acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                Fp3::One());
        });
    std::vector<cb::Instruction> acceptance_program;
    BcSub(
        acceptance_program,
        BcCurrent(
            acceptance_program, acceptance),
        BcConstant(
            acceptance_program,
            Fp3::One()));
    QueueCanonicalConstraintV1(
        out.cs,
        BcProgram(
            aq::AirKind::kFirstRow,
            1, std::move(acceptance_program)),
        canonical_constraints);
    out.acceptance = {acceptance, 0};
    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    std::string canonical_why;
    if (!InstallCanonicalConstraintsV1(
            out.cs.n_rows, out.cs.n_columns,
            canonical_constraints,
            out.cs, &canonical_why)) {
        return fail(
            "typed_hash_bytecode_install:" +
            canonical_why);
    }
    out.canonical_typed_input_constraints =
        static_cast<uint32_t>(
            out.plan.inputs.size());
    out.typed_inputs_canonical_bytecode =
        out.canonical_typed_input_constraints ==
            out.plan.inputs.size() &&
        canonical_constraints.size() ==
            out.cs.constraints.size() -
                first_relation_constraint;
    out.canonical_relation_constraints =
        static_cast<uint32_t>(
            canonical_constraints.size());
    out.all_relation_constraints_canonical_bytecode =
        out.typed_inputs_canonical_bytecode;
    out.proof_pins_ordinary = true;
    out.selectors_and_constants_only_preprocessed =
        std::none_of(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&shard](const auto& item) {
                return IsPinColumn(
                    shard.hash_layout,
                    item.first);
            });
    out.all_abi_words_exported =
        out.source_carriers.size() ==
            source_addresses.size();
    out.all_prior_edges_constrained =
        priors.size() ==
            prior_outputs.size();
    out.all_output_roots_constrained =
        !out.plan.outputs.empty();
    out.valid =
        out.violations == 0 &&
        out.proof_pins_ordinary &&
        out.selectors_and_constants_only_preprocessed &&
        out.all_abi_words_exported &&
        out.all_prior_edges_constrained &&
        out.all_output_roots_constrained &&
        out.typed_inputs_canonical_bytecode &&
        out.all_relation_constraints_canonical_bytecode;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "ordinary_typed_hash_product"
        : "stage3:v13_merkle_fold_parent:"
          "ordinary_hash_invalid:canonical=" +
              std::to_string(
                  out.canonical_relation_constraints) +
              ":required=" +
              std::to_string(
                  out.cs.constraints.size() -
                  first_relation_constraint) +
              ":violations=" +
              std::to_string(out.violations) +
              ":typed=" +
              std::to_string(
                  out.typed_inputs_canonical_bytecode) +
              ":pins=" +
              std::to_string(out.proof_pins_ordinary) +
              ":pre=" +
              std::to_string(
                  out.selectors_and_constants_only_preprocessed) +
              ":abi=" +
              std::to_string(out.all_abi_words_exported) +
              ":prior=" +
              std::to_string(
                  out.all_prior_edges_constrained) +
              ":roots=" +
              std::to_string(
                  out.all_output_roots_constrained);
    return out;
}

TypedFoldPlanV1 BuildTypedFoldPlanV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    TypedFoldPlanV1 out;
    const auto& batch =
        decoded.envelope.split.batch;
    const uint32_t fold_count =
        static_cast<uint32_t>(
            batch.fold_challenges.size());
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "fold_plan:" + detail;
            return out;
        };
    if (!decoded.canonical ||
        !decoded.complete ||
        !shard.valid ||
        fold_count == 0 ||
        shard.first_query >
            batch.queries.size() ||
        shard.query_count >
            batch.queries.size() -
                shard.first_query) {
        return fail("input");
    }
    out.expected_real_rows =
        shard.query_count * fold_count;
    if (shard.fold_real_rows !=
        out.expected_real_rows) {
        return fail("row_count");
    }
    const uint64_t n_lde64 =
        uint64_t{batch.n_coeffs} *
        batch.blowup;
    if (n_lde64 == 0 ||
        n_lde64 > UINT32_MAX ||
        (n_lde64 &
         (n_lde64 - 1)) != 0) {
        return fail("domain");
    }
    const uint32_t n_lde =
        static_cast<uint32_t>(
            n_lde64);
    bool addresses_canonical = true;
    const auto field6 =
        [&](abi::SourceKeyV1 key,
            std::array<uint32_t, 6>& target) {
            for (uint32_t coordinate = 0;
                 coordinate < 3;
                 ++coordinate) {
                const auto addresses =
                    FieldCoordinate(
                        decoded, key,
                        coordinate);
                if (!addresses.has_value()) {
                    return false;
                }
                target[2 * coordinate] =
                    (*addresses)[0];
                target[
                    2 * coordinate + 1] =
                    (*addresses)[1];
            }
            return true;
        };
    uint32_t row = 0;
    for (uint32_t query =
             shard.first_query;
         query <
             shard.first_query +
                 shard.query_count;
         ++query) {
        for (uint32_t fold = 0;
             fold < fold_count;
             ++fold, ++row) {
            FoldRowSourcePlanV1 item;
            item.row = row;
            item.query = query;
            item.fold = fold;
            if (!field6(
                    Key(
                        abi::FieldKindV1::
                            QueryStepEven,
                        query, fold),
                    item.even) ||
                !field6(
                    Key(
                        abi::FieldKindV1::
                            QueryStepOdd,
                        query, fold),
                    item.odd) ||
                !field6(
                    Key(
                        abi::FieldKindV1::
                            FoldChallenge,
                        fold),
                    item.beta) ||
                !field6(
                    Key(
                        abi::FieldKindV1::
                            FinalValue),
                    item.final_value)) {
                return fail(
                    "field_source");
            }
            const auto index =
                Address(
                    decoded,
                    fold == 0
                    ? Key(
                          abi::FieldKindV1::
                              QueryIndex,
                          query)
                    : Key(
                          abi::FieldKindV1::
                              QueryStepEvenIndex,
                          query, fold - 1));
            const auto even_index =
                Address(
                    decoded,
                    Key(
                        abi::FieldKindV1::
                            QueryStepEvenIndex,
                        query, fold));
            const auto odd_index =
                Address(
                    decoded,
                    Key(
                        abi::FieldKindV1::
                            QueryStepOddIndex,
                        query, fold));
            if (!index.has_value() ||
                !even_index.has_value() ||
                !odd_index.has_value()) {
                return fail(
                    "index_source");
            }
            item.index = *index;
            item.even_index =
                *even_index;
            item.odd_index =
                *odd_index;
            item.half =
                (n_lde >> fold) / 2;
            item.terminal =
                fold + 1 == fold_count;
            for (uint32_t address :
                 item.even) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            for (uint32_t address :
                 item.odd) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            for (uint32_t address :
                 item.beta) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            for (uint32_t address :
                 item.final_value) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            addresses_canonical =
                addresses_canonical &&
                CanonicalAddress(
                    decoded, item.index) &&
                CanonicalAddress(
                    decoded,
                    item.even_index) &&
                CanonicalAddress(
                    decoded,
                    item.odd_index);
            item.valid =
                item.half != 0;
            out.rows.push_back(item);
        }
    }
    out.real_rows = row;
    out.every_source_address_canonical =
        addresses_canonical;
    out.exact_query_fold_schedule =
        out.real_rows ==
            out.expected_real_rows;
    out.valid =
        out.every_source_address_canonical &&
        out.exact_query_fold_schedule &&
        std::all_of(
            out.rows.begin(),
            out.rows.end(),
            [](const auto& item) {
                return item.valid;
            });
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "typed_fold_source_plan"
        : "stage3:v13_merkle_fold_parent:"
          "fold_plan_incomplete";
    return out;
}

OrdinaryFoldProductV1 BuildOrdinaryFoldProductV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    OrdinaryFoldProductV1 out;
    out.plan =
        BuildTypedFoldPlanV1(
            decoded, shard);
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "ordinary_fold:" + detail;
            return out;
        };
    if (!out.plan.valid ||
        shard.fold_cs.n_rows !=
            shard.fold_trace_rows ||
        shard.fold_columns.size() !=
            shard.fold_cs.n_columns) {
        return fail("input");
    }
    out.cs = shard.fold_cs;
    out.columns = shard.fold_columns;
    const uint32_t first_relation_constraint =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    std::vector<PendingCanonicalConstraintV1>
        canonical_constraints;
    canonical_constraints.reserve(1024U);
    const auto& layout =
        shard.fold_layout;
    const std::set<uint32_t>
        public_schedule_columns{
            layout.chain_next,
            layout.terminal,
            layout.half};
    out.cs.preprocessed.erase(
        std::remove_if(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&public_schedule_columns](
                const auto& item) {
                return
                    !public_schedule_columns
                         .contains(
                             item.first);
            }),
        out.cs.preprocessed.end());
    out.cs.preprocessed_pin_ood = false;

    const auto append_column =
        [&out](std::vector<Fp3> values) {
            const uint32_t column =
                out.cs.n_columns++;
            out.columns.push_back(
                std::move(values));
            return column;
        };
    const auto constant_column =
        [&out, &append_column](Fp3 value) {
            return append_column(
                std::vector<Fp3>(
                    out.cs.n_rows, value));
        };
    const auto add_public =
        [&out, &append_column](
            std::vector<Fp3> values) {
            const uint32_t column =
                append_column(values);
            out.cs.preprocessed.emplace_back(
                column, std::move(values));
            return column;
        };

    std::set<uint32_t> addresses;
    for (const auto& row :
         out.plan.rows) {
        addresses.insert(
            row.even.begin(),
            row.even.end());
        addresses.insert(
            row.odd.begin(),
            row.odd.end());
        addresses.insert(
            row.beta.begin(),
            row.beta.end());
        addresses.insert(
            row.final_value.begin(),
            row.final_value.end());
        addresses.insert(row.index);
        addresses.insert(row.even_index);
        addresses.insert(row.odd_index);
    }
    std::map<uint32_t, uint32_t>
        source_columns;
    for (uint32_t address : addresses) {
        if (!CanonicalAddress(
                decoded, address)) {
            return fail(
                "source_address");
        }
        const uint32_t column =
            constant_column(
                U(SourceValue(
                    decoded, address)));
        source_columns[address] = column;
        out.source_carriers.push_back(
            {address,
             decoded.sources[address].key,
             {column, 0}});
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_source_carry",
            aq::AirKind::kTransition, 1,
            [column](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
        std::vector<cb::Instruction> program;
        BcSub(
            program,
            BcNext(program, column),
            BcCurrent(program, column));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kTransition,
                1, std::move(program)),
            canonical_constraints);
    }

    std::vector<uint32_t> row_selectors(
        out.plan.real_rows);
    for (uint32_t row = 0;
         row < out.plan.real_rows;
         ++row) {
        std::vector<Fp3> selector(
            out.cs.n_rows, Fp3::Zero());
        selector[row] = Fp3::One();
        row_selectors[row] =
            add_public(
                std::move(selector));
    }

    const auto field_columns =
        [&source_columns](
            const std::array<uint32_t, 6>&
                source) {
            std::array<uint32_t, 6> out{};
            for (uint32_t index = 0;
                 index < out.size();
                 ++index) {
                out[index] =
                    source_columns.at(
                        source[index]);
            }
            return out;
        };
    for (const auto& row :
         out.plan.rows) {
        const uint32_t selector =
            row_selectors[row.row];
        const auto add_field_alias =
            [&out, selector,
             &field_columns,
             &canonical_constraints](
                uint32_t target,
                const std::array<uint32_t, 6>&
                    source) {
                const auto columns =
                    field_columns(source);
                AddConstraint(
                    out.cs,
                    "stage3.v13_merkle_fold.fold_field_source",
                    aq::AirKind::kEverywhere,
                    2,
                    [selector, target,
                     columns](
                        const auto& current,
                        const auto&) {
                        Fp3 expected =
                            Fp3::Zero();
                        for (uint32_t coordinate =
                                 0;
                             coordinate < 3;
                             ++coordinate) {
                            const Fp3 word =
                                gf::Add(
                                    current[
                                        columns[
                                            2 *
                                            coordinate]],
                                    gf::Mul(
                                        U(uint64_t{1}
                                          << 32),
                                        current[
                                            columns[
                                                2 *
                                                coordinate +
                                                1]]));
                            expected =
                                gf::Add(
                                    expected,
                                    gf::Mul(
                                        Basis(
                                            coordinate),
                                        word));
                        }
                        return gf::Mul(
                            current[selector],
                            gf::Sub(
                                current[target],
                                expected));
                    });
                std::vector<cb::Instruction> program;
                uint32_t expected =
                    BcConstant(
                        program, Fp3::Zero());
                for (uint32_t coordinate = 0;
                     coordinate < 3;
                     ++coordinate) {
                    const uint32_t word =
                        BcAdd(
                            program,
                            BcCurrent(
                                program,
                                columns[
                                    2 * coordinate]),
                            BcMul(
                                program,
                                BcConstant(
                                    program,
                                    U(uint64_t{1}
                                      << 32)),
                                BcCurrent(
                                    program,
                                    columns[
                                        2 *
                                            coordinate +
                                        1])));
                    expected =
                        BcAdd(
                            program, expected,
                            BcMul(
                                program,
                                BcConstant(
                                    program,
                                    Basis(
                                        coordinate)),
                                word));
                }
                BcMul(
                    program,
                    BcCurrent(
                        program, selector),
                    BcSub(
                        program,
                        BcCurrent(
                            program, target),
                        expected));
                QueueCanonicalConstraintV1(
                    out.cs,
                    BcProgram(
                        aq::AirKind::kEverywhere,
                        2, std::move(program)),
                    canonical_constraints);
            };
        add_field_alias(
            layout.even, row.even);
        add_field_alias(
            layout.odd, row.odd);
        add_field_alias(
            layout.beta, row.beta);
        add_field_alias(
            layout.final_value,
            row.final_value);
        const std::array<
            std::pair<uint32_t, uint32_t>, 3>
            u32_aliases{{
                {layout.index, row.index},
                {layout.even_index,
                 row.even_index},
                {layout.odd_index,
                 row.odd_index},
            }};
        for (const auto& alias : u32_aliases) {
            const uint32_t target{alias.first};
            const uint32_t address{alias.second};
            const uint32_t source =
                source_columns.at(address);
            AddConstraint(
                out.cs,
                "stage3.v13_merkle_fold.fold_u32_source",
                aq::AirKind::kEverywhere,
                2,
                [selector, target, source](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[selector],
                        gf::Sub(
                            current[target],
                            current[source]));
                });
            std::vector<cb::Instruction> program;
            BcMul(
                program,
                BcCurrent(program, selector),
                BcSub(
                    program,
                    BcCurrent(program, target),
                    BcCurrent(program, source)));
            QueueCanonicalConstraintV1(
                out.cs,
                BcProgram(
                    aq::AirKind::kEverywhere,
                    2, std::move(program)),
                canonical_constraints);
        }
    }

    const uint32_t bit_base =
        out.cs.n_columns;
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        std::vector<Fp3> values(
            out.cs.n_rows, Fp3::Zero());
        for (const auto& row :
             out.plan.rows) {
            const uint32_t value =
                static_cast<uint32_t>(
                    SourceValue(
                        decoded,
                        row.even_index));
            values[row.row] =
                U((value >> bit) & 1U);
        }
        const uint32_t column =
            append_column(
                std::move(values));
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_index_bit",
            aq::AirKind::kEverywhere, 2,
            [column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[column],
                    gf::Sub(
                        current[column],
                        Fp3::One()));
            });
        std::vector<cb::Instruction> program;
        const uint32_t value =
            BcCurrent(program, column);
        BcMul(
            program, value,
            BcSub(
                program, value,
                BcConstant(
                    program, Fp3::One())));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                2, std::move(program)),
            canonical_constraints);
    }
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_index_recompose",
        aq::AirKind::kEverywhere, 1,
        [bit_base, index = layout.even_index](
            const auto& current,
            const auto&) {
            Fp3 expected = Fp3::Zero();
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < 32; ++bit) {
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        U(weight),
                        current[
                            bit_base + bit]));
                weight <<= 1;
            }
            return gf::Sub(
                current[index], expected);
        });
    std::vector<cb::Instruction> recompose_program;
    BcSub(
        recompose_program,
        BcCurrent(
            recompose_program,
            layout.even_index),
        BcRecomposeU32(
            recompose_program, bit_base));
    QueueCanonicalConstraintV1(
        out.cs,
        BcProgram(
            aq::AirKind::kEverywhere,
            1, std::move(recompose_program)),
        canonical_constraints);

    const uint32_t power_base =
        out.cs.n_columns;
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        std::vector<Fp3> values(
            out.cs.n_rows, Fp3::One());
        for (const auto& row :
             out.plan.rows) {
            const uint32_t width =
                row.half * 2;
            const Fp omega =
                OmegaForSize(width);
            if (omega == 0) {
                return fail(
                    "omega");
            }
            values[row.row] =
                Fp3::FromFp(
                    PowBase(
                        omega,
                        uint64_t{1}
                            << bit));
        }
        add_public(std::move(values));
    }
    const uint32_t allowed_base =
        out.cs.n_columns;
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        std::vector<Fp3> values(
            out.cs.n_rows, Fp3::Zero());
        for (const auto& row :
             out.plan.rows) {
            const uint32_t bits =
                std::countr_zero(
                    row.half);
            values[row.row] =
                bit < bits
                ? Fp3::One()
                : Fp3::Zero();
        }
        add_public(std::move(values));
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_index_range",
            aq::AirKind::kEverywhere, 2,
            [bit_column =
                 bit_base + bit,
             allowed_column =
                 allowed_base + bit](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[bit_column],
                    gf::Sub(
                        Fp3::One(),
                        current[
                            allowed_column]));
            });
        std::vector<cb::Instruction> program;
        BcMul(
            program,
            BcCurrent(
                program, bit_base + bit),
            BcSub(
                program,
                BcConstant(
                    program, Fp3::One()),
                BcCurrent(
                    program,
                    allowed_base + bit)));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                2, std::move(program)),
            canonical_constraints);
    }

    const uint32_t accumulator_base =
        out.cs.n_columns;
    std::array<std::vector<Fp3>, 33>
        accumulator_values;
    for (auto& values :
         accumulator_values) {
        values.assign(
            out.cs.n_rows,
            Fp3::One());
    }
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        Fp3 accumulator = Fp3::One();
        accumulator_values[0][row] =
            accumulator;
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const Fp3 selected =
                out.columns[
                    bit_base + bit][row];
            const Fp3 power =
                out.columns[
                    power_base + bit][row];
            accumulator = gf::Mul(
                accumulator,
                gf::Add(
                    Fp3::One(),
                    gf::Mul(
                        selected,
                        gf::Sub(
                            power,
                            Fp3::One()))));
            accumulator_values[
                bit + 1][row] =
                accumulator;
        }
    }
    for (uint32_t step = 0;
         step <= 32; ++step) {
        append_column(
            std::move(
                accumulator_values[step]));
    }
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_x_acc_start",
        aq::AirKind::kEverywhere, 1,
        [column = accumulator_base](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[column],
                Fp3::One());
        });
    std::vector<cb::Instruction> start_program;
    BcSub(
        start_program,
        BcCurrent(
            start_program, accumulator_base),
        BcConstant(
            start_program, Fp3::One()));
    QueueCanonicalConstraintV1(
        out.cs,
        BcProgram(
            aq::AirKind::kEverywhere,
            1, std::move(start_program)),
        canonical_constraints);
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_x_acc_step",
            aq::AirKind::kEverywhere, 3,
            [bit_column =
                 bit_base + bit,
             power_column =
                 power_base + bit,
             current_acc =
                 accumulator_base + bit,
             next_acc =
                 accumulator_base + bit + 1](
                const auto& current,
                const auto&) {
                const Fp3 factor =
                    gf::Add(
                        Fp3::One(),
                        gf::Mul(
                            current[
                                bit_column],
                            gf::Sub(
                                current[
                                    power_column],
                                Fp3::One())));
                return gf::Sub(
                    current[next_acc],
                    gf::Mul(
                        current[
                            current_acc],
                        factor));
            });
        std::vector<cb::Instruction> program;
        const uint32_t factor =
            BcAdd(
                program,
                BcConstant(
                    program, Fp3::One()),
                BcMul(
                    program,
                    BcCurrent(
                        program,
                        bit_base + bit),
                    BcSub(
                        program,
                        BcCurrent(
                            program,
                            power_base + bit),
                        BcConstant(
                            program,
                            Fp3::One()))));
        BcSub(
            program,
            BcCurrent(
                program,
                accumulator_base +
                    bit + 1),
            BcMul(
                program,
                BcCurrent(
                    program,
                    accumulator_base + bit),
                factor));
        QueueCanonicalConstraintV1(
            out.cs,
            BcProgram(
                aq::AirKind::kEverywhere,
                3, std::move(program)),
            canonical_constraints);
    }
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_x_bind",
        aq::AirKind::kEverywhere, 1,
        [x = layout.x,
         final_acc =
             accumulator_base + 32](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[x],
                current[final_acc]);
        });
    std::vector<cb::Instruction> bind_program;
    BcSub(
        bind_program,
        BcCurrent(
            bind_program, layout.x),
        BcCurrent(
            bind_program,
            accumulator_base + 32));
    QueueCanonicalConstraintV1(
        out.cs,
        BcProgram(
            aq::AirKind::kEverywhere,
            1, std::move(bind_program)),
        canonical_constraints);

    const uint32_t acceptance =
        append_column(
            std::vector<Fp3>(
                out.cs.n_rows,
                Fp3::Zero()));
    out.columns[acceptance][0] =
        Fp3::One();
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_acceptance",
        aq::AirKind::kFirstRow, 1,
        [acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                Fp3::One());
        });
    std::vector<cb::Instruction> acceptance_program;
    BcSub(
        acceptance_program,
        BcCurrent(
            acceptance_program, acceptance),
        BcConstant(
            acceptance_program,
            Fp3::One()));
    QueueCanonicalConstraintV1(
        out.cs,
        BcProgram(
            aq::AirKind::kFirstRow,
            1, std::move(acceptance_program)),
        canonical_constraints);
    out.acceptance = {acceptance, 0};

    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.fold_chain_constrained =
        std::any_of(
            out.cs.constraints.begin(),
            out.cs.constraints.end(),
            [](const auto& constraint) {
                return constraint.name ==
                    "stage3.v11_merkle_fold.chain";
            });
    std::string canonical_why;
    if (!InstallCanonicalConstraintsV1(
            out.cs.n_rows, out.cs.n_columns,
            canonical_constraints,
            out.cs, &canonical_why) ||
        canonical_constraints.size() !=
            out.cs.constraints.size() -
                first_relation_constraint) {
        return fail(
            "fold_bytecode_install:" +
            canonical_why);
    }
    out.canonical_relation_constraints =
        static_cast<uint32_t>(
            canonical_constraints.size());
    out.all_relation_constraints_canonical_bytecode =
        out.canonical_relation_constraints ==
            out.cs.constraints.size() -
                first_relation_constraint;
    out.proof_pins_ordinary = true;
    out.schedule_only_preprocessed =
        std::all_of(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&public_schedule_columns,
             first_new =
                 shard.fold_cs.n_columns](
                const auto& item) {
                return
                    public_schedule_columns
                        .contains(item.first) ||
                    item.first >= first_new;
            });
    out.all_abi_words_exported =
        out.source_carriers.size() ==
            addresses.size();
    out.index_bits_constrained = true;
    out.domain_point_exponentiation_constrained =
        true;
    out.valid =
        out.violations == 0 &&
        out.proof_pins_ordinary &&
        out.schedule_only_preprocessed &&
        out.all_abi_words_exported &&
        out.index_bits_constrained &&
        out.domain_point_exponentiation_constrained &&
        out.fold_chain_constrained &&
        out.all_relation_constraints_canonical_bytecode;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "ordinary_typed_fold_product"
        : "stage3:v13_merkle_fold_parent:"
          "ordinary_fold_invalid";
    return out;
}

namespace {

uint32_t Log2ExactPublic(uint32_t value)
{
    if (value == 0 ||
        (value & (value - 1)) != 0) {
        return UINT32_MAX;
    }
    return std::countr_zero(value);
}

Fri3AlgRowOpening PublicDummyRow(
    uint32_t values, uint32_t depth)
{
    Fri3AlgRowOpening out;
    out.values.resize(values, Fp3::Zero());
    out.siblings.resize(depth);
    return out;
}

abi::DecodedV1 StructuralDecoded(
    const tape::PublicShapeV1& shape,
    const tape::ScheduleV1& schedule)
{
    abi::DecodedV1 out;
    out.envelope.trace_columns =
        shape.trace_columns;
    out.envelope.quotient_len =
        shape.quotient_len;
    auto& split = out.envelope.split;
    split.version =
        aq::kAirQuotientSplitRapRowsSafeProofVersionV2;
    split.trace_rows = shape.trace_rows;
    split.base_column_indices =
        shape.base_column_indices;
    auto& batch = split.batch;
    batch.version =
        kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13;
    batch.blowup = kRCFriBlowup;
    batch.n_coeffs = shape.n_coeffs;
    const uint32_t n_lde =
        shape.n_coeffs * kRCFriBlowup;
    const uint32_t main =
        static_cast<uint32_t>(
            shape.base_column_indices.size());
    const uint32_t auxiliary =
        shape.trace_columns - main;
    const uint32_t row_depth =
        Log2ExactPublic(n_lde);
    const uint32_t folds =
        Log2ExactPublic(shape.n_coeffs);
    if (row_depth == UINT32_MAX ||
        folds == UINT32_MAX) {
        return {};
    }
    batch.groups.resize(3);
    batch.groups[0].role =
        Fri3AlgMultiRowGroupRole::MainTrace;
    batch.groups[0].first_column = 0;
    batch.groups[0].column_count = main;
    batch.groups[0].row_commit.n_leaves =
        n_lde;
    batch.groups[1].role =
        Fri3AlgMultiRowGroupRole::AuxiliaryTrace;
    batch.groups[1].first_column = main;
    batch.groups[1].column_count =
        auxiliary;
    batch.groups[1].row_commit.n_leaves =
        n_lde;
    batch.groups[2].role =
        Fri3AlgMultiRowGroupRole::Quotient;
    batch.groups[2].first_column =
        shape.trace_columns;
    batch.groups[2].column_count = 1;
    batch.groups[2].row_commit.n_leaves =
        n_lde;
    batch.column_len.assign(
        shape.trace_columns,
        shape.trace_rows);
    batch.column_len.push_back(
        shape.quotient_len);
    batch.evals_z1.resize(
        shape.trace_columns + 1);
    batch.evals_z2.resize(
        shape.trace_columns + 1);
    batch.fold_layers.resize(folds + 1);
    batch.fold_challenges.resize(folds);
    for (uint32_t fold = 0;
         fold <= folds; ++fold) {
        batch.fold_layers[fold].n_leaves =
            n_lde >> fold;
    }
    batch.queries.resize(
        abi::kQueryCountV11);
    split.next_trace_group_rows.resize(
        abi::kQueryCountV11);
    for (uint32_t query = 0;
         query < abi::kQueryCountV11;
         ++query) {
        auto& item = batch.queries[query];
        item.group_rows = {
            PublicDummyRow(main, row_depth),
            PublicDummyRow(auxiliary, row_depth),
            PublicDummyRow(1, row_depth),
        };
        item.steps.resize(folds);
        uint32_t index = 0;
        for (uint32_t fold = 0;
             fold < folds; ++fold) {
            const uint32_t half =
                (n_lde >> fold) / 2;
            auto& step = item.steps[fold];
            step.even_index = index % half;
            step.odd_index =
                step.even_index + half;
            step.even_siblings.resize(
                row_depth - fold);
            step.odd_siblings.resize(
                row_depth - fold);
            index %= half;
        }
        split.next_trace_group_rows[query] = {
            PublicDummyRow(main, row_depth),
            PublicDummyRow(auxiliary, row_depth),
        };
    }
    out.sources = schedule.semantic_sources;
    out.canonical = true;
    out.complete = true;
    out.addresses_unique = true;
    out.semantic_keys_unique = true;
    return out;
}

bool AppendStructuralTaskSchedule(
    const abi::DecodedV1& decoded,
    const unified::MerkleFoldPublicPlanV1&
        plan,
    std::vector<mf::HashTaskV1>& tasks,
    std::string* why)
{
    tasks.clear();
    const auto add =
        [&tasks](
            mf::HashTaskKindV1 kind,
            uint32_t query,
            uint32_t group,
            uint32_t fold,
            uint32_t level,
            std::vector<uint32_t> sources = {}) {
            mf::HashTaskV1 task;
            task.kind = kind;
            task.query = query;
            task.group = group;
            task.fold = fold;
            task.level = level;
            task.source_addresses =
                std::move(sources);
            tasks.push_back(
                std::move(task));
        };
    const auto field =
        [&decoded](
            abi::FieldKindV1 kind,
            uint32_t a = 0,
            uint32_t b = 0,
            uint32_t c = 0,
            uint32_t coordinates = 3) {
            return FieldAddresses(
                decoded,
                Key(kind, a, b, c),
                coordinates);
        };
    const auto u32 =
        [&decoded](
            abi::FieldKindV1 kind,
            uint32_t a = 0,
            uint32_t b = 0) {
            return Address(
                decoded,
                Key(kind, a, b));
        };
    const uint32_t folds =
        plan.shape.fold_count;
    const uint32_t depth =
        plan.shape.row_depth;
    const uint32_t blowup =
        plan.shape.blowup;
    const auto final_value =
        field(abi::FieldKindV1::FinalValue);
    if (!final_value.has_value()) {
        return Fail(
            why, "public_final_value_schedule");
    }
    for (uint32_t index = 0;
         index < blowup; ++index) {
        add(
            mf::HashTaskKindV1::FoldLeaf,
            plan.range.first_query, 7,
            folds, 0, *final_value);
    }
    uint32_t width = blowup;
    for (uint32_t level = 0;
         width > 1;
         ++level, width >>= 1) {
        for (uint32_t node = 0;
             node < width / 2;
             ++node) {
            std::vector<uint32_t> sources;
            if (width == 2) {
                const auto root =
                    field(
                        abi::FieldKindV1::
                            FoldRoot,
                        folds, 0, 0, 4);
                if (!root.has_value()) {
                    return Fail(
                        why,
                        "public_terminal_root_schedule");
                }
                sources = *root;
            }
            add(
                mf::HashTaskKindV1::
                    MerkleNode,
                plan.range.first_query,
                7, folds, level,
                std::move(sources));
        }
    }

    const auto append_row_leaf =
        [&](uint32_t query,
            uint32_t group,
            uint32_t values) {
            const uint64_t words =
                uint64_t{3} * values + 2;
            const uint32_t blocks =
                static_cast<uint32_t>(
                    (words +
                     alg_hash::kAlgHashRate -
                     1) /
                    alg_hash::kAlgHashRate);
            for (uint32_t block = 0;
                 block < blocks; ++block) {
                add(
                    mf::HashTaskKindV1::
                        RowLeaf,
                    query, group, 0, block);
            }
        };
    const auto append_path =
        [&](uint32_t query,
            uint32_t group,
            uint32_t fold,
            uint32_t path_depth) {
            for (uint32_t level = 0;
                 level < path_depth;
                 ++level) {
                std::optional<
                    std::vector<uint32_t>>
                    sibling;
                if (group <= 2) {
                    sibling = field(
                        abi::FieldKindV1::
                            QueryRowSibling,
                        query, group, level, 4);
                } else if (group <= 4) {
                    sibling = field(
                        abi::FieldKindV1::
                            NextRowSibling,
                        query, group - 3,
                        level, 4);
                } else {
                    sibling = field(
                        group == 5
                        ? abi::FieldKindV1::
                              QueryStepEvenSibling
                        : abi::FieldKindV1::
                              QueryStepOddSibling,
                        query, fold, level, 4);
                }
                if (!sibling.has_value()) {
                    return false;
                }
                std::vector<uint32_t>
                    sources = *sibling;
                if (level + 1 ==
                    path_depth) {
                    const auto root =
                        group <= 4
                        ? field(
                              abi::FieldKindV1::
                                  GroupRoot,
                              group <= 2
                                  ? group
                                  : group - 3,
                              0, 0, 4)
                        : field(
                              abi::FieldKindV1::
                                  FoldRoot,
                              fold, 0, 0, 4);
                    if (!root.has_value()) {
                        return false;
                    }
                    sources.insert(
                        sources.end(),
                        root->begin(),
                        root->end());
                }
                add(
                    mf::HashTaskKindV1::
                        MerkleNode,
                    query, group, fold,
                    level,
                    std::move(sources));
            }
            return true;
        };
    for (uint32_t query =
             plan.range.first_query;
         query <
             plan.range.first_query +
                 plan.range.query_count;
         ++query) {
        for (uint32_t group = 0;
             group < 3; ++group) {
            append_row_leaf(
                query, group,
                plan.shape
                    .group_columns[group]);
            if (!append_path(
                    query, group, 0,
                    depth)) {
                return Fail(
                    why,
                    "public_current_path_schedule");
            }
        }
        for (uint32_t group = 0;
             group < 2; ++group) {
            append_row_leaf(
                query, group + 3,
                plan.shape
                    .group_columns[group]);
            if (!append_path(
                    query, group + 3, 0,
                    depth)) {
                return Fail(
                    why,
                    "public_next_path_schedule");
            }
        }
        for (uint32_t fold = 0;
             fold < folds; ++fold) {
            const auto even =
                field(
                    abi::FieldKindV1::
                        QueryStepEven,
                    query, fold);
            const auto odd =
                field(
                    abi::FieldKindV1::
                        QueryStepOdd,
                    query, fold);
            const auto even_index =
                u32(
                    abi::FieldKindV1::
                        QueryStepEvenIndex,
                    query, fold);
            const auto odd_index =
                u32(
                    abi::FieldKindV1::
                        QueryStepOddIndex,
                    query, fold);
            if (!even.has_value() ||
                !odd.has_value() ||
                !even_index.has_value() ||
                !odd_index.has_value()) {
                return Fail(
                    why,
                    "public_fold_leaf_schedule");
            }
            auto even_sources = *even;
            even_sources.push_back(
                *even_index);
            add(
                mf::HashTaskKindV1::
                    FoldLeaf,
                query, 0, fold, 0,
                std::move(even_sources));
            auto odd_sources = *odd;
            odd_sources.push_back(
                *odd_index);
            add(
                mf::HashTaskKindV1::
                    FoldLeaf,
                query, 1, fold, 0,
                std::move(odd_sources));
            const uint32_t path_depth =
                depth - fold;
            if (!append_path(
                    query, 5, fold,
                    path_depth) ||
                !append_path(
                    query, 6, fold,
                    path_depth)) {
                return Fail(
                    why,
                    "public_fold_path_schedule");
            }
        }
    }
    if (tasks.size() !=
            plan.hash_real_rows) {
        return Fail(
            why,
            "public_hash_row_count");
    }
    return true;
}

mf::ShardProductV1 StructuralShard(
    const abi::DecodedV1& decoded,
    const unified::MerkleFoldPublicPlanV1&
        plan,
    std::string* why)
{
    mf::ShardProductV1 out;
    out.first_query =
        plan.range.first_query;
    out.query_count =
        plan.range.query_count;
    out.hash_real_rows =
        plan.hash_real_rows;
    out.hash_trace_rows =
        plan.hash_trace_rows;
    out.fold_real_rows =
        plan.fold_real_rows;
    out.fold_trace_rows =
        plan.fold_trace_rows;
    out.hash_layout =
        plan.hash_layout;
    out.fold_layout =
        plan.fold_layout;
    out.hash_cs = plan.hash_cs;
    out.fold_cs = plan.fold_cs;
    out.hash_columns.assign(
        out.hash_cs.n_columns,
        std::vector<Fp3>(
            out.hash_cs.n_rows,
            Fp3::Zero()));
    out.fold_columns.assign(
        out.fold_cs.n_columns,
        std::vector<Fp3>(
            out.fold_cs.n_rows,
            Fp3::Zero()));
    if (!AppendStructuralTaskSchedule(
            decoded, plan,
            out.hash_tasks, why)) {
        return {};
    }
    for (uint32_t row = 0;
         row < out.fold_real_rows;
         ++row) {
        const uint32_t fold =
            row % plan.shape.fold_count;
        out.fold_columns[
            out.fold_layout.half][row] =
            U(
                (plan.shape.n_lde >>
                 fold) /
                2);
        const bool terminal =
            fold + 1 ==
                plan.shape.fold_count;
        out.fold_columns[
            out.fold_layout.chain_next][row] =
            terminal
            ? Fp3::Zero()
            : Fp3::One();
        out.fold_columns[
            out.fold_layout.terminal][row] =
            terminal
            ? Fp3::One()
            : Fp3::Zero();
    }
    for (uint32_t column :
         {out.fold_layout.chain_next,
          out.fold_layout.terminal,
          out.fold_layout.half}) {
        out.fold_cs.preprocessed.push_back(
            {column,
             out.fold_columns[column]});
    }
    out.fold_cs.preprocessed_pin_ood = true;
    out.canonical_abi = true;
    out.valid = true;
    return out;
}

bool SameFp3Vector(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t i = 0;
         i < left.size(); ++i) {
        if (!gf::Eq(left[i], right[i])) {
            return false;
        }
    }
    return true;
}

bool SameConstraintSystemStructure(
    const aq::AirConstraintSystem<Fp3>& left,
    const aq::AirConstraintSystem<Fp3>& right)
{
    if (left.n_rows != right.n_rows ||
        left.n_columns != right.n_columns ||
        left.constraints.size() !=
            right.constraints.size() ||
        left.preprocessed.size() !=
            right.preprocessed.size() ||
        left.preprocessed_roots !=
            right.preprocessed_roots ||
        left.preprocessed_pin_ood !=
            right.preprocessed_pin_ood ||
        left.preprocessed_row_group_roots !=
            right.preprocessed_row_group_roots) {
        return false;
    }
    for (uint32_t i = 0;
         i < left.constraints.size(); ++i) {
        if (left.constraints[i].name !=
                right.constraints[i].name ||
            left.constraints[i].kind !=
                right.constraints[i].kind ||
            left.constraints[i].alg_degree !=
                right.constraints[i].alg_degree) {
            return false;
        }
    }
    for (uint32_t i = 0;
         i < left.preprocessed.size(); ++i) {
        if (left.preprocessed[i].first !=
                right.preprocessed[i].first ||
            !SameFp3Vector(
                left.preprocessed[i].second,
                right.preprocessed[i].second)) {
            return false;
        }
    }
    return true;
}

} // namespace

bool BuildPublicConstraintSystemsV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& binding,
    const rv::QueryRangeV1& range,
    PublicConstraintSystemsV1& out,
    std::string* why)
{
    out = {};
    const auto schedule =
        tape::BuildScheduleV1(
            shape, binding);
    if (!schedule.valid) {
        return Fail(
            why,
            "public_tape_schedule");
    }
    const auto decoded =
        StructuralDecoded(
            shape, schedule);
    out.canonical_shape =
        unified::
            BuildMerkleFoldPublicShapeV1(
                decoded);
    out.canonical_plan =
        unified::
            BuildMerkleFoldPublicPlanV1(
                out.canonical_shape,
                range);
    if (!out.canonical_shape.valid ||
        !out.canonical_plan.valid) {
        return Fail(
            why,
            "public_canonical_plan");
    }
    std::string local_why;
    auto structural =
        StructuralShard(
            decoded,
            out.canonical_plan,
            &local_why);
    if (!structural.valid) {
        return Fail(
            why,
            "public_task_schedule:" +
                local_why);
    }
    auto hash =
        BuildOrdinaryHashProductV1(
            decoded, structural);
    auto fold =
        BuildOrdinaryFoldProductV1(
            decoded, structural);
    if (!hash.plan.valid ||
        !fold.plan.valid ||
        !hash.all_relation_constraints_canonical_bytecode ||
        !fold.all_relation_constraints_canonical_bytecode) {
        return Fail(
            why,
            "public_relation_products:" +
                hash.note + ":" + fold.note);
    }
    out.hash_plan = hash.plan;
    out.fold_plan = fold.plan;
    out.hash_cs = std::move(hash.cs);
    out.fold_cs = std::move(fold.cs);
    out.hash_source_carriers =
        std::move(hash.source_carriers);
    out.fold_source_carriers =
        std::move(fold.source_carriers);
    out.hash_acceptance =
        hash.acceptance;
    out.fold_acceptance =
        fold.acceptance;
    out.tape_shape = shape;
    out.tape_binding = binding;
    out.range = range;
    out.structural_hash_tasks =
        static_cast<uint32_t>(
            structural.hash_tasks.size());
    out.structural_fold_rows =
        structural.fold_real_rows;
    out.source_schedule_regenerated =
        schedule
            .semantic_schedule_regenerated &&
        schedule.stable_addresses;
    out.task_schedule_regenerated =
        out.hash_plan.valid &&
        out.fold_plan.valid &&
        out.structural_hash_tasks ==
            out.canonical_plan
                .hash_real_rows &&
        out.structural_fold_rows ==
            out.canonical_plan
                .fold_real_rows &&
        !out.hash_source_carriers.empty() &&
        !out.fold_source_carriers.empty() &&
        out.hash_acceptance.column <
            out.hash_cs.n_columns &&
        out.hash_acceptance.row <
            out.hash_cs.n_rows &&
        out.fold_acceptance.column <
            out.fold_cs.n_columns &&
        out.fold_acceptance.row <
            out.fold_cs.n_rows;
    out.transformed_systems_rebuilt =
        out.hash_cs.n_rows ==
            out.canonical_plan
                .hash_trace_rows &&
        out.hash_cs.n_columns >
            out.canonical_plan
                .hash_cs.n_columns &&
        out.fold_cs.n_rows ==
            out.canonical_plan
                .fold_trace_rows &&
        out.fold_cs.n_columns >
            out.canonical_plan
                .fold_cs.n_columns &&
        !out.hash_cs.constraints.empty() &&
        !out.fold_cs.constraints.empty();
    out.hash_relations_canonical_bytecode =
        hash.all_relation_constraints_canonical_bytecode;
    out.fold_relations_canonical_bytecode =
        fold.all_relation_constraints_canonical_bytecode;
    out.proof_values_excluded =
        out.canonical_shape
            .proof_values_excluded &&
        out.canonical_plan
            .proof_independent;
    out.valid =
        out.source_schedule_regenerated &&
        out.task_schedule_regenerated &&
        out.transformed_systems_rebuilt &&
        out.hash_relations_canonical_bytecode &&
        out.fold_relations_canonical_bytecode &&
        out.proof_values_excluded;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "public_transformed_cs_rebuilt"
        : "stage3:v13_merkle_fold_parent:"
          "public_transformed_cs_invalid";
    if (!out.valid) {
        return Fail(
            why,
            "public_transformed_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildOrdinaryProductsFromPublicSystemsV1(
    const PublicConstraintSystemsV1&
        public_systems,
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard,
    OrdinaryHashProductV1& hash,
    OrdinaryFoldProductV1& fold,
    std::string* why)
{
    hash = {};
    fold = {};
    if (!public_systems.valid ||
        shard.first_query !=
            public_systems.range.first_query ||
        shard.query_count !=
            public_systems.range.query_count) {
        return Fail(
            why,
            "public_materialization_input");
    }
    const auto decoded_shape =
        unified::
            BuildMerkleFoldPublicShapeV1(
                decoded);
    if (!decoded_shape.valid ||
        decoded_shape !=
            public_systems
                .canonical_shape) {
        return Fail(
            why,
            "public_materialization_shape");
    }
    const auto canonical =
        unified::
            MaterializeMerkleFoldCanonicalPhasesV1(
                public_systems
                    .canonical_plan,
                decoded, shard);
    if (!canonical.valid) {
        return Fail(
            why,
            "public_materialization_canonical");
    }
    mf::ShardProductV1 adapted =
        shard;
    adapted.hash_cs =
        canonical.hash_cs;
    adapted.fold_cs =
        canonical.fold_cs;
    adapted.hash_columns =
        canonical.hash_columns;
    adapted.fold_columns =
        canonical.fold_columns;
    adapted.hash_layout =
        public_systems
            .canonical_plan.hash_layout;
    adapted.fold_layout =
        public_systems
            .canonical_plan.fold_layout;
    hash =
        BuildOrdinaryHashProductV1(
            decoded, adapted);
    fold =
        BuildOrdinaryFoldProductV1(
            decoded, adapted);
    if (!hash.valid ||
        !fold.valid ||
        !SameConstraintSystemStructure(
            hash.cs,
            public_systems.hash_cs) ||
        !SameConstraintSystemStructure(
            fold.cs,
            public_systems.fold_cs)) {
        hash = {};
        fold = {};
        return Fail(
            why,
            "public_materialization_structure");
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_merkle_fold_parent:"
            "public_cs_honest_witness_materialized";
    }
    return true;
}

bool AppendProofTapeAliasesV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const tape::ProductV1& tape_product,
    const composer::ChildAttachmentV1&
        tape_attachment,
    const OrdinaryHashProductV1& hash_product,
    const composer::ChildAttachmentV1&
        hash_attachment,
    const OrdinaryFoldProductV1& fold_product,
    const composer::ChildAttachmentV1&
        fold_attachment,
    ParentAliasAttachmentV1& out,
    std::string* why)
{
    namespace terminal =
        stage3_v13_terminal_fold_parent;
    out = {};
    if (!tape_product.valid ||
        !hash_product.valid ||
        !fold_product.valid ||
        !tape_attachment.valid ||
        !hash_attachment.valid ||
        !fold_attachment.valid ||
        tape_attachment.semantic_child_columns !=
            tape_product.cs.n_columns ||
        hash_attachment.semantic_child_columns !=
            hash_product.cs.n_columns ||
        fold_attachment.semantic_child_columns !=
            fold_product.cs.n_columns) {
        return Fail(
            why, "parent_alias_input");
    }
    std::map<uint32_t,
             tape::SourceAddressCellV1>
        tape_cells;
    for (const auto& cell :
         tape_product.source_cells) {
        if (!tape_cells.emplace(
                cell.address, cell)
                 .second) {
            return Fail(
                why,
                "duplicate_tape_address");
        }
    }
    std::vector<std::pair<
        terminal::CellRefV1,
        terminal::CellRefV1>>
        aliases;
    aliases.reserve(
        hash_product.source_carriers.size() +
        fold_product.source_carriers.size());
    const auto append_child =
        [&](const std::vector<SourceCarrierV1>&
                carriers,
            const composer::ChildAttachmentV1&
                attachment) {
            for (const auto& carrier :
                 carriers) {
                const auto tape_it =
                    tape_cells.find(
                        carrier.source_address);
                if (tape_it ==
                        tape_cells.end() ||
                    !(tape_it->second.key ==
                      carrier.source_key)) {
                    return false;
                }
                aliases.push_back({
                    {
                        tape_attachment
                            .ParentColumn(
                                tape_it->second
                                    .value_column),
                        tape_it->second.row,
                    },
                    {
                        attachment.ParentColumn(
                            carrier.cell.column),
                        carrier.cell.row,
                    }});
            }
            return true;
        };
    if (!append_child(
            hash_product.source_carriers,
            hash_attachment) ||
        !append_child(
            fold_product.source_carriers,
            fold_attachment) ||
        aliases.empty()) {
        return Fail(
            why, "missing_tape_address");
    }
    terminal::LiteralAliasAttachmentV1
        literal;
    if (!terminal::AppendLiteralAliasesV1(
            parent_cs, parent_columns,
            aliases, literal, why)) {
        return false;
    }
    out.source_aliases =
        literal.literal_aliases;
    out.constraints =
        literal.constraints;
    out.violations =
        literal.violations;
    out.tape_cells_literal =
        out.source_aliases ==
            hash_product.source_carriers.size() +
                fold_product.source_carriers.size();
    out.child_carriers_ordinary =
        literal.endpoints_ordinary;
    out.cross_row_transport_constrained =
        literal
            .cross_row_transport_constrained;
    out.global_r0_pending =
        literal.global_r0_pending;
    out.valid =
        literal.valid &&
        out.tape_cells_literal &&
        out.child_carriers_ordinary &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "all_proof_sources_physically_aliased;"
          "global_r0_pending"
        : "stage3:v13_merkle_fold_parent:"
          "parent_alias_invalid";
    if (!out.valid) {
        return Fail(
            why, "parent_alias_invalid");
    }
    if (why != nullptr) {
        *why = out.note;
    }
    return true;
}

uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>&
        columns)
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
    std::vector<Fp3> current(
        cs.n_columns);
    std::vector<Fp3> next(
        cs.n_columns);
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
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
            const bool applies =
                constraint.kind ==
                    aq::AirKind::kEverywhere ||
                (constraint.kind ==
                     aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows) ||
                (constraint.kind ==
                     aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind ==
                     aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows);
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

} // namespace matmul::v4::rc::stage3_v13_merkle_fold_parent
