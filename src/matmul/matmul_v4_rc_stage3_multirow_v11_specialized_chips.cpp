// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_specialized_chips.h>

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_multirow_v11_specialized_chips {
namespace {

using gf::Fp;
using gf::Fp3;
using Matrix12 = std::array<
    std::array<Fp, alg_hash::kAlgHashT>,
    alg_hash::kAlgHashT>;

struct Expr {
    std::vector<cb::Instruction> instructions;
    std::vector<uint32_t> degrees;

    uint32_t Current(uint32_t column)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Current;
        in.lhs = column;
        instructions.push_back(in);
        degrees.push_back(1);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Next(uint32_t column)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Next;
        in.lhs = column;
        instructions.push_back(in);
        degrees.push_back(1);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Constant(const Fp3& value)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Constant;
        in.constant = value;
        instructions.push_back(in);
        degrees.push_back(0);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Binary(
        cb::Opcode opcode,
        uint32_t left,
        uint32_t right)
    {
        cb::Instruction in;
        in.opcode = opcode;
        in.lhs = left;
        in.rhs = right;
        instructions.push_back(in);
        degrees.push_back(
            opcode == cb::Opcode::Mul
            ? degrees[left] + degrees[right]
            : std::max(
                degrees[left], degrees[right]));
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Add(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Add, left, right);
    }

    uint32_t Sub(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Sub, left, right);
    }

    uint32_t Mul(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Mul, left, right);
    }

    uint32_t One()
    {
        return Constant(Fp3::One());
    }

    uint32_t Boolean(uint32_t column)
    {
        const uint32_t value = Current(column);
        return Mul(
            value,
            Sub(value, One()));
    }
};

template <typename Build>
void AppendProgram(
    cb::ProgramTable& table,
    Build&& build)
{
    Expr expr;
    build(expr);
    cb::Program program;
    program.version =
        cb::kConstraintBytecodeVersion;
    program.role =
        RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal =
        static_cast<uint32_t>(
            table.programs.size());
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree =
        expr.degrees.back();
    program.current_width =
        table.current_width;
    program.next_width =
        table.next_width;
    program.challenge_width = 0;
    program.instructions =
        std::move(expr.instructions);
    table.programs.push_back(
        std::move(program));
}

uint64_t InstructionCount(
    const cb::ProgramTable& table,
    uint32_t first = 0,
    uint32_t count =
        std::numeric_limits<uint32_t>::max())
{
    uint64_t total = 0;
    const uint32_t end =
        std::min<uint32_t>(
            static_cast<uint32_t>(
                table.programs.size()),
            first + std::min<uint32_t>(
                count,
                std::numeric_limits<uint32_t>::max() -
                    first));
    for (uint32_t ordinal = first;
         ordinal < end;
         ++ordinal) {
        total +=
            table.programs[ordinal]
                .instructions.size();
    }
    return total;
}

bool AppendProgramRangeAtOffset(
    cb::ProgramTable& out,
    const cb::ProgramTable& source,
    uint32_t first,
    uint32_t count,
    uint32_t column_offset)
{
    if (first > source.programs.size() ||
        count > source.programs.size() - first) {
        return false;
    }
    for (uint32_t ordinal = first;
         ordinal < first + count;
         ++ordinal) {
        auto program = source.programs[ordinal];
        for (auto& instruction :
             program.instructions) {
            if (instruction.opcode !=
                    cb::Opcode::Current &&
                instruction.opcode !=
                    cb::Opcode::Next) {
                continue;
            }
            if (instruction.lhs >
                std::numeric_limits<uint32_t>::max() -
                    column_offset) {
                return false;
            }
            instruction.lhs += column_offset;
        }
        program.constraint_ordinal =
            static_cast<uint32_t>(
                out.programs.size());
        program.current_width =
            out.current_width;
        program.next_width =
            out.next_width;
        program.challenge_width =
            out.challenge_width;
        out.programs.push_back(
            std::move(program));
    }
    return true;
}

aq::AirConstraintSystem<Fp3>
ConstraintSystemFromTable(
    const cb::ProgramTable& table,
    uint32_t rows)
{
    aq::AirConstraintSystem<Fp3> out;
    out.n_rows = rows;
    out.n_columns = table.current_width;
    out.constraints.reserve(
        table.programs.size());
    for (const auto& program : table.programs) {
        aq::AirConstraint<Fp3> constraint;
        constraint.name =
            "stage3.v11_specialized_chip.bytecode";
        constraint.kind = program.kind;
        constraint.alg_degree =
            program.declared_degree;
        constraint.eval =
            [program](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                Fp3 result{};
                std::string why;
                if (!cb::EvaluateProgram(
                        program,
                        current, next,
                        result, &why)) {
                    return Fp3::One();
                }
                return result;
            };
        out.constraints.push_back(
            std::move(constraint));
    }
    return out;
}

bool Applies(
    aq::AirKind kind,
    uint32_t row,
    uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

uint64_t CountConstraintViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0;
         row < cs.n_rows;
         ++row) {
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
            if (Applies(
                    constraint.kind,
                    row, cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool CanonicalState(
    const alg_hash::State& state)
{
    return std::all_of(
        state.begin(), state.end(),
        [](Fp value) {
            return value < gf::kP;
        });
}

Matrix12 MatrixOfExternal()
{
    Matrix12 out{};
    for (uint32_t column = 0;
         column < alg_hash::kAlgHashT;
         ++column) {
        alg_hash::State basis{};
        basis[column] = 1;
        alg_hash::ApplyExternalMatrix(basis);
        for (uint32_t row = 0;
             row < alg_hash::kAlgHashT;
             ++row) {
            out[row][column] = basis[row];
        }
    }
    return out;
}

Matrix12 MatrixOfInternal()
{
    Matrix12 out{};
    for (uint32_t column = 0;
         column < alg_hash::kAlgHashT;
         ++column) {
        alg_hash::State basis{};
        basis[column] = 1;
        alg_hash::ApplyInternalMatrix(basis);
        for (uint32_t row = 0;
             row < alg_hash::kAlgHashT;
             ++row) {
            out[row][column] = basis[row];
        }
    }
    return out;
}

Matrix12 IdentityMatrix()
{
    Matrix12 out{};
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        out[lane][lane] = 1;
    }
    return out;
}

std::array<Fp3, alg_hash::kAlgHashT>
MatrixVector(
    const Matrix12& matrix,
    const std::array<
        Fp3, alg_hash::kAlgHashT>& vector)
{
    std::array<Fp3, alg_hash::kAlgHashT>
        out{};
    for (uint32_t row = 0;
         row < alg_hash::kAlgHashT;
         ++row) {
        for (uint32_t column = 0;
             column < alg_hash::kAlgHashT;
             ++column) {
            out[row] = gf::Add(
                out[row],
                gf::MulBase(
                    vector[column],
                    matrix[row][column]));
        }
    }
    return out;
}

void InstallPreprocessedRoot(
    aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    std::vector<uint32_t>& indices,
    uint256& root,
    bool& ok)
{
    std::sort(indices.begin(), indices.end());
    indices.erase(
        std::unique(
            indices.begin(), indices.end()),
        indices.end());
    for (uint32_t column : indices) {
        cs.preprocessed.emplace_back(
            column, columns[column]);
    }
    cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns, indices);
    ok = session.valid &&
        !session.base_row_commitment.IsNull();
    if (!ok) return;
    root = session.base_row_commitment;
    cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = indices,
        .root = root,
    });
}

} // namespace

PoseidonDataflowAuditV1
AuditPoseidonSubstitutionDataflowV1(
    const cb::ProgramTable& generic_table)
{
    PoseidonDataflowAuditV1 out;
    out.generic_poseidon_columns =
        pa::kFixedColumns;
    out.boundary_input_columns =
        alg_hash::kAlgHashT;
    out.boundary_output_columns =
        alg_hash::kAlgHashT;
    out.eliminated_internal_columns =
        out.generic_poseidon_columns -
        out.boundary_input_columns -
        out.boundary_output_columns;
    if (generic_table.programs.size() <
            np::kPoseidonProgramsV1) {
        out.note =
            "stage3:v11_specialized:dataflow:"
            "short_program_table";
        return out;
    }
    out.generic_programs =
        np::kPoseidonProgramsV1;
    out.generic_instructions =
        InstructionCount(
            generic_table, 0,
            np::kPoseidonProgramsV1);
    out.exact_poseidon_program_prefix =
        out.generic_instructions == 17412 &&
        generic_table.current_width ==
            pj::CanonicalLayoutV1().n_columns;

    std::set<uint32_t> distinct;
    const uint32_t output_first =
        air_recurse::kPermInputCells +
        air_recurse::SboxIndexFinalFull(
            alg_hash::kAlgHashFullRounds / 2 - 1,
            0);
    const uint32_t output_last =
        output_first + alg_hash::kAlgHashT;
    for (uint32_t ordinal =
             np::kPoseidonProgramsV1;
         ordinal < generic_table.programs.size();
         ++ordinal) {
        for (const auto& instruction :
             generic_table.programs[ordinal]
                 .instructions) {
            if ((instruction.opcode !=
                     cb::Opcode::Current &&
                 instruction.opcode !=
                     cb::Opcode::Next) ||
                instruction.lhs >=
                    pa::kFixedColumns) {
                continue;
            }
            ++out.external_poseidon_references;
            distinct.insert(instruction.lhs);
            const bool input =
                instruction.lhs <
                alg_hash::kAlgHashT;
            const bool output =
                instruction.lhs >= output_first &&
                instruction.lhs < output_last;
            if (!input && !output) {
                ++out.forbidden_internal_references;
            }
        }
    }
    out.distinct_external_poseidon_columns =
        static_cast<uint32_t>(distinct.size());
    out.only_inputs_and_final_outputs_escape =
        out.forbidden_internal_references == 0 &&
        out.distinct_external_poseidon_columns ==
            out.boundary_input_columns +
            out.boundary_output_columns;
    out.no_auxiliary_column_escapes =
        std::none_of(
            distinct.begin(), distinct.end(),
            [](uint32_t column) {
                return column >=
                    air_recurse::kPermCellsPerPerm;
            });
    out.substitution_dataflow_precondition =
        out.exact_poseidon_program_prefix &&
        out.only_inputs_and_final_outputs_escape &&
        out.no_auxiliary_column_escapes &&
        out.eliminated_internal_columns == 460;
    out.note =
        out.substitution_dataflow_precondition
        ? "stage3:v11_specialized:dataflow:"
          "only_12_input_plus_12_output_columns_escape"
        : "stage3:v11_specialized:dataflow:"
          "forbidden_internal_consumer";
    return out;
}

PoseidonRoundLayoutV1
CanonicalPoseidonRoundLayoutV1()
{
    PoseidonRoundLayoutV1 out;
    uint32_t next = 0;
    auto allocate_array =
        [&next](auto& array) {
            for (auto& column : array) {
                column = next++;
            }
        };
    allocate_array(out.state);
    allocate_array(out.x);
    allocate_array(out.x2);
    allocate_array(out.x4);
    allocate_array(out.x6);
    allocate_array(out.sbox);
    allocate_array(out.output);
    allocate_array(out.input_claim);
    allocate_array(out.output_claim);
    out.first = next++;
    out.last = next++;
    out.continue_round = next++;
    out.active_round = next++;
    for (auto& row : out.pre_matrix) {
        allocate_array(row);
    }
    allocate_array(out.round_constant);
    allocate_array(out.sbox_active);
    for (auto& row : out.post_matrix) {
        allocate_array(row);
    }
    out.n_columns = next;
    return out;
}

bool BuildPoseidonRoundProgramTableV1(
    cb::ProgramTable& out,
    std::string* why)
{
    const auto layout =
        CanonicalPoseidonRoundLayoutV1();
    out = {};
    out.version =
        cb::kConstraintBytecodeVersion;
    out.role =
        RCStage3RelationRole::CompositionLink;
    out.current_width = layout.n_columns;
    out.next_width = layout.n_columns;
    out.challenge_width = 0;
    out.programs.reserve(
        9 * alg_hash::kAlgHashT);

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        AppendProgram(out, [=](Expr& e) {
            uint32_t sum =
                e.Current(
                    layout.round_constant[lane]);
            for (uint32_t source = 0;
                 source < alg_hash::kAlgHashT;
                 ++source) {
                sum = e.Add(
                    sum,
                    e.Mul(
                        e.Current(
                            layout.pre_matrix[
                                lane][source]),
                        e.Current(
                            layout.state[source])));
            }
            e.Sub(e.Current(layout.x[lane]), sum);
        });
        AppendProgram(out, [=](Expr& e) {
            const uint32_t x =
                e.Current(layout.x[lane]);
            e.Sub(
                e.Current(layout.x2[lane]),
                e.Mul(x, x));
        });
        AppendProgram(out, [=](Expr& e) {
            const uint32_t x2 =
                e.Current(layout.x2[lane]);
            e.Sub(
                e.Current(layout.x4[lane]),
                e.Mul(x2, x2));
        });
        AppendProgram(out, [=](Expr& e) {
            e.Sub(
                e.Current(layout.x6[lane]),
                e.Mul(
                    e.Current(layout.x4[lane]),
                    e.Current(layout.x2[lane])));
        });
        AppendProgram(out, [=](Expr& e) {
            const uint32_t mask =
                e.Current(
                    layout.sbox_active[lane]);
            const uint32_t x =
                e.Current(layout.x[lane]);
            const uint32_t powered =
                e.Mul(
                    e.Current(layout.x6[lane]),
                    x);
            const uint32_t selected =
                e.Add(
                    e.Mul(mask, powered),
                    e.Mul(
                        e.Sub(e.One(), mask),
                        x));
            e.Sub(
                e.Current(layout.sbox[lane]),
                selected);
        });
        AppendProgram(out, [=](Expr& e) {
            uint32_t sum = e.Mul(
                e.Current(
                    layout.post_matrix[lane][0]),
                e.Current(layout.sbox[0]));
            for (uint32_t source = 1;
                 source < alg_hash::kAlgHashT;
                 ++source) {
                sum = e.Add(
                    sum,
                    e.Mul(
                        e.Current(
                            layout.post_matrix[
                                lane][source]),
                        e.Current(
                            layout.sbox[source])));
            }
            e.Sub(
                e.Current(layout.output[lane]),
                sum);
        });
        AppendProgram(out, [=](Expr& e) {
            e.Mul(
                e.Current(layout.continue_round),
                e.Sub(
                    e.Next(layout.state[lane]),
                    e.Current(layout.output[lane])));
        });
        AppendProgram(out, [=](Expr& e) {
            e.Mul(
                e.Current(layout.first),
                e.Sub(
                    e.Current(layout.state[lane]),
                    e.Current(
                        layout.input_claim[lane])));
        });
        AppendProgram(out, [=](Expr& e) {
            e.Mul(
                e.Current(layout.last),
                e.Sub(
                    e.Current(layout.output[lane]),
                    e.Current(
                        layout.output_claim[lane])));
        });
    }
    if (out.programs.size() != 108 ||
        !cb::ValidateProgramTable(out, why)) {
        if (why != nullptr && why->empty()) {
            *why =
                "stage3:v11_specialized:"
                "poseidon_program_table";
        }
        return false;
    }
    return true;
}

PoseidonRoundProductV1
BuildPoseidonRoundProductV1(
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& inputs,
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& claimed_outputs)
{
    PoseidonRoundProductV1 out;
    out.layout =
        CanonicalPoseidonRoundLayoutV1();
    out.claimed_inputs = inputs;
    out.claimed_outputs = claimed_outputs;
    out.trace_rows = kPoseidonTraceRowsV1;
    out.active_rows =
        kVerifierQueriesV1 *
        kPoseidonActiveRowsPerQueryV1;
    out.scheduler_reserve_rows =
        out.trace_rows - out.active_rows;
    out.trace_columns = out.layout.n_columns;
    std::string why;
    if (!BuildPoseidonRoundProgramTableV1(
            out.program_table, &why)) {
        out.note = why;
        return out;
    }
    out.programs =
        static_cast<uint32_t>(
            out.program_table.programs.size());
    out.instructions =
        InstructionCount(out.program_table);
    out.cs = ConstraintSystemFromTable(
        out.program_table, out.trace_rows);
    for (const auto& program :
         out.program_table.programs) {
        out.max_degree =
            std::max(
                out.max_degree,
                program.declared_degree);
    }
    out.columns.assign(
        out.trace_columns,
        std::vector<Fp3>(
            out.trace_rows, Fp3::Zero()));
    auto set = [&out](
                   uint32_t column,
                   uint32_t row,
                   const Fp3& value) {
        out.columns[column][row] = value;
    };
    const Matrix12 external =
        MatrixOfExternal();
    const Matrix12 internal =
        MatrixOfInternal();
    const Matrix12 identity =
        IdentityMatrix();
    const auto& constants =
        alg_hash::GetAlgHashConstants();
    out.exact_native_outputs = true;

    for (uint32_t query = 0;
         query < kVerifierQueriesV1;
         ++query) {
        if (!CanonicalState(inputs[query]) ||
            !CanonicalState(
                claimed_outputs[query])) {
            out.note =
                "stage3:v11_specialized:"
                "noncanonical_poseidon_io";
            return out;
        }
        alg_hash::State native =
            inputs[query];
        alg_hash::Permute(native);
        out.exact_native_outputs =
            out.exact_native_outputs &&
            native == claimed_outputs[query];
        std::array<Fp3, alg_hash::kAlgHashT>
            state{};
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashT;
             ++lane) {
            state[lane] =
                Fp3::FromFp(inputs[query][lane]);
        }
        for (uint32_t round = 0;
             round < kPoseidonRoundsV1;
             ++round) {
            const uint32_t row =
                query * kPoseidonRowsPerQueryV1 +
                round;
            const bool initial_full = round < 4;
            const bool partial =
                round >= 4 && round < 26;
            const bool final_full = round >= 26;
            const Matrix12& pre =
                round == 0 ? external : identity;
            const Matrix12& post =
                partial ? internal : external;
            auto x = MatrixVector(pre, state);
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                Fp round_constant = 0;
                bool sbox_active =
                    initial_full || final_full;
                if (initial_full) {
                    round_constant =
                        constants.rc_ext[round][lane];
                } else if (partial) {
                    sbox_active = lane == 0;
                    if (lane == 0) {
                        round_constant =
                            constants.rc_int[round - 4];
                    }
                } else {
                    round_constant =
                        constants.rc_ext[
                            4 + round - 26][lane];
                }
                x[lane] = gf::Add(
                    x[lane],
                    Fp3::FromFp(round_constant));
                const Fp3 x2 =
                    gf::Mul(x[lane], x[lane]);
                const Fp3 x4 =
                    gf::Mul(x2, x2);
                const Fp3 x6 =
                    gf::Mul(x4, x2);
                const Fp3 sbox =
                    sbox_active
                    ? gf::Mul(x6, x[lane])
                    : x[lane];
                set(
                    out.layout.state[lane],
                    row, state[lane]);
                set(
                    out.layout.x[lane],
                    row, x[lane]);
                set(
                    out.layout.x2[lane],
                    row, x2);
                set(
                    out.layout.x4[lane],
                    row, x4);
                set(
                    out.layout.x6[lane],
                    row, x6);
                set(
                    out.layout.sbox[lane],
                    row, sbox);
                set(
                    out.layout.input_claim[lane],
                    row,
                    round == 0
                    ? Fp3::FromFp(
                        inputs[query][lane])
                    : Fp3::Zero());
                set(
                    out.layout.output_claim[lane],
                    row,
                    round + 1 ==
                            kPoseidonRoundsV1
                    ? Fp3::FromFp(
                        claimed_outputs[
                            query][lane])
                    : Fp3::Zero());
                set(
                    out.layout.round_constant[lane],
                    row,
                    Fp3::FromFp(round_constant));
                set(
                    out.layout.sbox_active[lane],
                    row,
                    sbox_active
                    ? Fp3::One()
                    : Fp3::Zero());
                for (uint32_t source = 0;
                     source < alg_hash::kAlgHashT;
                     ++source) {
                    set(
                        out.layout.pre_matrix[
                            lane][source],
                        row,
                        Fp3::FromFp(
                            pre[lane][source]));
                    set(
                        out.layout.post_matrix[
                            lane][source],
                        row,
                        Fp3::FromFp(
                            post[lane][source]));
                }
            }
            std::array<Fp3, alg_hash::kAlgHashT>
                sbox_vector{};
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                sbox_vector[lane] =
                    out.columns[
                        out.layout.sbox[lane]][row];
            }
            const auto output =
                MatrixVector(post, sbox_vector);
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                set(
                    out.layout.output[lane],
                    row, output[lane]);
            }
            set(
                out.layout.first, row,
                round == 0
                ? Fp3::One()
                : Fp3::Zero());
            set(
                out.layout.last, row,
                round + 1 ==
                        kPoseidonRoundsV1
                ? Fp3::One()
                : Fp3::Zero());
            set(
                out.layout.continue_round, row,
                round + 1 <
                        kPoseidonRoundsV1
                ? Fp3::One()
                : Fp3::Zero());
            set(
                out.layout.active_round,
                row, Fp3::One());
            state = output;
        }
    }

    auto add_array =
        [&out](const auto& columns) {
            out.preprocessed_columns.insert(
                out.preprocessed_columns.end(),
                columns.begin(), columns.end());
        };
    add_array(out.layout.input_claim);
    add_array(out.layout.output_claim);
    out.preprocessed_columns.push_back(
        out.layout.first);
    out.preprocessed_columns.push_back(
        out.layout.last);
    out.preprocessed_columns.push_back(
        out.layout.continue_round);
    out.preprocessed_columns.push_back(
        out.layout.active_round);
    for (const auto& row :
         out.layout.pre_matrix) {
        add_array(row);
    }
    add_array(out.layout.round_constant);
    add_array(out.layout.sbox_active);
    for (const auto& row :
         out.layout.post_matrix) {
        add_array(row);
    }
    bool root_ok = false;
    InstallPreprocessedRoot(
        out.cs, out.columns,
        out.preprocessed_columns,
        out.preprocessed_row_group_root,
        root_ok);
    out.exact_round_schedule_root_pinned =
        root_ok;
    out.violations =
        root_ok
        ? RecountViolationsV1(
            out.cs, out.columns,
            out.preprocessed_columns,
            out.preprocessed_row_group_root)
        : std::numeric_limits<uint64_t>::max();
    out.executable =
        out.programs == 108 &&
        out.instructions == 1668 &&
        out.max_degree <= 3 &&
        out.trace_columns == 424 &&
        out.scheduler_reserve_rows == 128 &&
        out.violations == 0;
    out.recursive_authority_ready = false;
    out.valid =
        out.exact_native_outputs &&
        out.exact_round_schedule_root_pinned &&
        out.executable &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_specialized:"
          "poseidon_round_serial_executable"
        : "stage3:v11_specialized:"
          "poseidon_round_serial_failure:"
          "native=" +
          std::to_string(
              out.exact_native_outputs ? 1 : 0) +
          ":r0=" +
          std::to_string(
              out.exact_round_schedule_root_pinned ? 1 : 0) +
          ":exec=" +
          std::to_string(
              out.executable ? 1 : 0) +
          ":violations=" +
          std::to_string(out.violations) +
          ":programs=" +
          std::to_string(out.programs) +
          ":instructions=" +
          std::to_string(out.instructions) +
          ":columns=" +
          std::to_string(out.trace_columns) +
          ":degree=" +
          std::to_string(out.max_degree);
    return out;
}

StaticPoseidonRoundProductV1
BuildStaticPoseidonRoundProductV1(
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& inputs,
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& claimed_outputs)
{
    StaticPoseidonRoundProductV1 out;
    const auto witness =
        BuildPoseidonRoundProductV1(
            inputs, claimed_outputs);
    out.layout = witness.layout;
    out.program_table = witness.program_table;
    out.columns = witness.columns;
    out.trace_rows = witness.trace_rows;
    out.trace_columns = witness.trace_columns;
    out.programs = witness.programs;
    out.instructions = witness.instructions;
    out.max_degree = witness.max_degree;
    if (out.program_table.programs.empty() ||
        out.columns.size() !=
            out.trace_columns) {
        out.note =
            "stage3:v11_specialized:"
            "static_poseidon_witness_failure:" +
            witness.note;
        return out;
    }

    /*
     * Rebuild the CS instead of retaining the product's CS: the product form
     * intentionally pins its I/O claims for differential testing, whereas a
     * recursive verifier must receive those claims from an authenticated
     * proof/transcript bus.  Only immutable schedule data belongs in R0.
     */
    out.cs = ConstraintSystemFromTable(
        out.program_table, out.trace_rows);
    auto add_array =
        [&out](const auto& columns) {
            out.preprocessed_columns.insert(
                out.preprocessed_columns.end(),
                columns.begin(), columns.end());
        };
    out.preprocessed_columns.push_back(
        out.layout.first);
    out.preprocessed_columns.push_back(
        out.layout.last);
    out.preprocessed_columns.push_back(
        out.layout.continue_round);
    out.preprocessed_columns.push_back(
        out.layout.active_round);
    for (const auto& row :
         out.layout.pre_matrix) {
        add_array(row);
    }
    add_array(out.layout.round_constant);
    add_array(out.layout.sbox_active);
    for (const auto& row :
         out.layout.post_matrix) {
        add_array(row);
    }

    const auto is_preprocessed =
        [&out](uint32_t column) {
            return std::find(
                out.preprocessed_columns.begin(),
                out.preprocessed_columns.end(),
                column) !=
                out.preprocessed_columns.end();
        };
    out.input_claims_ordinary_witness = true;
    out.output_claims_ordinary_witness = true;
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        out.input_claims_ordinary_witness =
            out.input_claims_ordinary_witness &&
            !is_preprocessed(
                out.layout.input_claim[lane]);
        out.output_claims_ordinary_witness =
            out.output_claims_ordinary_witness &&
            !is_preprocessed(
                out.layout.output_claim[lane]);
    }
    out.proof_dependent_preprocessed_columns =
        (!out.input_claims_ordinary_witness
            ? alg_hash::kAlgHashT
            : 0) +
        (!out.output_claims_ordinary_witness
            ? alg_hash::kAlgHashT
            : 0);

    bool root_ok = false;
    InstallPreprocessedRoot(
        out.cs, out.columns,
        out.preprocessed_columns,
        out.preprocessed_row_group_root,
        root_ok);
    out.static_schedule_root_pinned = root_ok;
    out.cs_independent_of_io =
        out.preprocessed_columns.size() == 316 &&
        out.proof_dependent_preprocessed_columns == 0;
    out.violations =
        root_ok
        ? RecountViolationsV1(
            out.cs, out.columns,
            out.preprocessed_columns,
            out.preprocessed_row_group_root)
        : std::numeric_limits<uint64_t>::max();
    out.external_io_bus_complete = false;
    out.executable =
        witness.exact_native_outputs &&
        out.programs == 108 &&
        out.instructions == 1668 &&
        out.max_degree <= 3 &&
        out.trace_columns == 424 &&
        out.violations == 0;
    out.recursive_authority_ready = false;
    out.valid_foundation =
        out.input_claims_ordinary_witness &&
        out.output_claims_ordinary_witness &&
        out.static_schedule_root_pinned &&
        out.cs_independent_of_io &&
        out.executable &&
        !out.external_io_bus_complete &&
        !out.recursive_authority_ready;
    out.note = out.valid_foundation
        ? "stage3:v11_specialized:"
          "static_poseidon_round_cs_foundation:"
          "external_io_bus_pending"
        : "stage3:v11_specialized:"
          "static_poseidon_round_cs_failure:"
          "input_witness=" +
          std::to_string(
              out.input_claims_ordinary_witness
              ? 1 : 0) +
          ":output_witness=" +
          std::to_string(
              out.output_claims_ordinary_witness
              ? 1 : 0) +
          ":proof_r0=" +
          std::to_string(
              out.proof_dependent_preprocessed_columns) +
          ":r0=" +
          std::to_string(
              out.static_schedule_root_pinned
              ? 1 : 0) +
          ":static=" +
          std::to_string(
              out.cs_independent_of_io ? 1 : 0) +
          ":exec=" +
          std::to_string(
              out.executable ? 1 : 0) +
          ":violations=" +
          std::to_string(out.violations);
    return out;
}

CanonicalSplitLayoutV1
CanonicalSplitChipLayoutV1()
{
    CanonicalSplitLayoutV1 out;
    uint32_t next = 0;
    out.bit = next++;
    out.low_sum_before = next++;
    out.low_sum_after = next++;
    out.high_sum_before = next++;
    out.high_sum_after = next++;
    out.high_and_before = next++;
    out.high_and_after = next++;
    out.high_prefix_bit = next++;
    out.claim_lo = next++;
    out.claim_hi = next++;
    out.expected_lo = next++;
    out.expected_hi = next++;
    out.replay = next++;
    out.split_active = next++;
    out.low_inverse = next++;
    out.low_nonzero = next++;
    out.first = next++;
    out.last = next++;
    out.continue_bit = next++;
    out.low_mask = next++;
    out.high_mask = next++;
    out.high_first = next++;
    out.weight = next++;
    out.expected_active = next++;
    out.public_split_active = next++;
    out.query_ordinal = next++;
    out.split_ordinal = next++;
    out.bit_ordinal = next++;
    out.n_columns = next;
    return out;
}

bool BuildCanonicalSplitProgramTableV1(
    cb::ProgramTable& out,
    std::string* why)
{
    const auto l =
        CanonicalSplitChipLayoutV1();
    out = {};
    out.version =
        cb::kConstraintBytecodeVersion;
    out.role =
        RCStage3RelationRole::CompositionLink;
    out.current_width = l.n_columns;
    out.next_width = l.n_columns;
    out.challenge_width = 0;
    out.programs.reserve(29);
    AppendProgram(out, [=](Expr& e) {
        e.Boolean(l.bit);
    });
    AppendProgram(out, [=](Expr& e) {
        e.Boolean(l.split_active);
    });
    AppendProgram(out, [=](Expr& e) {
        e.Boolean(l.low_nonzero);
    });
    AppendProgram(out, [=](Expr& e) {
        e.Sub(
            e.Current(l.low_sum_after),
            e.Add(
                e.Current(l.low_sum_before),
                e.Mul(
                    e.Mul(
                        e.Current(l.low_mask),
                        e.Current(l.bit)),
                    e.Current(l.weight))));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Sub(
            e.Current(l.high_sum_after),
            e.Add(
                e.Current(l.high_sum_before),
                e.Mul(
                    e.Mul(
                        e.Current(l.high_mask),
                        e.Current(l.bit)),
                    e.Current(l.weight))));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.first),
            e.Current(l.low_sum_before));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.first),
            e.Current(l.high_sum_before));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.continue_bit),
            e.Sub(
                e.Next(l.low_sum_before),
                e.Current(l.low_sum_after)));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.continue_bit),
            e.Sub(
                e.Next(l.high_sum_before),
                e.Current(l.high_sum_after)));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Sub(
            e.Current(l.high_prefix_bit),
            e.Mul(
                e.Current(l.high_and_before),
                e.Current(l.bit)));
    });
    AppendProgram(out, [=](Expr& e) {
        const uint32_t high_first =
            e.Current(l.high_first);
        const uint32_t bit =
            e.Current(l.bit);
        const uint32_t value = e.Add(
            e.Mul(high_first, bit),
            e.Mul(
                e.Mul(
                    e.Current(l.high_mask),
                    e.Sub(e.One(), high_first)),
                e.Current(l.high_prefix_bit)));
        e.Sub(
            e.Current(l.high_and_after),
            value);
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.continue_bit),
            e.Sub(
                e.Next(l.high_and_before),
                e.Current(l.high_and_after)));
    });
    const std::array<uint32_t, 8> carried{{
        l.claim_lo,
        l.claim_hi,
        l.expected_lo,
        l.expected_hi,
        l.replay,
        l.split_active,
        l.low_inverse,
        l.low_nonzero,
    }};
    for (uint32_t column : carried) {
        AppendProgram(out, [=](Expr& e) {
            e.Mul(
                e.Current(l.continue_bit),
                e.Sub(
                    e.Next(column),
                    e.Current(column)));
        });
    }
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Sub(
                e.Current(l.low_sum_after),
                e.Current(l.claim_lo)));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Sub(
                e.Current(l.high_sum_after),
                e.Current(l.claim_hi)));
    });
    AppendProgram(out, [=](Expr& e) {
        const uint32_t raw = e.Add(
            e.Current(l.claim_lo),
            e.Mul(
                e.Constant(
                    gf::FromU64_3(
                        uint64_t{1} << 32)),
                e.Current(l.claim_hi)));
        e.Mul(
            e.Current(l.last),
            e.Mul(
                e.Current(l.split_active),
                e.Sub(
                    raw,
                    e.Current(l.replay))));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Sub(
            e.Current(l.public_split_active),
            e.Mul(
                e.Current(l.expected_active),
                e.Current(l.split_active)));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Mul(
                e.Current(l.public_split_active),
                e.Sub(
                    e.Current(l.claim_lo),
                    e.Current(l.expected_lo))));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Mul(
                e.Current(l.public_split_active),
                e.Sub(
                    e.Current(l.claim_hi),
                    e.Current(l.expected_hi))));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Sub(
                e.Mul(
                    e.Current(l.claim_lo),
                    e.Current(l.low_inverse)),
                e.Current(l.low_nonzero)));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Mul(
                e.Current(l.claim_lo),
                e.Sub(
                    e.One(),
                    e.Current(l.low_nonzero))));
    });
    AppendProgram(out, [=](Expr& e) {
        e.Mul(
            e.Current(l.last),
            e.Mul(
                e.Current(l.high_and_after),
                e.Current(l.low_nonzero)));
    });
    if (out.programs.size() != 29 ||
        !cb::ValidateProgramTable(out, why)) {
        if (why != nullptr && why->empty()) {
            *why =
                "stage3:v11_specialized:"
                "split_program_table";
        }
        return false;
    }
    return true;
}

CanonicalSplitProductV1
BuildCanonicalSplitProductV1(
    const std::array<
        std::array<
            CanonicalSplitInputV1,
            kCanonicalSplitsV1>,
        kVerifierQueriesV1>& inputs)
{
    CanonicalSplitProductV1 out;
    out.layout =
        CanonicalSplitChipLayoutV1();
    out.trace_rows =
        kCanonicalSplitTraceRowsV1;
    out.active_rows =
        kCanonicalSplitRealRowsV1;
    out.scheduler_reserve_rows =
        out.trace_rows - out.active_rows;
    out.trace_columns = out.layout.n_columns;
    std::string why;
    if (!BuildCanonicalSplitProgramTableV1(
            out.program_table, &why)) {
        out.note = why;
        return out;
    }
    out.programs =
        static_cast<uint32_t>(
            out.program_table.programs.size());
    out.instructions =
        InstructionCount(out.program_table);
    out.cs = ConstraintSystemFromTable(
        out.program_table, out.trace_rows);
    for (const auto& program :
         out.program_table.programs) {
        out.max_degree =
            std::max(
                out.max_degree,
                program.declared_degree);
    }
    out.columns.assign(
        out.trace_columns,
        std::vector<Fp3>(
            out.trace_rows, Fp3::Zero()));
    auto set = [&out](
                   uint32_t column,
                   uint32_t row,
                   const Fp3& value) {
        out.columns[column][row] = value;
    };
    uint32_t row = 0;
    for (uint32_t query = 0;
         query < kVerifierQueriesV1;
         ++query) {
        for (uint32_t split = 0;
             split < kCanonicalSplitsV1;
             ++split) {
            const auto& input =
                inputs[query][split];
            const bool expected_public =
                split < pj::kPublicFieldSlotsV1;
            if (input.expected_is_public !=
                expected_public) {
                out.note =
                    "stage3:v11_specialized:"
                    "split_public_schedule";
                return out;
            }
            if (!input.active) {
                out.note =
                    "stage3:v11_specialized:"
                    "split_active_schedule";
                return out;
            }
            const uint32_t low =
                static_cast<uint32_t>(
                    input.raw);
            const uint32_t high =
                static_cast<uint32_t>(
                    input.raw >> 32);
            const uint32_t expected_low =
                static_cast<uint32_t>(
                    input.expected);
            const uint32_t expected_high =
                static_cast<uint32_t>(
                    input.expected >> 32);
            const Fp3 low_fp =
                Fp3::FromFp(gf::FromU64(low));
            const Fp3 low_nonzero =
                low != 0
                ? Fp3::One()
                : Fp3::Zero();
            const Fp3 low_inverse =
                low != 0
                ? gf::Inv(low_fp)
                : Fp3::Zero();
            uint64_t low_sum = 0;
            uint64_t high_sum = 0;
            bool high_and = false;
            for (uint32_t bit = 0;
                 bit < kCanonicalSplitRowsV1;
                 ++bit, ++row) {
                const bool value =
                    ((input.raw >> bit) & 1U) != 0;
                const bool low_phase = bit < 32;
                const uint64_t weight =
                    uint64_t{1} <<
                    (low_phase ? bit : bit - 32);
                const uint64_t low_before =
                    low_sum;
                const uint64_t high_before =
                    high_sum;
                const bool high_and_before =
                    high_and;
                if (value) {
                    if (low_phase) {
                        low_sum += weight;
                    } else {
                        high_sum += weight;
                    }
                }
                if (bit == 32) {
                    high_and = value;
                } else if (bit > 32) {
                    high_and =
                        high_and && value;
                } else {
                    high_and = false;
                }
                set(
                    out.layout.bit, row,
                    value
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.low_sum_before,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(low_before)));
                set(
                    out.layout.low_sum_after,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(low_sum)));
                set(
                    out.layout.high_sum_before,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(high_before)));
                set(
                    out.layout.high_sum_after,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(high_sum)));
                set(
                    out.layout.high_and_before,
                    row,
                    high_and_before
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.high_and_after,
                    row,
                    high_and
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.high_prefix_bit,
                    row,
                    high_and_before && value
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.claim_lo, row,
                    Fp3::FromFp(
                        gf::FromU64(low)));
                set(
                    out.layout.claim_hi, row,
                    Fp3::FromFp(
                        gf::FromU64(high)));
                set(
                    out.layout.expected_lo, row,
                    Fp3::FromFp(
                        gf::FromU64(expected_low)));
                set(
                    out.layout.expected_hi, row,
                    Fp3::FromFp(
                        gf::FromU64(expected_high)));
                set(
                    out.layout.replay, row,
                    Fp3::FromFp(
                        gf::FromU64(input.raw)));
                set(
                    out.layout.split_active, row,
                    input.active
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.low_inverse,
                    row, low_inverse);
                set(
                    out.layout.low_nonzero,
                    row, low_nonzero);
                set(
                    out.layout.first, row,
                    bit == 0
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.last, row,
                    bit == 63
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.continue_bit,
                    row,
                    bit < 63
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.low_mask, row,
                    low_phase
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.high_mask, row,
                    !low_phase
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.high_first, row,
                    bit == 32
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.weight, row,
                    Fp3::FromFp(
                        gf::FromU64(weight)));
                set(
                    out.layout.expected_active,
                    row,
                    expected_public
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.public_split_active,
                    row,
                    expected_public && input.active
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.query_ordinal,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(query)));
                set(
                    out.layout.split_ordinal,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(split)));
                set(
                    out.layout.bit_ordinal,
                    row,
                    Fp3::FromFp(
                        gf::FromU64(bit)));
            }
        }
    }
    if (row != out.active_rows) {
        out.note =
            "stage3:v11_specialized:"
            "split_row_inventory";
        return out;
    }
    out.preprocessed_columns = {
        out.layout.expected_lo,
        out.layout.expected_hi,
        out.layout.split_active,
        out.layout.first,
        out.layout.last,
        out.layout.continue_bit,
        out.layout.low_mask,
        out.layout.high_mask,
        out.layout.high_first,
        out.layout.weight,
        out.layout.expected_active,
        out.layout.query_ordinal,
        out.layout.split_ordinal,
        out.layout.bit_ordinal,
    };
    bool root_ok = false;
    InstallPreprocessedRoot(
        out.cs, out.columns,
        out.preprocessed_columns,
        out.preprocessed_row_group_root,
        root_ok);
    out.exact_schedule_root_pinned = root_ok;
    out.violations =
        root_ok
        ? RecountViolationsV1(
            out.cs, out.columns,
            out.preprocessed_columns,
            out.preprocessed_row_group_root)
        : std::numeric_limits<uint64_t>::max();
    out.exact_seven_split_schedule =
        out.active_rows ==
            kVerifierQueriesV1 *
            kCanonicalSplitsV1 * 64 &&
        out.scheduler_reserve_rows == 4096;
    out.goldilocks_alias_rejected =
        out.programs == 29;
    out.executable =
        out.instructions == 167 &&
        out.trace_columns == 28 &&
        out.max_degree <= 3 &&
        out.violations == 0;
    out.recursive_authority_ready = false;
    out.valid =
        out.exact_seven_split_schedule &&
        out.goldilocks_alias_rejected &&
        out.exact_schedule_root_pinned &&
        out.executable &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_specialized:"
          "canonical_u64_row_serial_executable"
        : "stage3:v11_specialized:"
          "canonical_u64_row_serial_failure:"
          "schedule=" +
          std::to_string(
              out.exact_seven_split_schedule ? 1 : 0) +
          ":alias_guard=" +
          std::to_string(
              out.goldilocks_alias_rejected ? 1 : 0) +
          ":r0=" +
          std::to_string(
              out.exact_schedule_root_pinned ? 1 : 0) +
          ":exec=" +
          std::to_string(
              out.executable ? 1 : 0) +
          ":violations=" +
          std::to_string(out.violations) +
          ":programs=" +
          std::to_string(out.programs) +
          ":instructions=" +
          std::to_string(out.instructions) +
          ":columns=" +
          std::to_string(out.trace_columns) +
          ":degree=" +
          std::to_string(out.max_degree);
    return out;
}

uint64_t RecountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& preprocessed_columns,
    const uint256& expected_preprocessed_root)
{
    uint64_t violations =
        CountConstraintViolations(cs, columns);
    if (violations ==
        std::numeric_limits<uint64_t>::max()) {
        return violations;
    }
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns, preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment !=
            expected_preprocessed_root) {
        ++violations;
    }
    return violations;
}

CostAuditV1 AssessSpecializedCostV1(
    const cb::ProgramTable& generic_table,
    const cb::ProgramTable& poseidon_round_table,
    const cb::ProgramTable& canonical_split_table)
{
    CostAuditV1 out;
    const auto assessed =
        np::AssessProgramTableV1(
            generic_table,
            std::numeric_limits<uint32_t>::max());
    out.generic_total_instructions =
        assessed.instruction_count;
    out.generic_poseidon_instructions =
        assessed.poseidon_instructions;
    out.generic_transcript_instructions =
        assessed.transcript_glue_instructions;
    constexpr uint32_t kParentFirst =
        np::kPoseidonProgramsV1 +
        np::kTranscriptGlueProgramsV1;
    constexpr uint32_t kPublicAbsorbPrograms =
        pj::kPublicAbsorbSlotsV1 * 3;
    constexpr uint32_t kPublicSplitPrograms =
        pj::kPublicFieldSlotsV1 * 106;
    constexpr uint32_t kCandidateSplitPrograms =
        pj::kCandidateDigestLimbsV1 * 104;
    constexpr uint32_t kSplitFirst =
        kParentFirst + kPublicAbsorbPrograms;
    constexpr uint32_t kSplitPrograms =
        kPublicSplitPrograms +
        kCandidateSplitPrograms;
    out.generic_unrolled_split_instructions =
        InstructionCount(
            generic_table,
            kSplitFirst, kSplitPrograms);
    out.retained_parent_instructions =
        assessed.parent_join_instructions -
        out.generic_unrolled_split_instructions;
    out.specialized_poseidon_instructions =
        InstructionCount(
            poseidon_round_table);
    out.specialized_split_instructions =
        InstructionCount(
            canonical_split_table);
    out.specialized_total_instructions =
        out.generic_total_instructions -
        out.generic_poseidon_instructions -
        out.generic_unrolled_split_instructions +
        out.specialized_poseidon_instructions +
        out.specialized_split_instructions;
    out.fixedpoint_instruction_cap =
        np::kFixedPointInstructionCapV1;
    if (out.specialized_total_instructions <=
        out.fixedpoint_instruction_cap) {
        out.instruction_headroom =
            out.fixedpoint_instruction_cap -
            static_cast<uint32_t>(
                out.specialized_total_instructions);
    }
    out.generic_relation_shards =
        rs::kRelationShardsV1;
    out.specialized_relation_shards = 1;
    out.exact_generic_partition =
        assessed.canonical_program_table &&
        out.generic_total_instructions == 23669 &&
        out.generic_poseidon_instructions == 17412 &&
        out.generic_transcript_instructions == 1098 &&
        out.generic_unrolled_split_instructions == 4972 &&
        out.retained_parent_instructions == 187 &&
        assessed.parent_join_instructions ==
            out.generic_unrolled_split_instructions +
            out.retained_parent_instructions;
    out.specialized_cost_below_fixedpoint_cap =
        out.specialized_poseidon_instructions == 1668 &&
        out.specialized_split_instructions == 167 &&
        out.specialized_total_instructions == 3120 &&
        out.instruction_headroom == 1040;
    out.generic_fallback_preserved =
        generic_table.programs.size() ==
            np::kExpectedProgramsV1 &&
        cb::ValidateProgramTable(generic_table);
    out.specialized_recursive_receipt_consumption_executed =
        false;
    out.recursive_authority_ready = false;
    out.valid_foundation =
        out.exact_generic_partition &&
        out.specialized_cost_below_fixedpoint_cap &&
        out.generic_fallback_preserved &&
        !out.specialized_recursive_receipt_consumption_executed &&
        !out.recursive_authority_ready;
    out.note = out.valid_foundation
        ? "stage3:v11_specialized:"
          "single_partition_fits;"
          "recursive_receipt_consumption_pending"
        : "stage3:v11_specialized:"
          "cost_or_partition_failure:"
          "partition=" +
          std::to_string(
              out.exact_generic_partition ? 1 : 0) +
          ":fits=" +
          std::to_string(
              out.specialized_cost_below_fixedpoint_cap ? 1 : 0) +
          ":generic=" +
          std::to_string(
              out.generic_total_instructions) +
          ":poseidon_old=" +
          std::to_string(
              out.generic_poseidon_instructions) +
          ":transcript=" +
          std::to_string(
              out.generic_transcript_instructions) +
          ":split_old=" +
          std::to_string(
              out.generic_unrolled_split_instructions) +
          ":retained=" +
          std::to_string(
              out.retained_parent_instructions) +
          ":poseidon_new=" +
          std::to_string(
              out.specialized_poseidon_instructions) +
          ":split_new=" +
          std::to_string(
              out.specialized_split_instructions) +
          ":total=" +
          std::to_string(
              out.specialized_total_instructions);
    return out;
}

StaticVerifierDomainAuditV1
AssessStaticVerifierDomainV1()
{
    StaticVerifierDomainAuditV1 out;
    out.query_count = 96;

    cb::ProgramTable generic;
    cb::ProgramTable poseidon;
    cb::ProgramTable split;
    std::string why;
    if (!np::BuildCanonicalProgramTableV1(
            generic, nullptr, &why) ||
        !BuildPoseidonRoundProgramTableV1(
            poseidon, &why) ||
        !BuildCanonicalSplitProgramTableV1(
            split, &why)) {
        out.note =
            "stage3:v11_specialized:"
            "static_domain_source:" + why;
        return out;
    }

    out.retained_parent_columns =
        generic.current_width;
    out.poseidon_columns =
        poseidon.current_width;
    out.split_columns =
        split.current_width;
    const uint64_t static_columns =
        uint64_t{out.retained_parent_columns} +
        out.poseidon_columns +
        out.split_columns;
    if (static_columns >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:v11_specialized:"
            "static_domain_column_overflow";
        return out;
    }
    out.static_columns =
        static_cast<uint32_t>(
            static_columns);

    out.program_table.version =
        cb::kConstraintBytecodeVersion;
    out.program_table.role =
        RCStage3RelationRole::CompositionLink;
    out.program_table.current_width =
        out.static_columns;
    out.program_table.next_width =
        out.static_columns;
    out.program_table.challenge_width = 0;

    constexpr uint32_t kParentFirst =
        np::kPoseidonProgramsV1 +
        np::kTranscriptGlueProgramsV1;
    constexpr uint32_t kPublicAbsorbPrograms =
        pj::kPublicAbsorbSlotsV1 * 3;
    constexpr uint32_t kPublicSplitPrograms =
        pj::kPublicFieldSlotsV1 * 106;
    constexpr uint32_t kCandidateSplitPrograms =
        pj::kCandidateDigestLimbsV1 * 104;
    constexpr uint32_t kUnrolledSplitPrograms =
        kPublicSplitPrograms +
        kCandidateSplitPrograms;
    constexpr uint32_t kUnrolledSplitFirst =
        kParentFirst + kPublicAbsorbPrograms;
    constexpr uint32_t kParentTailFirst =
        kUnrolledSplitFirst +
        kUnrolledSplitPrograms;
    constexpr uint32_t kParentTailPrograms =
        np::kExpectedProgramsV1 -
        kParentTailFirst;

    const bool assembled =
        AppendProgramRangeAtOffset(
            out.program_table, generic,
            np::kPoseidonProgramsV1,
            np::kTranscriptGlueProgramsV1 +
                kPublicAbsorbPrograms,
            0) &&
        AppendProgramRangeAtOffset(
            out.program_table, generic,
            kParentTailFirst,
            kParentTailPrograms,
            0) &&
        AppendProgramRangeAtOffset(
            out.program_table, poseidon,
            0,
            static_cast<uint32_t>(
                poseidon.programs.size()),
            out.retained_parent_columns) &&
        AppendProgramRangeAtOffset(
            out.program_table, split,
            0,
            static_cast<uint32_t>(
                split.programs.size()),
            out.retained_parent_columns +
                out.poseidon_columns);
    if (!assembled ||
        !cb::ValidateProgramTable(
            out.program_table, &why)) {
        out.note =
            "stage3:v11_specialized:"
            "static_domain_table:" + why;
        return out;
    }

    out.retained_parent_programs =
        np::kTranscriptGlueProgramsV1 +
        kPublicAbsorbPrograms +
        kParentTailPrograms;
    out.poseidon_programs =
        static_cast<uint32_t>(
            poseidon.programs.size());
    out.split_programs =
        static_cast<uint32_t>(
            split.programs.size());
    out.total_programs =
        static_cast<uint32_t>(
            out.program_table.programs.size());
    out.retained_parent_instructions =
        InstructionCount(
            generic,
            np::kPoseidonProgramsV1,
            np::kTranscriptGlueProgramsV1 +
                kPublicAbsorbPrograms) +
        InstructionCount(
            generic,
            kParentTailFirst,
            kParentTailPrograms);
    out.poseidon_instructions =
        InstructionCount(poseidon);
    out.split_instructions =
        InstructionCount(split);
    out.total_instructions =
        InstructionCount(out.program_table);
    out.domain =
        np::AssessExecutionDomainV1(
            out.program_table,
            out.query_count);
    out.program_root =
        cb::CommitProgramTable(
            out.program_table);
    out.proof_dependent_preprocessed_columns = 0;
    out.exact_retained_partition =
        out.retained_parent_programs == 70 &&
        out.retained_parent_instructions == 1285 &&
        out.poseidon_programs == 108 &&
        out.poseidon_instructions == 1668 &&
        out.split_programs == 29 &&
        out.split_instructions == 167 &&
        out.total_programs == 207 &&
        out.total_instructions == 3120;
    out.disjoint_column_ranges =
        out.retained_parent_columns == 1298 &&
        out.poseidon_columns == 424 &&
        out.split_columns == 28 &&
        out.static_columns == 1750;
    out.static_program_root_bound =
        !out.program_root.IsNull();
    out.challenge_independent =
        cb::ProgramTableIsChallengeIndependent(
            out.program_table);
    out.proof_independent_construction =
        out.proof_dependent_preprocessed_columns == 0 &&
        out.challenge_independent;
    out.component_buses_executable = false;
    out.child_acceptance_executable = false;
    out.recursive_authority_ready = false;
    out.valid_capacity_foundation =
        out.exact_retained_partition &&
        out.disjoint_column_ranges &&
        out.static_program_root_bound &&
        out.proof_independent_construction &&
        out.domain.valid &&
        out.domain.max_constraint_degree <= 3 &&
        out.domain.real_rows < (uint64_t{1} << 19) &&
        out.domain.lde_rows <=
            np::kLdeRowsCapV1 &&
        !out.component_buses_executable &&
        !out.child_acceptance_executable &&
        !out.recursive_authority_ready;
    out.note = out.valid_capacity_foundation
        ? "stage3:v11_specialized:"
          "q96_static_domain_fits;"
          "component_buses_and_acceptance_pending"
        : "stage3:v11_specialized:"
          "q96_static_domain_failure:"
          "partition=" +
          std::to_string(
              out.exact_retained_partition ? 1 : 0) +
          ":ranges=" +
          std::to_string(
              out.disjoint_column_ranges ? 1 : 0) +
          ":root=" +
          std::to_string(
              out.static_program_root_bound ? 1 : 0) +
          ":proof_independent=" +
          std::to_string(
              out.proof_independent_construction ? 1 : 0) +
          ":rows=" +
          std::to_string(out.domain.real_rows) +
          ":degree=" +
          std::to_string(
              out.domain.max_constraint_degree) +
          ":lde=" +
          std::to_string(out.domain.lde_rows);
    return out;
}

FixedOffsetTapeDomainAuditV1
AssessQ96FixedOffsetTapeDomainV1()
{
    FixedOffsetTapeDomainAuditV1 out;

    /*
     * Proposed V12 fixed shape.  The 330 R0 columns are exactly the static
     * round chip's 316 schedule/matrix columns plus the split chip's fourteen
     * schedule columns.  Retained relation constants live in canonical
     * bytecode and therefore do not consume proof tape cells.
     */
    constexpr uint64_t q = 96;
    constexpr uint64_t width = 1750;
    constexpr uint64_t base = 330;
    constexpr uint64_t folds = 20;
    constexpr uint64_t depth = 24;
    constexpr uint64_t rate = alg_hash::kAlgHashRate;
    constexpr uint64_t rounds = kPoseidonRoundsV1;
    constexpr uint64_t header_words =
        stage3_multirow_v11_proof_abi::
            kFieldAbiHeaderWordsV1;

    out.semantic_field_families =
        static_cast<uint32_t>(
            stage3_multirow_v11_proof_abi::
                FieldKindV1::NextRowSibling);
    out.query_count = static_cast<uint32_t>(q);
    out.trace_columns =
        static_cast<uint32_t>(width);
    out.base_columns =
        static_cast<uint32_t>(base);
    out.fold_layers =
        static_cast<uint32_t>(folds);
    out.row_path_depth =
        static_cast<uint32_t>(depth);

    /*
     * This is the closed form of proof_abi::Walk:
     *
     * common = 126 + 15F + B + 13W
     * current/query =
     *   15 + 6W + 24D + 16F + 16FD - 8F(F-1)
     * next/query = 5 + 6W + 16D
     *
     * F=log2(n_coeffs), D=log2(n_coeffs*blowup).  Each Fp3 is
     * six canonical u32 words and each digest is eight.
     */
    out.common_value_words =
        126 + 15 * folds + base + 13 * width;
    out.current_query_value_words =
        15 + 6 * width + 24 * depth +
        16 * folds + 16 * folds * depth -
        8 * folds * (folds - 1);
    out.next_query_value_words =
        5 + 6 * width + 16 * depth;
    out.total_value_words =
        out.common_value_words +
        q * (
            out.current_query_value_words +
            out.next_query_value_words);
    out.value_tape_bytes =
        out.total_value_words * sizeof(uint32_t);
    out.diagnostic_address_value_words =
        header_words + 2 * out.total_value_words;
    out.full_tape_sponge_permutations =
        (out.total_value_words + 1 + rate - 1) /
        rate;
    out.full_tape_round_rows =
        out.full_tape_sponge_permutations *
        rounds;

    const auto verifier =
        AssessStaticVerifierDomainV1();
    out.q96_verifier_real_rows =
        verifier.domain.real_rows;
    out.q96_trace_row_headroom =
        verifier.domain.trace_rows >
            verifier.domain.real_rows
        ? verifier.domain.trace_rows -
            verifier.domain.real_rows
        : 0;
    out.q96_headroom_sponge_permutations =
        out.q96_trace_row_headroom / rounds;
    out.full_hash_permutation_excess =
        out.full_tape_sponge_permutations >
            out.q96_headroom_sponge_permutations
        ? out.full_tape_sponge_permutations -
            out.q96_headroom_sponge_permutations
        : 0;
    out.full_hash_round_row_excess =
        out.full_tape_round_rows >
            out.q96_trace_row_headroom
        ? out.full_tape_round_rows -
            out.q96_trace_row_headroom
        : 0;
    out.combined_real_rows =
        out.q96_verifier_real_rows +
        out.full_tape_round_rows;

    uint64_t trace_rows = 1;
    while (trace_rows <
           out.combined_real_rows) {
        trace_rows <<= 1;
    }
    out.combined_trace_rows =
        trace_rows <=
            std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(trace_rows)
        : 0;
    out.combined_max_degree = 3;
    if (out.combined_trace_rows != 0) {
        out.combined_max_composed_degree =
            uint64_t{out.combined_max_degree} *
            (out.combined_trace_rows - 1);
        out.combined_quotient_len =
            out.combined_max_composed_degree -
            out.combined_trace_rows + 1;
        uint64_t coefficient_rows = 1;
        while (coefficient_rows <
               std::max<uint64_t>(
                   out.combined_trace_rows,
                   out.combined_quotient_len)) {
            coefficient_rows <<= 1;
        }
        if (coefficient_rows <=
            std::numeric_limits<uint32_t>::max()) {
            out.combined_coefficient_rows =
                static_cast<uint32_t>(
                    coefficient_rows);
            out.combined_lde_rows =
                coefficient_rows *
                np::kFriBlowupV1;
        }
    }
    out.combined_lde_excess =
        out.combined_lde_rows >
            np::kLdeRowsCapV1
        ? out.combined_lde_rows -
            np::kLdeRowsCapV1
        : 0;
    out.combined_lde_over_cap_factor =
        out.combined_lde_rows != 0 &&
            out.combined_lde_rows %
                np::kLdeRowsCapV1 == 0
        ? static_cast<uint32_t>(
            out.combined_lde_rows /
            np::kLdeRowsCapV1)
        : 0;

    out.exact_fixed_shape_inventory =
        out.semantic_field_families == 60 &&
        out.common_value_words == 23506 &&
        out.current_query_value_words == 16051 &&
        out.next_query_value_words == 10889 &&
        out.total_value_words == 2609746;
    out.implicit_offsets_remove_address_words =
        out.diagnostic_address_value_words ==
            header_words +
            2 * out.total_value_words;
    out.full_tape_hash_fits_q96 =
        out.full_tape_sponge_permutations <=
            out.q96_headroom_sponge_permutations &&
        out.combined_lde_rows <=
            np::kLdeRowsCapV1;
    out.monolithic_full_hash_rejected =
        !out.full_tape_hash_fits_q96 &&
        out.full_tape_sponge_permutations >
            out.q96_headroom_sponge_permutations &&
        out.combined_lde_rows >
            np::kLdeRowsCapV1;

    /*
     * No second hash is needed in the final construction: the parent STARK
     * already commits every ordinary witness column.  What is still missing
     * is the static offset schedule plus equality constraints from each
     * consumer cell to its unique tape cell.  Keep that distinction
     * fail-closed until the bus and proof-level re-entry exist.
     */
    out.full_child_tape_hash_required = false;
    out.parent_trace_commitment_binding_model = true;
    out.public_child_statement_binding_required = true;
    out.in_parent_child_acceptance_required = true;
    out.attachment_identity_uses_parent_proof_hash = true;
    out.no_tape_hash_route_capacity_viable =
        verifier.valid_capacity_foundation;
    out.parent_witness_commitment_route_required = true;
    out.fixed_offset_equality_bus_executable = false;
    out.child_acceptance_executable = false;
    out.recursive_authority_ready = false;
    out.valid_capacity_audit =
        verifier.valid_capacity_foundation &&
        out.exact_fixed_shape_inventory &&
        out.implicit_offsets_remove_address_words &&
        out.monolithic_full_hash_rejected &&
        !out.full_child_tape_hash_required &&
        out.parent_trace_commitment_binding_model &&
        out.public_child_statement_binding_required &&
        out.in_parent_child_acceptance_required &&
        out.attachment_identity_uses_parent_proof_hash &&
        out.no_tape_hash_route_capacity_viable &&
        out.parent_witness_commitment_route_required &&
        !out.fixed_offset_equality_bus_executable &&
        !out.child_acceptance_executable &&
        !out.recursive_authority_ready;
    out.note = out.valid_capacity_audit
        ? "stage3:v11_specialized:"
          "q96_fixed_tape_exact;"
          "monolithic_hash_rejected;"
          "parent_witness_equality_bus_pending"
        : "stage3:v11_specialized:"
          "q96_fixed_tape_audit_failure:"
          "exact=" +
          std::to_string(
              out.exact_fixed_shape_inventory
              ? 1 : 0) +
          ":hash_fits=" +
          std::to_string(
              out.full_tape_hash_fits_q96
              ? 1 : 0) +
          ":hash_rejected=" +
          std::to_string(
              out.monolithic_full_hash_rejected
              ? 1 : 0) +
          ":combined_lde=" +
          std::to_string(
              out.combined_lde_rows);
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_specialized_chips
