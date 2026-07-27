// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_bytecode_air.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::recursive_bytecode_air {
namespace {

using gf::Fp3;

uint32_t NextPow2(uint32_t value)
{
    uint32_t out = 1;
    while (out < value) {
        if (out > std::numeric_limits<uint32_t>::max() / 2) {
            return 0;
        }
        out <<= 1;
    }
    return std::max<uint32_t>(2, out);
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

Fp3 Pow(Fp3 base, uint32_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

bool DigestIsZero(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return gf::Canonical(value) == 0;
        });
}

void Add(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back({
        name, kind, degree, std::move(eval)});
}

std::vector<Fp3> RowAt(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t row)
{
    std::vector<Fp3> out(columns.size(), Fp3::Zero());
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        out[column] = columns[column][row];
    }
    return out;
}

uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows < 2) {
        return std::numeric_limits<uint32_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint32_t>::max();
        }
    }
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const auto current = RowAt(columns, row);
        const auto next = RowAt(
            columns,
            std::min<uint32_t>(row + 1, cs.n_rows - 1));
        for (const auto& constraint : cs.constraints) {
            bool enabled = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                enabled = true;
                break;
            case aq::AirKind::kTransition:
                enabled = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                enabled = row == 0;
                break;
            case aq::AirKind::kLastRow:
                enabled = row + 1 == cs.n_rows;
                break;
            }
            if (enabled &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool SameWitness(
    const std::vector<std::vector<Fp3>>& a,
    const std::vector<std::vector<Fp3>>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t column = 0;
         column < a.size(); ++column) {
        if (a[column].size() != b[column].size()) {
            return false;
        }
        for (uint32_t row = 0;
             row < a[column].size(); ++row) {
            if (!gf::Eq(a[column][row], b[column][row])) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

CanonicalBytecodeQuotientAirV1
BuildCanonicalBytecodeQuotientAirV1(
    const cb::ProgramTable& table,
    const alg_hash::Digest& selected_program_key,
    const QuotientDomainV1& domain,
    const std::vector<QuotientOpeningRowV1>& rows)
{
    CanonicalBytecodeQuotientAirV1 out;
    out.semantic_rows =
        static_cast<uint32_t>(rows.size());
    const alg_hash::Digest canonical_key =
        cb::CommitProgramTableAlgHash(table);
    if (!cb::ValidateProgramTable(table) ||
        !IsPowerOfTwo(domain.trace_rows) ||
        !IsPowerOfTwo(domain.evaluation_rows) ||
        domain.evaluation_rows <
            domain.trace_rows ||
        domain.evaluation_rows %
                domain.trace_rows !=
            0 ||
        !gf::Eq(
            Pow(domain.trace_omega, domain.trace_rows),
            Fp3::One()) ||
        gf::Eq(
            Pow(
                domain.trace_omega,
                domain.trace_rows / 2),
            Fp3::One()) ||
        !gf::Eq(
            Pow(
                domain.evaluation_omega,
                domain.evaluation_rows),
            Fp3::One()) ||
        gf::Eq(
            Pow(
                domain.evaluation_omega,
                domain.evaluation_rows / 2),
            Fp3::One()) ||
        !gf::Eq(
            domain.trace_omega,
            Pow(
                domain.evaluation_omega,
                domain.evaluation_rows /
                    domain.trace_rows)) ||
        gf::IsZero(domain.coset_shift) ||
        rows.empty() ||
        rows.size() >
            std::numeric_limits<uint32_t>::max() ||
        DigestIsZero(canonical_key) ||
        canonical_key != selected_program_key) {
        out.note =
            "stage3:recursive_bytecode_air:input";
        return out;
    }
    uint64_t register_count = 0;
    for (const auto& program : table.programs) {
        register_count += program.instructions.size();
    }
    if (register_count == 0 ||
        register_count >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:recursive_bytecode_air:register_count";
        return out;
    }
    for (const auto& row : rows) {
        if (row.current.size() != table.current_width ||
            row.next.size() != table.next_width ||
            row.challenge.size() != table.challenge_width ||
            row.query_index >=
                domain.evaluation_rows ||
            gf::IsZero(
                gf::Sub(
                    row.evaluation_point,
                    Fp3::One())) ||
            gf::IsZero(
                gf::Sub(
                    row.evaluation_point,
                    gf::Inv(domain.trace_omega)))) {
            out.note =
                "stage3:recursive_bytecode_air:row_shape";
            return out;
        }
    }

    out.air_rows = NextPow2(out.semantic_rows);
    if (out.air_rows == 0) {
        out.note =
            "stage3:recursive_bytecode_air:air_rows";
        return out;
    }
    uint64_t cursor = 0;
    const auto take = [&cursor](uint32_t count) {
        const uint32_t base =
            static_cast<uint32_t>(cursor);
        cursor += count;
        return base;
    };
    out.source_current_base =
        take(table.current_width);
    out.source_next_base =
        take(table.next_width);
    out.source_challenge_base =
        take(table.challenge_width);
    out.source_lambda = take(1);
    out.source_query_index = take(1);
    out.source_evaluation_point = take(1);
    out.source_next_evaluation_point = take(1);
    out.source_quotient_opening = take(1);
    out.interpreter_current_base =
        take(table.current_width);
    out.interpreter_next_base =
        take(table.next_width);
    out.interpreter_challenge_base =
        take(table.challenge_width);
    out.interpreter_selector_base =
        take(table.programs.size());
    out.interpreter_lambda = take(1);
    out.query_bit_count =
        Log2Exact(domain.evaluation_rows);
    out.query_bit_base =
        take(out.query_bit_count);
    out.query_power_accumulator_base =
        take(out.query_bit_count + 1);
    out.evaluation_power_count =
        Log2Exact(domain.trace_rows) + 1;
    out.evaluation_power_base =
        take(out.evaluation_power_count);
    out.vanishing = take(1);
    out.first_denominator_inverse = take(1);
    out.last_denominator_inverse = take(1);
    out.register_base =
        take(static_cast<uint32_t>(register_count));
    out.terminal_base =
        take(table.programs.size());
    out.lambda_power_base =
        take(table.programs.size());
    out.weighted_residual = take(1);
    out.active = take(1);
    if (cursor >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:recursive_bytecode_air:column_count";
        return out;
    }
    out.columns = static_cast<uint32_t>(cursor);
    out.instruction_registers =
        static_cast<uint32_t>(register_count);
    out.program_key = canonical_key;
    out.cs.n_rows = out.air_rows;
    out.cs.n_columns = out.columns;
    out.cs.preprocessed_pin_ood = true;
    out.witness.assign(
        out.columns,
        std::vector<Fp3>(
            out.air_rows, Fp3::Zero()));

    std::vector<Fp3> active_values(
        out.air_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < out.semantic_rows; ++row) {
        active_values[row] = Fp3::One();
        out.witness[out.active][row] =
            Fp3::One();
        for (uint32_t column = 0;
             column < table.current_width; ++column) {
            out.witness[
                out.source_current_base + column][row] =
                rows[row].current[column];
            out.witness[
                out.interpreter_current_base + column][row] =
                rows[row].current[column];
        }
        for (uint32_t column = 0;
             column < table.next_width; ++column) {
            out.witness[
                out.source_next_base + column][row] =
                rows[row].next[column];
            out.witness[
                out.interpreter_next_base + column][row] =
                rows[row].next[column];
        }
        for (uint32_t column = 0;
             column < table.challenge_width; ++column) {
            out.witness[
                out.source_challenge_base + column][row] =
                rows[row].challenge[column];
            out.witness[
                out.interpreter_challenge_base + column][row] =
                rows[row].challenge[column];
        }
        out.witness[out.source_lambda][row] =
            rows[row].constraint_lambda;
        out.witness[out.interpreter_lambda][row] =
            rows[row].constraint_lambda;
        out.witness[out.source_query_index][row] =
            gf::FromU64_3(
                rows[row].query_index);
        out.witness[
            out.source_evaluation_point][row] =
            rows[row].evaluation_point;
        out.witness[
            out.source_next_evaluation_point][row] =
            rows[row].next_evaluation_point;
        out.witness[
            out.source_quotient_opening][row] =
            rows[row].quotient_opening;
        Fp3 query_accumulator =
            Fp3::One();
        out.witness[
            out.query_power_accumulator_base][row] =
            query_accumulator;
        Fp3 omega_power =
            domain.evaluation_omega;
        for (uint32_t bit = 0;
             bit < out.query_bit_count; ++bit) {
            const bool set =
                ((rows[row].query_index >> bit) &
                 1U) != 0;
            out.witness[
                out.query_bit_base + bit][row] =
                set
                ? Fp3::One()
                : Fp3::Zero();
            const Fp3 factor =
                set
                ? omega_power
                : Fp3::One();
            query_accumulator = gf::Mul(
                query_accumulator, factor);
            out.witness[
                out.query_power_accumulator_base +
                bit + 1][row] =
                query_accumulator;
            omega_power = gf::Mul(
                omega_power, omega_power);
        }
        Fp3 square = rows[row].evaluation_point;
        for (uint32_t power_index = 0;
             power_index <
                 out.evaluation_power_count;
             ++power_index) {
            out.witness[
                out.evaluation_power_base +
                power_index][row] = square;
            square = gf::Mul(square, square);
        }
        const Fp3 zh = gf::Sub(
            Pow(
                rows[row].evaluation_point,
                domain.trace_rows),
            Fp3::One());
        out.witness[out.vanishing][row] = zh;
        out.witness[
            out.first_denominator_inverse][row] =
            gf::Inv(
                gf::Sub(
                    rows[row].evaluation_point,
                    Fp3::One()));
        const Fp3 h_last =
            gf::Inv(domain.trace_omega);
        out.witness[
            out.last_denominator_inverse][row] =
            gf::Inv(
                gf::Sub(
                    rows[row].evaluation_point,
                    h_last));

        uint32_t register_offset = 0;
        Fp3 power = Fp3::One();
        Fp3 weighted = Fp3::Zero();
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size(); ++ordinal) {
            const auto& program =
                table.programs[ordinal];
            std::vector<Fp3> registers;
            registers.reserve(
                program.instructions.size());
            for (const auto& instruction :
                 program.instructions) {
                Fp3 value = Fp3::Zero();
                switch (instruction.opcode) {
                case cb::Opcode::Current:
                    value =
                        rows[row].current[
                            instruction.lhs];
                    break;
                case cb::Opcode::Next:
                    value =
                        rows[row].next[
                            instruction.lhs];
                    break;
                case cb::Opcode::Challenge:
                    value =
                        rows[row].challenge[
                            instruction.lhs];
                    break;
                case cb::Opcode::Constant:
                    value = instruction.constant;
                    break;
                case cb::Opcode::Add:
                    value = gf::Add(
                        registers[instruction.lhs],
                        registers[instruction.rhs]);
                    break;
                case cb::Opcode::Sub:
                    value = gf::Sub(
                        registers[instruction.lhs],
                        registers[instruction.rhs]);
                    break;
                case cb::Opcode::Mul:
                    value = gf::Mul(
                        registers[instruction.lhs],
                        registers[instruction.rhs]);
                    break;
                }
                registers.push_back(value);
                out.witness[
                    out.register_base +
                    register_offset +
                    registers.size() - 1][row] =
                    value;
            }
            const Fp3 terminal =
                registers.back();
            out.witness[
                out.terminal_base + ordinal][row] =
                terminal;
            out.witness[
                out.lambda_power_base + ordinal][row] =
                power;
            Fp3 selector = Fp3::Zero();
            switch (program.kind) {
            case aq::AirKind::kEverywhere:
                selector = Fp3::One();
                break;
            case aq::AirKind::kTransition:
                selector = gf::Sub(
                    rows[row].evaluation_point,
                    h_last);
                break;
            case aq::AirKind::kFirstRow:
                selector = gf::Mul(
                    zh,
                    out.witness[
                        out.first_denominator_inverse][row]);
                break;
            case aq::AirKind::kLastRow:
                selector = gf::Mul(
                    zh,
                    out.witness[
                        out.last_denominator_inverse][row]);
                break;
            }
            out.witness[
                out.interpreter_selector_base +
                ordinal][row] = selector;
            weighted = gf::Add(
                weighted,
                gf::Mul(
                    selector,
                    gf::Mul(power, terminal)));
            power = gf::Mul(
                power,
                rows[row].constraint_lambda);
            register_offset +=
                program.instructions.size();
        }
        out.witness[out.weighted_residual][row] =
            weighted;
    }
    out.cs.preprocessed.push_back(
        {out.active, active_values});

    Add(
        out.cs,
        "stage3.recursive_bytecode.active_boolean",
        aq::AirKind::kEverywhere, 2,
        [active = out.active](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Mul(
                current[active],
                gf::Sub(
                    current[active], Fp3::One()));
        });
    for (uint32_t column = 0;
         column < table.current_width; ++column) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.current_alias",
            aq::AirKind::kEverywhere, 2,
            [active = out.active,
             source =
                 out.source_current_base + column,
             interpreted =
                 out.interpreter_current_base + column](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    current[active],
                    gf::Sub(
                        current[interpreted],
                        current[source]));
            });
    }
    for (uint32_t column = 0;
         column < table.next_width; ++column) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.next_alias",
            aq::AirKind::kEverywhere, 2,
            [active = out.active,
             source = out.source_next_base + column,
             interpreted =
                 out.interpreter_next_base + column](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    current[active],
                    gf::Sub(
                        current[interpreted],
                        current[source]));
            });
    }
    for (uint32_t column = 0;
         column < table.challenge_width; ++column) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.challenge_alias",
            aq::AirKind::kEverywhere, 2,
            [active = out.active,
             source =
                 out.source_challenge_base + column,
             interpreted =
                 out.interpreter_challenge_base + column](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    current[active],
                    gf::Sub(
                        current[interpreted],
                        current[source]));
            });
    }
    Add(
        out.cs,
        "stage3.recursive_bytecode.lambda_alias",
        aq::AirKind::kEverywhere, 2,
        [active = out.active,
         source = out.source_lambda,
         interpreted = out.interpreter_lambda](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Mul(
                current[active],
                gf::Sub(
                    current[interpreted],
                    current[source]));
        });
    for (uint32_t bit = 0;
         bit < out.query_bit_count; ++bit) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.query_bit_boolean",
            aq::AirKind::kEverywhere, 3,
            [active = out.active,
             bit_column = out.query_bit_base + bit](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[active],
                    gf::Mul(
                        row[bit_column],
                        gf::Sub(
                            row[bit_column],
                            Fp3::One())));
            });
    }
    Add(
        out.cs,
        "stage3.recursive_bytecode.query_index_bits",
        aq::AirKind::kEverywhere, 2,
        [active = out.active,
         query = out.source_query_index,
         bits = out.query_bit_base,
         count = out.query_bit_count](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 reconstructed =
                Fp3::Zero();
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < count; ++bit) {
                reconstructed = gf::Add(
                    reconstructed,
                    gf::Mul(
                        gf::FromU64_3(weight),
                        row[bits + bit]));
                weight <<= 1;
            }
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[query],
                    reconstructed));
        });
    Add(
        out.cs,
        "stage3.recursive_bytecode.query_power_first",
        aq::AirKind::kEverywhere, 2,
        [active = out.active,
         accumulator =
             out.query_power_accumulator_base](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[accumulator],
                    Fp3::One()));
        });
    Fp3 omega_power =
        domain.evaluation_omega;
    for (uint32_t bit = 0;
         bit < out.query_bit_count; ++bit) {
        const Fp3 bit_omega =
            omega_power;
        Add(
            out.cs,
            "stage3.recursive_bytecode.query_power_step",
            aq::AirKind::kEverywhere, 4,
            [active = out.active,
             bit_column =
                 out.query_bit_base + bit,
             previous =
                 out.query_power_accumulator_base +
                 bit,
             current =
                 out.query_power_accumulator_base +
                 bit + 1,
             bit_omega](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 factor = gf::Add(
                    Fp3::One(),
                    gf::Mul(
                        row[bit_column],
                        gf::Sub(
                            bit_omega,
                            Fp3::One())));
                return gf::Mul(
                    row[active],
                    gf::Sub(
                        row[current],
                        gf::Mul(
                            row[previous],
                            factor)));
            });
        omega_power =
            gf::Mul(
                omega_power, omega_power);
    }
    Add(
        out.cs,
        "stage3.recursive_bytecode.query_to_evaluation_point",
        aq::AirKind::kEverywhere, 3,
        [active = out.active,
         z = out.source_evaluation_point,
         accumulator =
             out.query_power_accumulator_base +
             out.query_bit_count,
         shift = domain.coset_shift](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[z],
                    gf::Mul(
                        shift,
                        row[accumulator])));
        });
    Add(
        out.cs,
        "stage3.recursive_bytecode.next_point_omega_z",
        aq::AirKind::kEverywhere, 3,
        [active = out.active,
         z = out.source_evaluation_point,
         next_z =
             out.source_next_evaluation_point,
         omega = domain.trace_omega](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[next_z],
                    gf::Mul(omega, row[z])));
        });
    for (uint32_t power_index = 0;
         power_index <
             out.evaluation_power_count;
         ++power_index) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.evaluation_power",
            aq::AirKind::kEverywhere, 3,
            [active = out.active,
             z = out.source_evaluation_point,
             current =
                 out.evaluation_power_base +
                 power_index,
             previous =
                 power_index == 0
                 ? out.evaluation_power_base
                 : out.evaluation_power_base +
                     power_index - 1,
             first = power_index == 0](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 expected =
                    first
                    ? row[z]
                    : gf::Mul(
                        row[previous],
                        row[previous]);
                return gf::Mul(
                    row[active],
                    gf::Sub(
                        row[current], expected));
            });
    }
    Add(
        out.cs,
        "stage3.recursive_bytecode.vanishing",
        aq::AirKind::kEverywhere, 2,
        [active = out.active,
         last_power =
             out.evaluation_power_base +
             out.evaluation_power_count - 1,
         vanishing = out.vanishing](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[vanishing],
                    gf::Sub(
                        row[last_power],
                        Fp3::One())));
        });
    Add(
        out.cs,
        "stage3.recursive_bytecode.first_denominator_inverse",
        aq::AirKind::kEverywhere, 3,
        [active = out.active,
         z = out.source_evaluation_point,
         inverse =
             out.first_denominator_inverse](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    gf::Mul(
                        gf::Sub(
                            row[z],
                            Fp3::One()),
                        row[inverse]),
                    Fp3::One()));
        });
    const Fp3 h_last =
        gf::Inv(domain.trace_omega);
    Add(
        out.cs,
        "stage3.recursive_bytecode.last_denominator_inverse",
        aq::AirKind::kEverywhere, 3,
        [active = out.active,
         z = out.source_evaluation_point,
         inverse =
             out.last_denominator_inverse,
         h_last](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    gf::Mul(
                        gf::Sub(row[z], h_last),
                        row[inverse]),
                    Fp3::One()));
        });
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        const aq::AirKind kind =
            table.programs[ordinal].kind;
        Add(
            out.cs,
            "stage3.recursive_bytecode.selector_derived",
            aq::AirKind::kEverywhere, 3,
            [active = out.active,
             selector =
                 out.interpreter_selector_base +
                 ordinal,
             z = out.source_evaluation_point,
             vanishing = out.vanishing,
             first_inverse =
                 out.first_denominator_inverse,
             last_inverse =
                 out.last_denominator_inverse,
             h_last,
             kind](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 expected = Fp3::Zero();
                switch (kind) {
                case aq::AirKind::kEverywhere:
                    expected = Fp3::One();
                    break;
                case aq::AirKind::kTransition:
                    expected =
                        gf::Sub(row[z], h_last);
                    break;
                case aq::AirKind::kFirstRow:
                    expected = gf::Mul(
                        row[vanishing],
                        row[first_inverse]);
                    break;
                case aq::AirKind::kLastRow:
                    expected = gf::Mul(
                        row[vanishing],
                        row[last_inverse]);
                    break;
                }
                return gf::Mul(
                    row[active],
                    gf::Sub(
                        row[selector], expected));
            });
    }

    uint32_t register_offset = 0;
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        const auto& program = table.programs[ordinal];
        for (uint32_t instruction_index = 0;
             instruction_index <
                 program.instructions.size();
             ++instruction_index) {
            const auto instruction =
                program.instructions[
                    instruction_index];
            const uint32_t output =
                out.register_base +
                register_offset +
                instruction_index;
            Add(
                out.cs,
                "stage3.recursive_bytecode.ssa_instruction",
                aq::AirKind::kEverywhere,
                std::max<uint32_t>(
                    2,
                    instruction.opcode ==
                            cb::Opcode::Mul
                        ? 3
                        : 2),
                [active = out.active,
                 output,
                 register_base =
                     out.register_base +
                     register_offset,
                 current_base =
                     out.interpreter_current_base,
                 next_base =
                     out.interpreter_next_base,
                 challenge_base =
                     out.interpreter_challenge_base,
                 instruction](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    Fp3 expected = Fp3::Zero();
                    switch (instruction.opcode) {
                    case cb::Opcode::Current:
                        expected =
                            row[current_base +
                                instruction.lhs];
                        break;
                    case cb::Opcode::Next:
                        expected =
                            row[next_base +
                                instruction.lhs];
                        break;
                    case cb::Opcode::Challenge:
                        expected =
                            row[challenge_base +
                                instruction.lhs];
                        break;
                    case cb::Opcode::Constant:
                        expected =
                            instruction.constant;
                        break;
                    case cb::Opcode::Add:
                        expected = gf::Add(
                            row[register_base +
                                instruction.lhs],
                            row[register_base +
                                instruction.rhs]);
                        break;
                    case cb::Opcode::Sub:
                        expected = gf::Sub(
                            row[register_base +
                                instruction.lhs],
                            row[register_base +
                                instruction.rhs]);
                        break;
                    case cb::Opcode::Mul:
                        expected = gf::Mul(
                            row[register_base +
                                instruction.lhs],
                            row[register_base +
                                instruction.rhs]);
                        break;
                    }
                    return gf::Mul(
                        row[active],
                        gf::Sub(row[output], expected));
                });
        }
        const uint32_t terminal_register =
            out.register_base +
            register_offset +
            program.instructions.size() - 1;
        Add(
            out.cs,
            "stage3.recursive_bytecode.terminal",
            aq::AirKind::kEverywhere, 2,
            [active = out.active,
             terminal =
                 out.terminal_base + ordinal,
             terminal_register](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[active],
                    gf::Sub(
                        row[terminal],
                        row[terminal_register]));
            });
        register_offset +=
            program.instructions.size();
    }
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.lambda_power",
            aq::AirKind::kEverywhere,
            ordinal == 0 ? 2 : 3,
            [active = out.active,
             power = out.lambda_power_base + ordinal,
             previous =
                 ordinal == 0
                 ? out.lambda_power_base
                 : out.lambda_power_base +
                     ordinal - 1,
             lambda = out.interpreter_lambda,
             first = ordinal == 0](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 expected =
                    first
                    ? Fp3::One()
                    : gf::Mul(
                        row[previous],
                        row[lambda]);
                return gf::Mul(
                    row[active],
                    gf::Sub(
                        row[power], expected));
            });
    }
    Add(
        out.cs,
        "stage3.recursive_bytecode.weighted_residual",
        aq::AirKind::kEverywhere, 4,
        [active = out.active,
         weighted = out.weighted_residual,
         selector_base =
             out.interpreter_selector_base,
         terminal_base = out.terminal_base,
         power_base = out.lambda_power_base,
         count =
             static_cast<uint32_t>(
                 table.programs.size())](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 expected = Fp3::Zero();
            for (uint32_t ordinal = 0;
                 ordinal < count; ++ordinal) {
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        row[selector_base + ordinal],
                        gf::Mul(
                            row[power_base + ordinal],
                            row[terminal_base + ordinal])));
            }
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[weighted], expected));
        });
    Add(
        out.cs,
        "stage3.recursive_bytecode.quotient_feed",
        aq::AirKind::kEverywhere, 3,
        [active = out.active,
         weighted = out.weighted_residual,
         quotient = out.source_quotient_opening,
         vanishing = out.vanishing](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[active],
                gf::Sub(
                    row[weighted],
                    gf::Mul(
                        row[quotient],
                        row[vanishing])));
        });

    // No inactive witness cell can carry an unconstrained alternate
    // interpretation. ACTIVE itself is immutable preprocessing.
    for (uint32_t column = 0;
         column < out.active; ++column) {
        Add(
            out.cs,
            "stage3.recursive_bytecode.padding_zero",
            aq::AirKind::kEverywhere, 2,
            [active = out.active, column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[active]),
                    row[column]);
            });
    }
    out.constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    const uint32_t violations =
        CountViolations(out.cs, out.witness);
    out.caller_selected_program_key =
        canonical_key == selected_program_key;
    out.current_next_direct_aliases = true;
    out.challenge_columns_direct_aliases = true;
    out.selectors_derived_from_evaluation_point =
        true;
    out.lambda_direct_alias = true;
    out.next_opening_point_is_omega_z = true;
    out.quotient_vanishing_identity_constrained =
        true;
    out.proof_sources_authenticated_by_parent =
        false;
    out.current_next_values_bound_to_pcs_openings =
        false;
    out.query_index_to_evaluation_point_in_air =
        true;
    out.canonical_ssa_executes =
        violations == 0;
    out.terminals_feed_quotient_residual =
        violations == 0;
    out.padding_zero_constrained = true;
    out.constant_width_universal = false;
    out.recursive_fixed_point = false;
    out.authority = false;
    out.valid =
        out.caller_selected_program_key &&
        out.current_next_direct_aliases &&
        out.challenge_columns_direct_aliases &&
        out.selectors_derived_from_evaluation_point &&
        out.lambda_direct_alias &&
        out.next_opening_point_is_omega_z &&
        out.quotient_vanishing_identity_constrained &&
        !out.proof_sources_authenticated_by_parent &&
        !out.current_next_values_bound_to_pcs_openings &&
        out.query_index_to_evaluation_point_in_air &&
        out.canonical_ssa_executes &&
        out.terminals_feed_quotient_residual &&
        out.padding_zero_constrained &&
        !out.constant_width_universal &&
        !out.recursive_fixed_point &&
        !out.authority;
    out.note = out.valid
        ? "stage3:recursive_bytecode_air:"
          "canonical_ssa_and_quotient_feed_executable;"
          "universal_fixed_point_false"
        : "stage3:recursive_bytecode_air:"
          "constraint_violation";
    return out;
}

bool ValidateCanonicalBytecodeQuotientAirV1(
    const cb::ProgramTable& table,
    const alg_hash::Digest& selected_program_key,
    const QuotientDomainV1& domain,
    const std::vector<QuotientOpeningRowV1>& rows,
    const CanonicalBytecodeQuotientAirV1& candidate,
    std::string* why)
{
    const auto expected =
        BuildCanonicalBytecodeQuotientAirV1(
            table, selected_program_key,
            domain, rows);
    const auto fail = [why](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{
                    "stage3:recursive_bytecode_air:"} +
                detail;
        }
        return false;
    };
    if (!expected.valid ||
        !candidate.valid) {
        return fail("candidate_invalid");
    }
    if (candidate.version != expected.version ||
        candidate.semantic_rows !=
            expected.semantic_rows ||
        candidate.air_rows != expected.air_rows ||
        candidate.columns != expected.columns ||
        candidate.constraints != expected.constraints ||
        candidate.instruction_registers !=
            expected.instruction_registers ||
        candidate.program_key !=
            expected.program_key ||
        candidate.caller_selected_program_key !=
            expected.caller_selected_program_key ||
        candidate.current_next_direct_aliases !=
            expected.current_next_direct_aliases ||
        candidate.challenge_columns_direct_aliases !=
            expected.challenge_columns_direct_aliases ||
        candidate.selectors_derived_from_evaluation_point !=
            expected.selectors_derived_from_evaluation_point ||
        candidate.lambda_direct_alias !=
            expected.lambda_direct_alias ||
        candidate.next_opening_point_is_omega_z !=
            expected.next_opening_point_is_omega_z ||
        candidate.quotient_vanishing_identity_constrained !=
            expected.quotient_vanishing_identity_constrained ||
        candidate.proof_sources_authenticated_by_parent ||
        candidate.current_next_values_bound_to_pcs_openings ||
        !candidate.query_index_to_evaluation_point_in_air ||
        candidate.canonical_ssa_executes !=
            expected.canonical_ssa_executes ||
        candidate.terminals_feed_quotient_residual !=
            expected.terminals_feed_quotient_residual ||
        candidate.padding_zero_constrained !=
            expected.padding_zero_constrained ||
        candidate.constant_width_universal ||
        candidate.recursive_fixed_point ||
        candidate.authority ||
        !SameWitness(
            candidate.witness,
            expected.witness) ||
        CountViolations(
            candidate.cs,
            candidate.witness) != 0) {
        return fail("substitution");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_bytecode_air:ok";
    }
    return true;
}

} // namespace matmul::v4::rc::recursive_bytecode_air
