// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_constant_width_bytecode_air.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::constant_width_bytecode_air {
namespace {

using gf::Fp3;

constexpr char CONSTANT_WIDTH_BYTECODE_DOMAIN[] =
    "BTX_RC_STAGE3_CONSTANT_WIDTH_BYTECODE_AIR_V1";

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1U)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint32_t>::max() / 2) {
            return 0;
        }
        out <<= 1;
    }
    return out;
}

uint64_t NextPowerOfTwo64(uint64_t value)
{
    uint64_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint64_t>::max() / 2) {
            return 0;
        }
        out <<= 1;
    }
    return out;
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

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
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
        [](gf::Fp limb) {
            return gf::Canonical(limb) == 0;
        });
}

bool SameDigest(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) !=
            gf::Canonical(b[i])) {
            return false;
        }
    }
    return true;
}

bool DomainValid(const rba::QuotientDomainV1& domain)
{
    return
        IsPowerOfTwo(domain.trace_rows) &&
        IsPowerOfTwo(domain.evaluation_rows) &&
        domain.evaluation_rows >=
            domain.trace_rows &&
        domain.evaluation_rows %
                domain.trace_rows ==
            0 &&
        gf::Eq(
            Pow(
                domain.trace_omega,
                domain.trace_rows),
            Fp3::One()) &&
        !gf::Eq(
            Pow(
                domain.trace_omega,
                domain.trace_rows / 2),
            Fp3::One()) &&
        gf::Eq(
            Pow(
                domain.evaluation_omega,
                domain.evaluation_rows),
            Fp3::One()) &&
        !gf::Eq(
            Pow(
                domain.evaluation_omega,
                domain.evaluation_rows / 2),
            Fp3::One()) &&
        gf::Eq(
            domain.trace_omega,
            Pow(
                domain.evaluation_omega,
                domain.evaluation_rows /
                    domain.trace_rows)) &&
        !gf::IsZero(domain.coset_shift);
}

struct Emitter {
    std::vector<cb::Instruction> code;
    std::vector<uint32_t> degrees;

    uint32_t Current(uint32_t column)
    {
        code.push_back({
            cb::Opcode::Current, column, 0,
            Fp3::Zero()});
        degrees.push_back(1);
        return static_cast<uint32_t>(
            code.size() - 1);
    }

    uint32_t Next(uint32_t column)
    {
        code.push_back({
            cb::Opcode::Next, column, 0,
            Fp3::Zero()});
        degrees.push_back(1);
        return static_cast<uint32_t>(
            code.size() - 1);
    }

    uint32_t Constant(Fp3 value)
    {
        code.push_back({
            cb::Opcode::Constant, 0, 0, value});
        degrees.push_back(0);
        return static_cast<uint32_t>(
            code.size() - 1);
    }

    uint32_t Binary(
        cb::Opcode opcode,
        uint32_t lhs,
        uint32_t rhs)
    {
        code.push_back({
            opcode, lhs, rhs, Fp3::Zero()});
        const uint32_t degree =
            opcode == cb::Opcode::Mul
            ? degrees[lhs] + degrees[rhs]
            : std::max(
                degrees[lhs], degrees[rhs]);
        degrees.push_back(degree);
        return static_cast<uint32_t>(
            code.size() - 1);
    }

    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Add, lhs, rhs);
    }

    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Sub, lhs, rhs);
    }

    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Mul, lhs, rhs);
    }

    uint32_t AppendOriginal(
        const cb::Program& program,
        const SourceLayoutV1& layout)
    {
        const uint32_t base =
            static_cast<uint32_t>(code.size());
        for (const auto& instruction :
             program.instructions) {
            switch (instruction.opcode) {
            case cb::Opcode::Current:
                Current(
                    layout.current_base +
                    instruction.lhs);
                break;
            case cb::Opcode::Next:
                // The child proof's next opening is a separate, authenticated
                // source-tape range in the same quotient-query row. It is not
                // the next quotient-query row.
                Current(
                    layout.next_base +
                    instruction.lhs);
                break;
            case cb::Opcode::Constant:
                Constant(instruction.constant);
                break;
            case cb::Opcode::Add:
            case cb::Opcode::Sub:
            case cb::Opcode::Mul:
                Binary(
                    instruction.opcode,
                    base + instruction.lhs,
                    base + instruction.rhs);
                break;
            case cb::Opcode::Challenge:
                Current(
                    layout.challenge_base +
                    instruction.lhs);
                break;
            }
        }
        return static_cast<uint32_t>(
            code.size() - 1);
    }
};

bool AppendProgram(
    cb::ProgramTable& table,
    air_quotient::AirKind kind,
    Emitter emitter)
{
    if (emitter.code.empty() ||
        emitter.code.size() >
            cb::kConstraintBytecodeMaxInstructions ||
        emitter.degrees.back() == 0) {
        return false;
    }
    cb::Program program;
    program.role = table.role;
    program.constraint_ordinal =
        static_cast<uint32_t>(
            table.programs.size());
    program.kind = kind;
    program.declared_degree =
        emitter.degrees.back();
    program.current_width =
        table.current_width;
    program.next_width =
        table.next_width;
    program.challenge_width = 0;
    program.instructions =
        std::move(emitter.code);
    table.programs.push_back(
        std::move(program));
    return true;
}

SourceLayoutV1 BuildLayout(
    const cb::ProgramTable& table,
    const rba::QuotientDomainV1& domain)
{
    SourceLayoutV1 out;
    uint64_t cursor = 0;
    const auto take = [&cursor](uint32_t count) {
        const uint32_t base =
            static_cast<uint32_t>(cursor);
        cursor += count;
        return base;
    };
    out.current_base =
        take(table.current_width);
    out.next_base =
        take(table.next_width);
    out.challenge_width =
        table.challenge_width;
    out.challenge_base =
        take(table.challenge_width);
    out.constraint_lambda = take(1);
    out.query_index = take(1);
    out.evaluation_point = take(1);
    out.next_evaluation_point = take(1);
    out.quotient_opening = take(1);
    out.first_denominator_inverse = take(1);
    out.last_denominator_inverse = take(1);
    out.semantic_ordinal = take(1);
    out.active = take(1);
    out.cut = take(1);
    out.cut_inverse = take(1);
    out.query_bit_count =
        Log2Exact(domain.evaluation_rows);
    out.query_bit_base =
        take(out.query_bit_count);
    out.source_width =
        cursor <=
            std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(cursor)
        : 0;
    return out;
}

bool BuildCompiledTable(
    const cb::ProgramTable& selected,
    const rba::QuotientDomainV1& domain,
    uint32_t semantic_rows,
    uint32_t padded_rows,
    const SourceLayoutV1& layout,
    cb::ProgramTable& out)
{
    out = {};
    out.role = selected.role;
    out.current_width = layout.source_width;
    // Schedule constraints use the next VM source row. Original bytecode Next
    // loads were already redirected to layout.next_base above.
    out.next_width = layout.source_width;
    out.challenge_width = 0;

    // Immutable active/cut/ordinal schedule. This gives Q=192 a canonical
    // 256-row carrier without letting a prover choose which 192 rows count.
    {
        Emitter e;
        const auto active =
            e.Current(layout.active);
        const auto one =
            e.Constant(Fp3::One());
        const auto delta =
            e.Sub(active, one);
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                [&] {
                    Emitter p = std::move(e);
                    p.Mul(active, delta);
                    return p;
                }())) return false;
    }
    {
        Emitter e;
        e.Current(layout.semantic_ordinal);
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kFirstRow,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto active =
            e.Current(layout.active);
        const auto one =
            e.Constant(Fp3::One());
        e.Sub(active, one);
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kFirstRow,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto next =
            e.Next(layout.semantic_ordinal);
        const auto current =
            e.Current(layout.semantic_ordinal);
        const auto one =
            e.Constant(Fp3::One());
        e.Sub(next, e.Add(current, one));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kTransition,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto cut =
            e.Current(layout.cut);
        const auto one =
            e.Constant(Fp3::One());
        e.Mul(cut, e.Sub(cut, one));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto ordinal =
            e.Current(layout.semantic_ordinal);
        const auto target =
            e.Constant(U(semantic_rows - 1U));
        const auto cut =
            e.Current(layout.cut);
        e.Mul(e.Sub(ordinal, target), cut);
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto ordinal =
            e.Current(layout.semantic_ordinal);
        const auto target =
            e.Constant(U(semantic_rows - 1U));
        const auto inverse =
            e.Current(layout.cut_inverse);
        const auto one =
            e.Constant(Fp3::One());
        const auto cut =
            e.Current(layout.cut);
        e.Sub(
            e.Mul(
                e.Sub(ordinal, target),
                inverse),
            e.Sub(one, cut));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto next =
            e.Next(layout.active);
        const auto active =
            e.Current(layout.active);
        const auto one =
            e.Constant(Fp3::One());
        const auto cut =
            e.Current(layout.cut);
        e.Sub(
            next,
            e.Mul(active, e.Sub(one, cut)));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kTransition,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto ordinal =
            e.Current(layout.semantic_ordinal);
        const auto last =
            e.Constant(U(padded_rows - 1U));
        e.Sub(ordinal, last);
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kLastRow,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto active =
            e.Current(layout.active);
        const auto expected =
            e.Constant(
                semantic_rows == padded_rows
                ? Fp3::One()
                : Fp3::Zero());
        e.Sub(active, expected);
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kLastRow,
                std::move(e))) return false;
    }

    // A relation challenge is drawn once by the parent transcript and is
    // identical at every quotient opening. The tape is disjoint from
    // current/next openings; parent-FS ownership is a separate outer link.
    for (uint32_t challenge = 0;
         challenge < layout.challenge_width;
         ++challenge) {
        Emitter e;
        const auto active =
            e.Current(layout.active);
        const auto next_active =
            e.Next(layout.active);
        const auto current =
            e.Current(
                layout.challenge_base + challenge);
        const auto next =
            e.Next(
                layout.challenge_base + challenge);
        e.Mul(
            active,
            e.Mul(
                next_active,
                e.Sub(next, current)));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kTransition,
                std::move(e))) return false;
    }

    // Query index range and z = shift * omega^index. All semantic checks are
    // multiplied by ACTIVE; padding cells therefore have one canonical zero
    // interpretation.
    for (uint32_t bit = 0;
         bit < layout.query_bit_count; ++bit) {
        Emitter e;
        const auto active =
            e.Current(layout.active);
        const auto value =
            e.Current(
                layout.query_bit_base + bit);
        const auto one =
            e.Constant(Fp3::One());
        e.Mul(
            active,
            e.Mul(value, e.Sub(value, one)));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        uint32_t reconstructed =
            e.Constant(Fp3::Zero());
        uint64_t weight = 1;
        for (uint32_t bit = 0;
             bit < layout.query_bit_count;
             ++bit) {
            const auto coefficient =
                e.Constant(U(weight));
            const auto value =
                e.Current(
                    layout.query_bit_base + bit);
            reconstructed = e.Add(
                reconstructed,
                e.Mul(coefficient, value));
            weight <<= 1;
        }
        const auto claimed =
            e.Current(layout.query_index);
        const auto active =
            e.Current(layout.active);
        e.Mul(
            active,
            e.Sub(reconstructed, claimed));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        uint32_t accumulator =
            e.Constant(Fp3::One());
        Fp3 omega_power =
            domain.evaluation_omega;
        for (uint32_t bit = 0;
             bit < layout.query_bit_count;
             ++bit) {
            const auto one =
                e.Constant(Fp3::One());
            const auto value =
                e.Current(
                    layout.query_bit_base + bit);
            const auto delta =
                e.Constant(
                    gf::Sub(
                        omega_power,
                        Fp3::One()));
            const auto factor =
                e.Add(one, e.Mul(value, delta));
            accumulator =
                e.Mul(accumulator, factor);
            omega_power =
                gf::Mul(
                    omega_power, omega_power);
        }
        const auto shift =
            e.Constant(domain.coset_shift);
        const auto expected =
            e.Mul(shift, accumulator);
        const auto claimed =
            e.Current(layout.evaluation_point);
        const auto active =
            e.Current(layout.active);
        e.Mul(active, e.Sub(claimed, expected));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto next =
            e.Current(
                layout.next_evaluation_point);
        const auto omega =
            e.Constant(domain.trace_omega);
        const auto z =
            e.Current(layout.evaluation_point);
        const auto active =
            e.Current(layout.active);
        e.Mul(
            active,
            e.Sub(next, e.Mul(omega, z)));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto z =
            e.Current(layout.evaluation_point);
        const auto one =
            e.Constant(Fp3::One());
        const auto inverse =
            e.Current(
                layout.first_denominator_inverse);
        const auto active =
            e.Current(layout.active);
        e.Mul(
            active,
            e.Sub(
                e.Mul(e.Sub(z, one), inverse),
                e.Constant(Fp3::One())));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    {
        Emitter e;
        const auto z =
            e.Current(layout.evaluation_point);
        const auto h_last =
            e.Constant(
                gf::Inv(domain.trace_omega));
        const auto inverse =
            e.Current(
                layout.last_denominator_inverse);
        const auto active =
            e.Current(layout.active);
        e.Mul(
            active,
            e.Sub(
                e.Mul(
                    e.Sub(z, h_last),
                    inverse),
                e.Constant(Fp3::One())));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }

    // One canonical instruction-step program executes every source program,
    // derives its row selector, folds terminals by successive lambda powers,
    // and enforces sum(lambda^i selector_i C_i) = Q(z) Z_H(z).
    {
        Emitter e;
        const auto active =
            e.Current(layout.active);
        const auto z =
            e.Current(layout.evaluation_point);
        uint32_t z_power = z;
        for (uint32_t bit = 0;
             bit < Log2Exact(domain.trace_rows);
             ++bit) {
            z_power =
                e.Mul(z_power, z_power);
        }
        const auto zh =
            e.Sub(
                z_power,
                e.Constant(Fp3::One()));
        const bool needs_lambda =
            selected.programs.size() > 1;
        const bool has_transition =
            std::any_of(
                selected.programs.begin(),
                selected.programs.end(),
                [](const cb::Program& program) {
                    return program.kind ==
                        air_quotient::AirKind::
                            kTransition;
                });
        const bool has_first =
            std::any_of(
                selected.programs.begin(),
                selected.programs.end(),
                [](const cb::Program& program) {
                    return program.kind ==
                        air_quotient::AirKind::
                            kFirstRow;
                });
        const bool has_last =
            std::any_of(
                selected.programs.begin(),
                selected.programs.end(),
                [](const cb::Program& program) {
                    return program.kind ==
                        air_quotient::AirKind::
                            kLastRow;
                });
        const uint32_t lambda =
            needs_lambda
            ? e.Current(layout.constraint_lambda)
            : 0;
        uint32_t lambda_power =
            e.Constant(Fp3::One());
        uint32_t weighted =
            e.Constant(Fp3::Zero());
        const uint32_t h_last =
            has_transition
            ? e.Constant(
                  gf::Inv(domain.trace_omega))
            : 0;
        const uint32_t first_inverse =
            has_first
            ? e.Current(
                  layout.first_denominator_inverse)
            : 0;
        const uint32_t last_inverse =
            has_last
            ? e.Current(
                  layout.last_denominator_inverse)
            : 0;
        for (uint32_t ordinal = 0;
             ordinal < selected.programs.size();
             ++ordinal) {
            const auto& original =
                selected.programs[ordinal];
            const uint32_t terminal =
                e.AppendOriginal(original, layout);
            if (terminal ==
                std::numeric_limits<uint32_t>::max()) {
                return false;
            }
            uint32_t selector = 0;
            switch (original.kind) {
            case air_quotient::AirKind::kEverywhere:
                selector =
                    e.Constant(Fp3::One());
                break;
            case air_quotient::AirKind::kTransition:
                selector =
                    e.Sub(z, h_last);
                break;
            case air_quotient::AirKind::kFirstRow:
                selector =
                    e.Mul(zh, first_inverse);
                break;
            case air_quotient::AirKind::kLastRow:
                selector =
                    e.Mul(zh, last_inverse);
                break;
            }
            const auto selected_terminal =
                e.Mul(terminal, selector);
            const auto weighted_terminal =
                e.Mul(
                    selected_terminal,
                    lambda_power);
            weighted =
                e.Add(weighted, weighted_terminal);
            if (ordinal + 1 <
                selected.programs.size()) {
                lambda_power =
                    e.Mul(lambda_power, lambda);
            }
        }
        const auto quotient =
            e.Current(layout.quotient_opening);
        const auto quotient_times_zh =
            e.Mul(quotient, zh);
        e.Mul(
            active,
            e.Sub(weighted, quotient_times_zh));
        if (!AppendProgram(
                out,
                air_quotient::AirKind::kEverywhere,
                std::move(e))) return false;
    }
    return cb::ValidateProgramTable(out);
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0)
         << gf::Canonical(value.c1)
         << gf::Canonical(value.c2);
}

void HashDigest(
    HashWriter& hash,
    const alg_hash::Digest& digest)
{
    for (const auto limb : digest) {
        hash << gf::Canonical(limb);
    }
}

uint256 StatementBinding(
    uint32_t program_id,
    const uint256& registry_root,
    const alg_hash::Digest& selected_key,
    const alg_hash::Digest& compiled_key,
    const rba::QuotientDomainV1& domain,
    const SourceLayoutV1& layout,
    uint32_t semantic_rows,
    uint32_t padded_rows)
{
    HashWriter hash;
    hash << CONSTANT_WIDTH_BYTECODE_DOMAIN
         << kConstantWidthBytecodeAirVersionV1
         << program_id
         << registry_root;
    HashDigest(hash, selected_key);
    HashDigest(hash, compiled_key);
    hash << domain.trace_rows
         << domain.evaluation_rows;
    HashFp3(hash, domain.trace_omega);
    HashFp3(hash, domain.evaluation_omega);
    HashFp3(hash, domain.coset_shift);
    hash << layout.current_base
         << layout.next_base
         << layout.challenge_base
         << layout.challenge_width
         << layout.constraint_lambda
         << layout.query_index
         << layout.evaluation_point
         << layout.next_evaluation_point
         << layout.quotient_opening
         << layout.first_denominator_inverse
         << layout.last_denominator_inverse
         << layout.semantic_ordinal
         << layout.active
         << layout.cut
         << layout.cut_inverse
         << layout.query_bit_base
         << layout.query_bit_count
         << layout.source_width
         << semantic_rows
         << padded_rows
         << vm::kFamilyVmExecutableColumnsV1;
    return hash.GetHash();
}

bool FillSourceColumns(
    const cb::ProgramTable& table,
    const rba::QuotientDomainV1& domain,
    const SourceLayoutV1& layout,
    uint32_t padded_rows,
    const std::vector<OpeningRowV1>& rows,
    std::vector<std::vector<Fp3>>& columns,
    std::string& why)
{
    columns.assign(
        layout.source_width,
        std::vector<Fp3>(
            padded_rows, Fp3::Zero()));
    const uint32_t semantic_rows =
        static_cast<uint32_t>(rows.size());
    const Fp3 h_last =
        gf::Inv(domain.trace_omega);
    for (uint32_t row = 0;
         row < padded_rows; ++row) {
        columns[layout.semantic_ordinal][row] =
            U(row);
        const Fp3 cut_delta =
            gf::Sub(
                U(row),
                U(semantic_rows - 1U));
        if (row + 1 == semantic_rows) {
            columns[layout.cut][row] =
                Fp3::One();
        } else {
            columns[layout.cut_inverse][row] =
                gf::Inv(cut_delta);
        }
        if (row >= semantic_rows) continue;
        const auto& owned = rows[row];
        const auto& opening = owned.quotient;
        if (opening.current.size() !=
                table.current_width ||
            opening.next.size() !=
                table.next_width ||
            owned.verifier_challenges.size() !=
                table.challenge_width ||
            opening.query_index >=
                domain.evaluation_rows ||
            !gf::Eq(
                opening.next_evaluation_point,
                gf::Mul(
                    domain.trace_omega,
                    opening.evaluation_point)) ||
            gf::IsZero(
                gf::Sub(
                    opening.evaluation_point,
                    Fp3::One())) ||
            gf::IsZero(
                gf::Sub(
                    opening.evaluation_point,
                    h_last))) {
            why =
                "stage3:constant_width_bytecode:"
                "opening_shape";
            return false;
        }
        columns[layout.active][row] =
            Fp3::One();
        for (uint32_t column = 0;
             column < table.current_width;
             ++column) {
            columns[
                layout.current_base + column][row] =
                opening.current[column];
        }
        for (uint32_t column = 0;
             column < table.next_width;
             ++column) {
            columns[
                layout.next_base + column][row] =
                opening.next[column];
        }
        for (uint32_t challenge = 0;
             challenge < table.challenge_width;
             ++challenge) {
            columns[
                layout.challenge_base +
                challenge][row] =
                owned.verifier_challenges[
                    challenge];
        }
        columns[layout.constraint_lambda][row] =
            opening.constraint_lambda;
        columns[layout.query_index][row] =
            U(opening.query_index);
        columns[layout.evaluation_point][row] =
            opening.evaluation_point;
        columns[
            layout.next_evaluation_point][row] =
            opening.next_evaluation_point;
        columns[layout.quotient_opening][row] =
            opening.quotient_opening;
        columns[
            layout.first_denominator_inverse][row] =
            gf::Inv(
                gf::Sub(
                    opening.evaluation_point,
                    Fp3::One()));
        columns[
            layout.last_denominator_inverse][row] =
            gf::Inv(
                gf::Sub(
                    opening.evaluation_point,
                    h_last));
        for (uint32_t bit = 0;
             bit < layout.query_bit_count;
             ++bit) {
            columns[
                layout.query_bit_base + bit][row] =
                ((opening.query_index >> bit) &
                 1U) != 0
                ? Fp3::One()
                : Fp3::Zero();
        }
    }
    return true;
}

} // namespace

CompiledQuotientProgramV1
CompileConstantWidthQuotientProgramV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    uint32_t semantic_rows)
{
    CompiledQuotientProgramV1 out;
    out.semantic_rows = semantic_rows;
    out.original_programs =
        static_cast<uint32_t>(
            selected_table.programs.size());
    for (const auto& program :
         selected_table.programs) {
        if (out.original_instructions >
            std::numeric_limits<uint32_t>::max() -
                program.instructions.size()) {
            out.note =
                "stage3:constant_width_bytecode:"
                "instruction_overflow";
            return out;
        }
        out.original_instructions +=
            static_cast<uint32_t>(
                program.instructions.size());
    }
    const auto canonical_key =
        cb::CommitProgramTableAlgHash(
            selected_table);
    if (!cb::ValidateProgramTable(
            selected_table) ||
        !DomainValid(domain) ||
        semantic_rows == 0 ||
        DigestIsZero(canonical_key) ||
        !SameDigest(
            canonical_key,
            selected_program_key)) {
        out.note =
            "stage3:constant_width_bytecode:"
            "source_statement";
        return out;
    }
    out.padded_rows =
        NextPowerOfTwo(semantic_rows);
    if (out.padded_rows == 0) {
        out.note =
            "stage3:constant_width_bytecode:"
            "padded_rows";
        return out;
    }
    out.layout =
        BuildLayout(selected_table, domain);
    if (out.layout.source_width == 0 ||
        !BuildCompiledTable(
            selected_table, domain,
            semantic_rows, out.padded_rows,
            out.layout, out.compiled_table)) {
        out.note =
            "stage3:constant_width_bytecode:"
            "compile";
        return out;
    }
    out.selected_program_key =
        canonical_key;
    out.compiled_program_key =
        cb::CommitProgramTableAlgHash(
            out.compiled_table);
    if (DigestIsZero(
            out.compiled_program_key)) {
        out.note =
            "stage3:constant_width_bytecode:"
            "compiled_key";
        return out;
    }
    out.compiled_programs =
        static_cast<uint32_t>(
            out.compiled_table.programs.size());
    for (const auto& program :
         out.compiled_table.programs) {
        out.compiled_instructions +=
            static_cast<uint32_t>(
                program.instructions.size());
    }
    out.physical_columns =
        vm::kFamilyVmExecutableColumnsV1;
    out.challenge_free_source_table =
        selected_table.challenge_width == 0;
    out.challenge_loads_use_dedicated_tape =
        out.layout.challenge_width ==
            selected_table.challenge_width &&
        out.layout.challenge_base ==
            selected_table.current_width +
            selected_table.next_width;
    out.challenge_tape_constant_compiled =
        true;
    out.current_next_sources_disjoint =
        out.layout.next_base ==
            selected_table.current_width &&
        out.layout.challenge_base ==
            selected_table.current_width +
            selected_table.next_width &&
        out.layout.constraint_lambda ==
            selected_table.current_width +
            selected_table.next_width +
            selected_table.challenge_width;
    out.query_point_derived_from_index = true;
    out.selector_derivation_compiled = true;
    out.terminal_lambda_fold_compiled = true;
    out.quotient_identity_compiled = true;
    out.canonical_padding_schedule_compiled =
        true;
    out.constant_physical_width =
        out.physical_columns ==
            vm::kFamilyVmExecutableColumnsV1;
    out.valid =
        out.current_next_sources_disjoint &&
        out.challenge_loads_use_dedicated_tape &&
        out.challenge_tape_constant_compiled &&
        out.query_point_derived_from_index &&
        out.selector_derivation_compiled &&
        out.terminal_lambda_fold_compiled &&
        out.quotient_identity_compiled &&
        out.canonical_padding_schedule_compiled &&
        out.constant_physical_width;
    out.note = out.valid
        ? "stage3:constant_width_bytecode:"
          "canonical_vertical_quotient_program"
        : "stage3:constant_width_bytecode:"
          "compile_invariant";
    return out;
}

VerticalVmCapacityV1
AssessVerticalVmCapacityV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    uint32_t semantic_rows)
{
    VerticalVmCapacityV1 out;
    out.semantic_rows = semantic_rows;
    out.coefficient_cap =
        vm::kFamilyVmCoefficientCapV1;
    const auto compiled =
        CompileConstantWidthQuotientProgramV1(
            selected_table,
            selected_program_key,
            domain, semantic_rows);
    if (!compiled.valid) {
        out.note =
            "stage3:constant_width_bytecode:"
            "capacity:" + compiled.note;
        return out;
    }
    out.padded_source_rows =
        compiled.padded_rows;
    out.source_columns =
        compiled.compiled_table.current_width;
    out.compiled_programs =
        compiled.compiled_programs;
    out.compiled_instructions =
        compiled.compiled_instructions;
    out.physical_columns =
        compiled.physical_columns;
    const uint64_t rows_per_source_row =
        uint64_t{out.source_columns} +
        out.compiled_instructions;
    if (rows_per_source_row == 0 ||
        compiled.padded_rows >
            std::numeric_limits<uint64_t>::max() /
                rows_per_source_row) {
        out.note =
            "stage3:constant_width_bytecode:"
            "capacity:row_overflow";
        return out;
    }
    out.logical_vertical_rows =
        uint64_t{compiled.padded_rows} *
        rows_per_source_row;
    out.padded_vertical_rows =
        NextPowerOfTwo64(
            out.logical_vertical_rows);
    if (out.padded_vertical_rows == 0 ||
        out.coefficient_cap == 0 ||
        out.logical_vertical_rows >
            std::numeric_limits<uint64_t>::max() -
                (out.coefficient_cap - 1)) {
        out.note =
            "stage3:constant_width_bytecode:"
            "capacity:padded_rows";
        return out;
    }
    const uint64_t segments =
        (out.logical_vertical_rows +
         out.coefficient_cap - 1) /
        out.coefficient_cap;
    if (segments == 0 ||
        segments >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:constant_width_bytecode:"
            "capacity:segment_count";
        return out;
    }
    out.minimum_vm_segments =
        static_cast<uint32_t>(segments);
    out.fits_unsegmented_split_rap =
        out.padded_vertical_rows <=
        out.coefficient_cap;
    // Capacity arithmetic is not a segmented proof. These remain false until
    // a real segment protocol pins order, root and carried machine state.
    out.ordered_segment_roots_constrained = false;
    out.boundary_machine_state_constrained = false;
    out.terminal_segment_fold_constrained = false;
    out.segmented_vertical_vm_executable = false;
    out.valid =
        out.physical_columns ==
            vm::kFamilyVmExecutableColumnsV1 &&
        out.padded_source_rows >= semantic_rows &&
        out.logical_vertical_rows != 0 &&
        out.padded_vertical_rows >=
            out.logical_vertical_rows &&
        out.minimum_vm_segments >= 1 &&
        !out.ordered_segment_roots_constrained &&
        !out.boundary_machine_state_constrained &&
        !out.terminal_segment_fold_constrained &&
        !out.segmented_vertical_vm_executable;
    out.note = out.valid
        ? "stage3:constant_width_bytecode:"
          "capacity:exact_inventory;"
          "segmented_order_boundary_fold_pending"
        : "stage3:constant_width_bytecode:"
          "capacity:invariant";
    return out;
}

ProveResultV1
ProveConstantWidthBytecodeQuotientV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    const std::vector<
        rba::QuotientOpeningRowV1>& rows,
    uint32_t program_id,
    const uint256& program_registry_alg_root,
    const uint256& public_fs_seed)
{
    if (selected_table.challenge_width != 0) {
        ProveResultV1 out;
        out.note =
            "stage3:constant_width_bytecode:"
            "prove:verifier_challenges_required";
        return out;
    }
    std::vector<OpeningRowV1> extended;
    extended.reserve(rows.size());
    for (const auto& row : rows) {
        extended.push_back({row, {}});
    }
    return ProveConstantWidthBytecodeQuotientV1(
        selected_table, selected_program_key,
        domain, extended, program_id,
        program_registry_alg_root,
        public_fs_seed);
}

ProveResultV1
ProveConstantWidthBytecodeQuotientV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    const std::vector<OpeningRowV1>& rows,
    uint32_t program_id,
    const uint256& program_registry_alg_root,
    const uint256& public_fs_seed)
{
    ProveResultV1 out;
    const auto fail =
        [&](const std::string& detail) {
            out.ok = false;
            out.note =
                "stage3:constant_width_bytecode:"
                "prove:" + detail;
            return out;
        };
    if (rows.empty() ||
        rows.size() >
            std::numeric_limits<uint32_t>::max() ||
        program_registry_alg_root.IsNull() ||
        public_fs_seed.IsNull()) {
        return fail("statement");
    }
    const uint32_t semantic_rows =
        static_cast<uint32_t>(rows.size());
    const auto compiled =
        CompileConstantWidthQuotientProgramV1(
            selected_table,
            selected_program_key,
            domain, semantic_rows);
    if (!compiled.valid) {
        return fail(compiled.note);
    }
    std::vector<std::vector<Fp3>>
        source_columns;
    std::string why;
    if (!FillSourceColumns(
            selected_table, domain,
            compiled.layout,
            compiled.padded_rows, rows,
            source_columns, why)) {
        return fail(why);
    }
    const uint256 statement_binding =
        StatementBinding(
            program_id,
            program_registry_alg_root,
            compiled.selected_program_key,
            compiled.compiled_program_key,
            domain, compiled.layout,
            semantic_rows,
            compiled.padded_rows);
    if (statement_binding.IsNull()) {
        return fail("statement_binding");
    }
    const auto family =
        vm::ProveFamilyVmV1(
            compiled.compiled_table,
            source_columns,
            program_id,
            program_registry_alg_root,
            statement_binding,
            public_fs_seed);
    if (!family.ok) {
        return fail(family.note);
    }
    out.public_inputs.version =
        kConstantWidthBytecodeAirVersionV1;
    out.public_inputs.program_id =
        program_id;
    out.public_inputs.program_registry_alg_root =
        program_registry_alg_root;
    out.public_inputs.selected_program_key =
        compiled.selected_program_key;
    out.public_inputs.compiled_program_key =
        compiled.compiled_program_key;
    out.public_inputs.domain = domain;
    out.public_inputs.source_layout =
        compiled.layout;
    out.public_inputs.semantic_rows =
        semantic_rows;
    out.public_inputs.padded_rows =
        compiled.padded_rows;
    out.public_inputs.physical_columns =
        compiled.physical_columns;
    out.public_inputs.ordered_vm_phase0_root =
        family.public_inputs
            .phase0_row_group_root;
    out.public_inputs.family =
        family.public_inputs;
    out.proof.version =
        kConstantWidthBytecodeAirVersionV1;
    out.proof.family = family.proof;
    out.ok = true;
    out.note =
        "stage3:constant_width_bytecode:"
        "prove:split_rap_q192";
    return out;
}

VerificationAuditV1
VerifyConstantWidthBytecodeQuotientV1(
    const cb::ProgramTable& selected_table,
    const PublicInputsV1& public_inputs,
    const ProofV1& proof,
    const uint256& public_fs_seed)
{
    VerificationAuditV1 out;
    out.semantic_rows =
        public_inputs.semantic_rows;
    out.padded_rows =
        public_inputs.padded_rows;
    out.physical_columns =
        public_inputs.physical_columns;
    const auto fail =
        [&](const std::string& detail) {
            out.valid = false;
            out.production_authority_ready =
                false;
            out.note =
                "stage3:constant_width_bytecode:"
                "verify:" + detail;
            return out;
        };
    if (public_inputs.version !=
            kConstantWidthBytecodeAirVersionV1 ||
        proof.version !=
            kConstantWidthBytecodeAirVersionV1 ||
        public_inputs
            .program_registry_alg_root.IsNull() ||
        public_inputs
            .ordered_vm_phase0_root.IsNull() ||
        public_fs_seed.IsNull()) {
        return fail("statement");
    }
    const auto compiled =
        CompileConstantWidthQuotientProgramV1(
            selected_table,
            public_inputs.selected_program_key,
            public_inputs.domain,
            public_inputs.semantic_rows);
    if (!compiled.valid ||
        !SameDigest(
            compiled.compiled_program_key,
            public_inputs.compiled_program_key) ||
        compiled.layout !=
            public_inputs.source_layout ||
        compiled.padded_rows !=
            public_inputs.padded_rows ||
        compiled.physical_columns !=
            public_inputs.physical_columns) {
        return fail("compiled_statement");
    }
    const uint256 expected_binding =
        StatementBinding(
            public_inputs.program_id,
            public_inputs
                .program_registry_alg_root,
            compiled.selected_program_key,
            compiled.compiled_program_key,
            public_inputs.domain,
            compiled.layout,
            compiled.semantic_rows,
            compiled.padded_rows);
    const auto& family_inputs =
        public_inputs.family;
    if (family_inputs.program_id !=
            public_inputs.program_id ||
        family_inputs
            .program_registry_alg_root !=
            public_inputs
                .program_registry_alg_root ||
        family_inputs
            .public_statement_binding !=
            expected_binding ||
        family_inputs
            .phase0_row_group_root !=
            public_inputs
                .ordered_vm_phase0_root ||
        family_inputs.original_trace_rows !=
            compiled.padded_rows ||
        family_inputs.vm_columns !=
            vm::kFamilyVmExecutableColumnsV1 ||
        !SameDigest(
            family_inputs.program_table_alg_hash,
            compiled.compiled_program_key)) {
        return fail("family_public_inputs");
    }
    const auto family =
        vm::VerifyFamilyVmV1(
            compiled.compiled_table,
            family_inputs,
            proof.family,
            public_fs_seed);
    if (!family.valid) {
        return fail(family.note);
    }
    out.original_programs =
        compiled.original_programs;
    out.original_instructions =
        compiled.original_instructions;
    out.compiled_instructions =
        compiled.compiled_instructions;
    out.caller_selected_program_key = true;
    out.compiled_program_key_canonical = true;
    out.current_next_source_cells_disjoint =
        compiled.current_next_sources_disjoint;
    out.query_index_to_evaluation_point_in_vm =
        compiled.query_point_derived_from_index;
    out.selector_derivation_in_vm =
        compiled.selector_derivation_compiled;
    out.terminal_lambda_fold_in_vm =
        compiled.terminal_lambda_fold_compiled;
    out.quotient_vanishing_identity_in_vm =
        compiled.quotient_identity_compiled;
    out.canonical_padding_schedule_in_vm =
        compiled.canonical_padding_schedule_compiled;
    out.ordered_vm_phase0_root_exact =
        family.phase0_group_root_exact;
    out.split_rap_quotient_fri_verified =
        family.split_rap_quotient_fri_verified;
    out.constant_width_universal =
        compiled.constant_physical_width &&
        family.split_rap_quotient_fri_verified;
    out.verifier_work_rows =
        family.verifier_work_rows;
    out.verifier_work_cells =
        family.verifier_work_cells;
    // These are intentionally not inferred from a non-null root. They become
    // true only when the normalized parent exports the same source cells/root
    // and recursively executes this verifier.
    out.registry_membership_proved = false;
    out.challenge_loads_from_dedicated_tape =
        compiled.challenge_loads_use_dedicated_tape;
    out.challenge_tape_constant_across_active_rows =
        compiled.challenge_tape_constant_compiled;
    out.challenge_tape_owned_by_parent_fs = false;
    out.segmented_vertical_vm_executable =
        false;
    out.source_cells_owned_by_parent_pcs =
        false;
    out.query_schedule_owned_by_parent_fs =
        false;
    out.recursive_parent_consumes_this_verifier =
        false;
    out.recursive_fixed_point = false;
    out.production_authority_ready = false;
    out.valid =
        out.caller_selected_program_key &&
        out.compiled_program_key_canonical &&
        out.current_next_source_cells_disjoint &&
        out.query_index_to_evaluation_point_in_vm &&
        out.selector_derivation_in_vm &&
        out.terminal_lambda_fold_in_vm &&
        out.quotient_vanishing_identity_in_vm &&
        out.canonical_padding_schedule_in_vm &&
        out.ordered_vm_phase0_root_exact &&
        out.split_rap_quotient_fri_verified &&
        out.constant_width_universal &&
        !out.registry_membership_proved &&
        out.challenge_loads_from_dedicated_tape &&
        out.challenge_tape_constant_across_active_rows &&
        !out.challenge_tape_owned_by_parent_fs &&
        !out.segmented_vertical_vm_executable &&
        !out.source_cells_owned_by_parent_pcs &&
        !out.query_schedule_owned_by_parent_fs &&
        !out.recursive_parent_consumes_this_verifier &&
        !out.recursive_fixed_point &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:constant_width_bytecode:"
          "verify:fixed_53_column_vertical_vm;"
          "registry_membership,parent_pcs_source_alias,"
          "challenge_tape,segmented_fold,and_recursive_consumption_pending"
        : "stage3:constant_width_bytecode:"
          "verify:invariant";
    return out;
}

} // namespace matmul::v4::rc::constant_width_bytecode_air
