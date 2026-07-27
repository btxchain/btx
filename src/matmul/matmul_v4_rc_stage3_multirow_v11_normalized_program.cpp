// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_bytecode.h>

#include <algorithm>
#include <array>
#include <limits>
#include <utility>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_normalized_program {
namespace {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace pa = stage3_poseidon_air;
namespace tp = stage3_multirow_p2_transcript;
using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v11_normalized_program:" + detail;
    }
    return false;
}

bool StrictFp3(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

struct Expr {
    std::vector<cb::Instruction> instructions;
    std::vector<uint32_t> degree;

    uint32_t Current(uint32_t column)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Current;
        in.lhs = column;
        instructions.push_back(in);
        degree.push_back(1);
        return static_cast<uint32_t>(instructions.size()) - 1;
    }

    uint32_t Next(uint32_t column)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Next;
        in.lhs = column;
        instructions.push_back(in);
        degree.push_back(1);
        return static_cast<uint32_t>(instructions.size()) - 1;
    }

    uint32_t Constant(const Fp3& value)
    {
        cb::Instruction in;
        in.opcode = cb::Opcode::Constant;
        in.constant = value;
        instructions.push_back(in);
        degree.push_back(0);
        return static_cast<uint32_t>(instructions.size()) - 1;
    }

    uint32_t Binary(cb::Opcode opcode, uint32_t lhs, uint32_t rhs)
    {
        cb::Instruction in;
        in.opcode = opcode;
        in.lhs = lhs;
        in.rhs = rhs;
        instructions.push_back(in);
        degree.push_back(
            opcode == cb::Opcode::Mul
                ? degree[lhs] + degree[rhs]
                : std::max(degree[lhs], degree[rhs]));
        return static_cast<uint32_t>(instructions.size()) - 1;
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

    uint32_t One()
    {
        return Constant(Fp3::One());
    }

    uint32_t Boolean(uint32_t column)
    {
        const uint32_t x = Current(column);
        return Mul(x, Sub(x, One()));
    }
};

struct Affine {
    Fp3 constant{};
    std::vector<std::pair<uint32_t, Fp3>> terms;
};

template <typename Eval>
Affine RecoverAffine(uint32_t width, Eval&& eval)
{
    std::vector<Fp3> row(width, Fp3::Zero());
    Affine out;
    out.constant = eval(row);
    for (uint32_t column = 0; column < width; ++column) {
        row[column] = Fp3::One();
        const Fp3 coefficient =
            gf::Sub(eval(row), out.constant);
        row[column] = Fp3::Zero();
        if (!gf::IsZero(coefficient)) {
            out.terms.emplace_back(column, coefficient);
        }
    }
    return out;
}

uint32_t EmitAffine(Expr& e, const Affine& affine)
{
    uint32_t result = e.Constant(affine.constant);
    for (const auto& [column, coefficient] : affine.terms) {
        result = e.Add(
            result,
            e.Mul(
                e.Constant(coefficient),
                e.Current(column)));
    }
    return result;
}

cb::Program Finish(
    Expr&& e, uint32_t ordinal, aq::AirKind kind,
    uint32_t width)
{
    cb::Program out;
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.constraint_ordinal = ordinal;
    out.kind = kind;
    out.declared_degree = e.degree.back();
    out.current_width = width;
    out.next_width = width;
    out.challenge_width = 0;
    out.instructions = std::move(e.instructions);
    return out;
}

template <typename Build>
void Append(
    cb::ProgramTable& table, aq::AirKind kind,
    Build&& build)
{
    Expr e;
    build(e);
    table.programs.push_back(Finish(
        std::move(e),
        static_cast<uint32_t>(table.programs.size()),
        kind, table.current_width));
}

void AppendCanonicalSplit(
    cb::ProgramTable& table,
    const pj::CanonicalSplitLayoutV1& split,
    uint32_t replay_column,
    bool expected_is_public)
{
    Append(table, aq::AirKind::kEverywhere,
        [=](Expr& e) { e.Boolean(split.active); });
    for (uint32_t bit = 0; bit < pj::kRawBitsV1; ++bit) {
        Append(table, aq::AirKind::kEverywhere,
            [=](Expr& e) { e.Boolean(split.Bit(bit)); });
    }
    Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
        uint32_t sum = e.Constant(Fp3::Zero());
        uint64_t power = 1;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            sum = e.Add(
                sum,
                e.Mul(
                    e.Constant(gf::FromU64_3(power)),
                    e.Current(split.Bit(bit))));
            power <<= 1;
        }
        e.Sub(e.Current(split.claim_lo), sum);
    });
    Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
        uint32_t sum = e.Constant(Fp3::Zero());
        uint64_t power = 1;
        for (uint32_t bit = 32; bit < 64; ++bit) {
            sum = e.Add(
                sum,
                e.Mul(
                    e.Constant(gf::FromU64_3(power)),
                    e.Current(split.Bit(bit))));
            power <<= 1;
        }
        e.Sub(e.Current(split.claim_hi), sum);
    });
    Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
        const uint32_t raw = e.Add(
            e.Current(split.claim_lo),
            e.Mul(
                e.Constant(gf::FromU64_3(uint64_t{1} << 32)),
                e.Current(split.claim_hi)));
        e.Mul(
            e.Current(split.active),
            e.Sub(raw, e.Current(replay_column)));
    });
    if (expected_is_public) {
        Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
            e.Mul(
                e.Current(split.active),
                e.Sub(
                    e.Current(split.claim_lo),
                    e.Current(split.expected_lo)));
        });
        Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
            e.Mul(
                e.Current(split.active),
                e.Sub(
                    e.Current(split.claim_hi),
                    e.Current(split.expected_hi)));
        });
    }
    Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Sub(
            e.Mul(
                e.Current(split.claim_lo),
                e.Current(split.low_inverse)),
            e.Current(split.low_nonzero));
    });
    Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Mul(
            e.Current(split.claim_lo),
            e.Sub(e.One(), e.Current(split.low_nonzero)));
    });
    Append(table, aq::AirKind::kEverywhere,
        [=](Expr& e) { e.Boolean(split.low_nonzero); });
    for (uint32_t bit = 0; bit < pj::kHighAndBitsV1; ++bit) {
        Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
            const uint32_t expected =
                bit == 0
                ? e.Current(split.Bit(32))
                : e.Mul(
                    e.Current(split.HighAnd(bit - 1)),
                    e.Current(split.Bit(32 + bit)));
            e.Sub(e.Current(split.HighAnd(bit)), expected);
        });
    }
    Append(table, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Mul(
            e.Current(split.HighAnd(pj::kHighAndBitsV1 - 1)),
            e.Current(split.low_nonzero));
    });
}

uint64_t CountInstructions(const cb::ProgramTable& table)
{
    uint64_t out = 0;
    for (const auto& program : table.programs) {
        out += program.instructions.size();
    }
    return out;
}

uint64_t CountInstructions(
    const cb::ProgramTable& table,
    uint32_t first, uint32_t count)
{
    uint64_t out = 0;
    const uint32_t end = std::min<uint32_t>(
        static_cast<uint32_t>(table.programs.size()),
        first + count);
    for (uint32_t i = first; i < end; ++i) {
        out += table.programs[i].instructions.size();
    }
    return out;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    uint64_t out = 1;
    while (out < value) {
        out <<= 1;
        if (out > std::numeric_limits<uint32_t>::max()) return 0;
    }
    return static_cast<uint32_t>(out);
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 &&
        b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

bool ComposedDegreeBound(
    const cb::Program& program,
    uint32_t trace_rows,
    uint64_t& out)
{
    if (trace_rows < 2) return false;
    const uint64_t trace_degree =
        static_cast<uint64_t>(trace_rows) - 1;
    uint64_t degree = 0;
    if (!CheckedMul(
            program.declared_degree, trace_degree, degree)) {
        return false;
    }
    switch (program.kind) {
    case aq::AirKind::kEverywhere:
        out = degree;
        return true;
    case aq::AirKind::kTransition:
        return CheckedAdd(degree, 1, out);
    case aq::AirKind::kFirstRow:
    case aq::AirKind::kLastRow:
        return CheckedAdd(degree, trace_degree, out);
    }
    return false;
}

bool DigestEq(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) return false;
    }
    return true;
}

bool Applies(aq::AirKind kind, uint32_t probe, uint32_t probes)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition: return probe + 1 < probes;
    case aq::AirKind::kFirstRow: return probe == 0;
    case aq::AirKind::kLastRow: return probe + 1 == probes;
    }
    return false;
}

uint64_t SplitMix64(uint64_t& state)
{
    state += UINT64_C(0x9e3779b97f4a7c15);
    uint64_t z = state;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

} // namespace

bool BuildCanonicalProgramTableV1(
    cb::ProgramTable& out,
    ManifestV1* manifest,
    std::string* why)
{
    const pj::LayoutV1 layout = pj::CanonicalLayoutV1();
    if (layout.n_columns == 0 ||
        layout.replay.poseidon.perm.base != 0) {
        return Fail(why, "layout");
    }
    out = {};
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = layout.n_columns;
    out.next_width = layout.n_columns;
    out.challenge_width = 0;
    out.programs.reserve(kExpectedProgramsV1);

    cb::ProgramTable poseidon;
    if (!pa::BuildFixedProgramTable(poseidon, why) ||
        poseidon.programs.size() != kPoseidonProgramsV1) {
        return Fail(why, "poseidon_table");
    }
    for (auto program : poseidon.programs) {
        program.constraint_ordinal =
            static_cast<uint32_t>(out.programs.size());
        program.current_width = out.current_width;
        program.next_width = out.next_width;
        out.programs.push_back(std::move(program));
    }

    std::array<Affine, alg_hash::kAlgHashT> output_affine;
    for (uint32_t lane = 0; lane < output_affine.size(); ++lane) {
        output_affine[lane] = RecoverAffine(
            layout.replay.poseidon.End(),
            [perm = layout.replay.poseidon.perm, lane](
                const std::vector<Fp3>& row) {
                return ar::PermOutputLane(perm, row, lane);
            });
    }

    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.replay.terminal);
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.replay.query_candidate_active);
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.replay.query_candidate_first);
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.query_candidate_first),
            e.Sub(
                e.One(),
                e.Current(layout.replay.query_candidate_active)));
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.replay.candidate_valid);
    });
    Append(out, aq::AirKind::kEverywhere, [&](Expr& e) {
        const uint32_t x = e.Add(
            EmitAffine(e, output_affine[0]), e.One());
        e.Sub(
            e.Mul(
                x, e.Current(layout.replay.candidate_inverse)),
            e.Current(layout.replay.candidate_valid));
    });
    Append(out, aq::AirKind::kEverywhere, [&](Expr& e) {
        const uint32_t x = e.Add(
            EmitAffine(e, output_affine[0]), e.One());
        e.Mul(
            x,
            e.Sub(
                e.One(),
                e.Current(layout.replay.candidate_valid)));
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.replay.candidate_prior_valid);
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.replay.candidate_selected);
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.query_candidate_first),
            e.Current(layout.replay.candidate_prior_valid));
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Sub(
            e.Current(layout.replay.candidate_selected),
            e.Mul(
                e.Current(layout.replay.candidate_valid),
                e.Sub(
                    e.One(),
                    e.Current(layout.replay.candidate_prior_valid))));
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.candidate_selected),
            e.Sub(
                e.One(),
                e.Current(layout.replay.query_candidate_active)));
    });
    Append(out, aq::AirKind::kTransition, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.query_candidate_first),
            e.Sub(
                e.Next(layout.replay.candidate_prior_valid),
                e.Current(layout.replay.candidate_valid)));
    });
    Append(out, aq::AirKind::kTransition, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.query_candidate_first),
            e.Sub(
                e.Add(
                    e.Current(layout.replay.candidate_selected),
                    e.Next(layout.replay.candidate_selected)),
                e.One()));
    });
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashT; ++lane) {
        Append(out, aq::AirKind::kFirstRow, [=](Expr& e) {
            const uint32_t expected =
                lane < alg_hash::kAlgHashRate
                ? e.Current(layout.replay.Absorb(lane))
                : e.Constant(Fp3::Zero());
            e.Sub(
                e.Current(
                    layout.replay.poseidon.perm.InputCol(lane)),
                expected);
        });
        Append(out, aq::AirKind::kTransition, [&](Expr& e) {
            uint32_t expected =
                lane < alg_hash::kAlgHashRate
                ? e.Next(layout.replay.Absorb(lane))
                : e.Constant(Fp3::Zero());
            expected = e.Add(
                expected,
                e.Mul(
                    e.Sub(
                        e.One(),
                        e.Current(layout.replay.terminal)),
                    EmitAffine(e, output_affine[lane])));
            e.Sub(
                e.Next(
                    layout.replay.poseidon.perm.InputCol(lane)),
                expected);
        });
    }
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen; ++limb) {
        Append(out, aq::AirKind::kEverywhere, [&](Expr& e) {
            e.Mul(
                e.Current(layout.replay.terminal),
                e.Sub(
                    EmitAffine(e, output_affine[limb]),
                    e.Current(layout.replay.DigestClaim(limb))));
        });
    }
    if (out.programs.size() !=
        kPoseidonProgramsV1 + kTranscriptGlueProgramsV1) {
        return Fail(why, "transcript_program_count");
    }

    for (const auto& slot : layout.public_absorb) {
        Append(out, aq::AirKind::kEverywhere,
            [=](Expr& e) { e.Boolean(slot.active); });
        Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
            e.Mul(
                e.Current(slot.active),
                e.Sub(
                    e.Current(slot.claim),
                    e.Current(slot.expected)));
        });
        const uint32_t lane =
            static_cast<uint32_t>(&slot - &layout.public_absorb[0]);
        Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
            e.Mul(
                e.Current(slot.active),
                e.Sub(
                    e.Current(slot.claim),
                    e.Current(layout.replay.Absorb(lane))));
        });
    }
    for (uint32_t limb = 0; limb < pj::kPublicFieldSlotsV1; ++limb) {
        AppendCanonicalSplit(
            out, layout.public_field[limb],
            layout.replay.DigestClaim(limb), true);
    }
    for (uint32_t limb = 0;
         limb < pj::kCandidateDigestLimbsV1; ++limb) {
        AppendCanonicalSplit(
            out, layout.candidate_digest[limb],
            layout.replay.DigestClaim(limb), false);
    }
    Append(out, aq::AirKind::kTransition, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.query_candidate_first),
            e.Sub(
                e.Current(layout.selected_ordinal_claim),
                e.Next(layout.replay.candidate_selected)));
    });
    // The production statement uses n_coeffs=1024 and blowup=16, hence the
    // exact parent-join index decomposition consumes 14 low digest bits.
    constexpr uint32_t kProductionDomainLog = 14;
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        uint32_t index = e.Constant(Fp3::Zero());
        uint64_t power = 1;
        for (uint32_t bit = 0; bit < kProductionDomainLog; ++bit) {
            index = e.Add(
                index,
                e.Mul(
                    e.Constant(gf::FromU64_3(power)),
                    e.Current(layout.candidate_digest[0].Bit(bit))));
            power <<= 1;
        }
        e.Mul(
            e.Current(layout.replay.candidate_selected),
            e.Sub(index, e.Current(layout.query_index_claim)));
    });
    Append(out, aq::AirKind::kTransition, [=](Expr& e) {
        e.Mul(
            e.Current(layout.replay.query_candidate_first),
            e.Sub(
                e.Next(layout.query_index_claim),
                e.Current(layout.query_index_claim)));
    });
    Append(out, aq::AirKind::kEverywhere, [=](Expr& e) {
        e.Boolean(layout.coefficient_active);
    });

    if (out.programs.size() != kExpectedProgramsV1 ||
        !cb::ValidateProgramTable(out, why)) {
        return Fail(why, "complete_table");
    }
    const ManifestV1 assessed = AssessProgramTableV1(out);
    if (!assessed.canonical_program_table ||
        !assessed.canonical_field_encodings ||
        assessed.unlowered_relations != 0) {
        return Fail(why, "strict_table");
    }
    if (manifest != nullptr) *manifest = assessed;
    if (why != nullptr) *why = assessed.note;
    return true;
}

ExecutionDomainV1 AssessExecutionDomainV1(
    const cb::ProgramTable& table,
    uint32_t query_count)
{
    ExecutionDomainV1 out;
    out.query_count = query_count;
    if (query_count == 0 ||
        !cb::ValidateProgramTable(table, nullptr)) {
        return out;
    }

    const uint64_t instructions = CountInstructions(table);
    uint64_t row_width = 0;
    if (!CheckedAdd(
            static_cast<uint64_t>(table.current_width),
            instructions, row_width) ||
        !CheckedAdd(row_width, 3, row_width) ||
        !CheckedMul(query_count, row_width, out.real_rows)) {
        return out;
    }
    out.trace_rows = NextPowerOfTwo(out.real_rows);
    if (out.trace_rows == 0) return out;

    for (const auto& program : table.programs) {
        out.max_constraint_degree = std::max(
            out.max_constraint_degree,
            program.declared_degree);
        uint64_t composed_degree = 0;
        if (!ComposedDegreeBound(
                program, out.trace_rows, composed_degree)) {
            return out;
        }
        out.max_composed_degree = std::max(
            out.max_composed_degree, composed_degree);
    }
    out.quotient_len =
        out.max_composed_degree < out.trace_rows
        ? 1
        : out.max_composed_degree - out.trace_rows + 1;
    // AirConstraintSystem::QuotientLen() and the FRI implementation use a
    // uint32_t coefficient count.  Refuse an unrepresentable domain rather
    // than truncating it.
    if (out.quotient_len >
        std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.coefficient_rows = NextPowerOfTwo(std::max<uint64_t>(
        out.trace_rows, out.quotient_len));
    if (out.coefficient_rows == 0 ||
        !CheckedMul(
            out.coefficient_rows, kFriBlowupV1, out.lde_rows)) {
        return out;
    }
    out.exact_degree_accounting = true;
    out.trace_rows_fit =
        out.trace_rows <= kTraceRowsCapV1;
    out.lde_rows_fit =
        out.lde_rows <= kLdeRowsCapV1;
    out.valid =
        out.exact_degree_accounting &&
        out.trace_rows_fit &&
        out.lde_rows_fit;
    return out;
}

ManifestV1 AssessProgramTableV1(
    const cb::ProgramTable& table,
    uint32_t instruction_cap,
    uint32_t query_count)
{
    ManifestV1 out;
    out.fixedpoint_instruction_cap = instruction_cap;
    out.query_count = query_count;
    out.current_columns = table.current_width;
    out.next_columns = table.next_width;
    out.program_count =
        static_cast<uint32_t>(table.programs.size());
    out.poseidon_programs =
        std::min(out.program_count, kPoseidonProgramsV1);
    out.transcript_glue_programs =
        out.program_count > kPoseidonProgramsV1
        ? std::min(
            out.program_count - kPoseidonProgramsV1,
            kTranscriptGlueProgramsV1)
        : 0;
    out.parent_join_programs =
        out.program_count >
            kPoseidonProgramsV1 + kTranscriptGlueProgramsV1
        ? out.program_count -
            kPoseidonProgramsV1 - kTranscriptGlueProgramsV1
        : 0;
    out.instruction_count = CountInstructions(table);
    out.poseidon_instructions = CountInstructions(
        table, 0, kPoseidonProgramsV1);
    out.transcript_glue_instructions = CountInstructions(
        table, kPoseidonProgramsV1, kTranscriptGlueProgramsV1);
    out.parent_join_instructions = CountInstructions(
        table,
        kPoseidonProgramsV1 + kTranscriptGlueProgramsV1,
        kParentJoinProgramsV1);
    for (const auto& program : table.programs) {
        out.max_program_instructions = std::max<uint32_t>(
            out.max_program_instructions,
            static_cast<uint32_t>(program.instructions.size()));
    }
    std::string why;
    out.canonical_program_table =
        cb::ValidateProgramTable(table, &why);
    out.opcode_and_operand_bounds =
        out.canonical_program_table;
    out.canonical_field_encodings = true;
    for (const auto& program : table.programs) {
        for (const auto& in : program.instructions) {
            if (!StrictFp3(in.constant)) {
                out.canonical_field_encodings = false;
            }
        }
    }
    out.exact_native_constraint_order =
        out.canonical_program_table &&
        table.role == RCStage3RelationRole::CompositionLink &&
        table.current_width == pj::CanonicalLayoutV1().n_columns &&
        table.next_width == table.current_width &&
        table.challenge_width == 0 &&
        out.program_count == kExpectedProgramsV1;
    out.unlowered_relations =
        out.program_count >= kExpectedProgramsV1
        ? 0 : kExpectedProgramsV1 - out.program_count;
    out.no_opaque_callbacks =
        out.exact_native_constraint_order &&
        out.unlowered_relations == 0;
    out.instruction_cap_fits =
        out.instruction_count <= instruction_cap;
    const auto domain =
        AssessExecutionDomainV1(table, out.query_count);
    out.exact_vm_real_rows = domain.real_rows;
    out.exact_vm_trace_rows = domain.trace_rows;
    out.exact_vm_max_constraint_degree =
        domain.max_constraint_degree;
    out.exact_vm_max_composed_degree =
        domain.max_composed_degree;
    out.exact_vm_quotient_len = domain.quotient_len;
    out.exact_vm_coefficient_rows =
        domain.coefficient_rows;
    out.exact_vm_lde_rows = domain.lde_rows;
    out.trace_rows_fit = domain.trace_rows_fit;
    out.lde_rows_fit = domain.lde_rows_fit;
    std::vector<unsigned char> bytes;
    if (out.canonical_program_table &&
        out.canonical_field_encodings &&
        cb::SerializeProgramTable(table, bytes, &why)) {
        out.serialized_bytes = bytes.size();
        out.program_root = cb::CommitProgramTableAlgHash(table);
    }
    if (!out.canonical_program_table ||
        !out.exact_native_constraint_order) {
        out.residual_mask |= kResidualProgramShape;
    }
    if (!out.canonical_field_encodings) {
        out.residual_mask |= kResidualNoncanonicalFieldEncoding;
    }
    if (!out.no_opaque_callbacks) {
        out.residual_mask |= kResidualUnloweredRelation;
    }
    if (!out.instruction_cap_fits) {
        out.residual_mask |= kResidualFixedPointInstructionCap;
    }
    if (!domain.valid) {
        out.residual_mask |= kResidualExecutionDomain;
    }
    out.canonical_program_executable =
        out.residual_mask == 0 &&
        out.trace_rows_fit &&
        out.lde_rows_fit;
    out.recursive_authority_ready = false;
    out.note =
        out.canonical_program_table &&
        out.canonical_field_encodings &&
        out.no_opaque_callbacks &&
        !out.instruction_cap_fits
        ? "stage3:v11_normalized_program:exact_lowering_exceeds_fixedpoint_cap"
        : out.canonical_program_executable
            ? "stage3:v11_normalized_program:executable_under_supplied_cap;"
              "recursive_authority_still_false"
            : "stage3:v11_normalized_program:invalid_or_incomplete";
    return out;
}

bool ProgramRootMatchesV1(
    const cb::ProgramTable& table,
    const alg_hash::Digest& expected_root)
{
    const ManifestV1 assessed = AssessProgramTableV1(
        table, std::numeric_limits<uint32_t>::max());
    return assessed.canonical_program_table &&
        assessed.canonical_field_encodings &&
        assessed.no_opaque_callbacks &&
        DigestEq(assessed.program_root, expected_root);
}

DifferentialAuditV1 AuditAgainstNativeV1(
    const pj::ProductV1& product,
    const cb::ProgramTable& table,
    uint32_t probes)
{
    DifferentialAuditV1 out;
    out.native_constraints =
        static_cast<uint32_t>(product.cs.constraints.size());
    out.bytecode_programs =
        static_cast<uint32_t>(table.programs.size());
    out.probes = probes;
    const ManifestV1 assessed = AssessProgramTableV1(
        table, std::numeric_limits<uint32_t>::max());
    out.product_shape_exact =
        product.cs.n_columns == table.current_width &&
        product.layout.n_columns == table.current_width &&
        product.constraints == kExpectedProgramsV1;
    out.every_native_constraint_lowered =
        assessed.no_opaque_callbacks &&
        out.native_constraints == out.bytecode_programs;
    if (!out.product_shape_exact ||
        !out.every_native_constraint_lowered ||
        probes < 2) {
        out.note =
            "stage3:v11_normalized_program:differential_shape";
        return out;
    }
    uint64_t state = UINT64_C(0x87d14f392abc5601);
    std::vector<Fp3> current(table.current_width);
    std::vector<Fp3> next(table.next_width);
    for (uint32_t probe = 0; probe < probes; ++probe) {
        for (auto& value : current) {
            value = Fp3{
                gf::FromU64(SplitMix64(state)),
                gf::FromU64(SplitMix64(state)),
                gf::FromU64(SplitMix64(state))};
        }
        for (auto& value : next) {
            value = Fp3{
                gf::FromU64(SplitMix64(state)),
                gf::FromU64(SplitMix64(state)),
                gf::FromU64(SplitMix64(state))};
        }
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size(); ++ordinal) {
            if (!Applies(
                    table.programs[ordinal].kind,
                    probe, probes)) {
                continue;
            }
            Fp3 bytecode;
            if (!cb::EvaluateProgram(
                    table.programs[ordinal],
                    current, next, bytecode, nullptr)) {
                ++out.mismatches;
                continue;
            }
            const Fp3 native =
                product.cs.constraints[ordinal].eval(
                    current, next);
            ++out.evaluations;
            if (!gf::Eq(bytecode, native)) {
                ++out.mismatches;
            }
        }
    }
    out.bit_exact =
        out.evaluations != 0 && out.mismatches == 0;
    out.valid =
        out.product_shape_exact &&
        out.every_native_constraint_lowered &&
        out.bit_exact;
    out.note = out.valid
        ? "stage3:v11_normalized_program:differential_exact"
        : "stage3:v11_normalized_program:differential_mismatch";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_normalized_program
