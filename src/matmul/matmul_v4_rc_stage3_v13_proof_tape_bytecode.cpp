// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_proof_tape_bytecode.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_bytecode.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air {
namespace {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace p2bc = stage3_poseidon_air;
using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v13_proof_tape_bytecode:" + detail;
    }
    return false;
}

uint32_t Constant(
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

uint32_t Current(
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

uint32_t Next(
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

uint32_t Binary(
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

uint32_t Add(
    std::vector<cb::Instruction>& instructions,
    uint32_t lhs,
    uint32_t rhs)
{
    return Binary(
        instructions, cb::Opcode::Add, lhs, rhs);
}

uint32_t Sub(
    std::vector<cb::Instruction>& instructions,
    uint32_t lhs,
    uint32_t rhs)
{
    return Binary(
        instructions, cb::Opcode::Sub, lhs, rhs);
}

uint32_t Mul(
    std::vector<cb::Instruction>& instructions,
    uint32_t lhs,
    uint32_t rhs)
{
    return Binary(
        instructions, cb::Opcode::Mul, lhs, rhs);
}

struct AffineForm {
    Fp3 constant{};
    std::vector<std::pair<uint32_t, Fp3>> terms;
};

AffineForm RecoverPermOutput(
    const LayoutV1& layout,
    uint32_t lane)
{
    std::vector<Fp3> row(
        layout.End(), Fp3::Zero());
    AffineForm form;
    form.constant =
        ar::PermOutputLane(
            layout.poseidon.perm, row, lane);
    for (uint32_t column = 0;
         column < layout.poseidon.End(); ++column) {
        row[column] = Fp3::One();
        const Fp3 coefficient =
            gf::Sub(
                ar::PermOutputLane(
                    layout.poseidon.perm,
                    row, lane),
                form.constant);
        row[column] = Fp3::Zero();
        if (!gf::IsZero(coefficient)) {
            form.terms.emplace_back(
                column, coefficient);
        }
    }
    return form;
}

uint32_t EmitAffine(
    std::vector<cb::Instruction>& instructions,
    const AffineForm& form)
{
    uint32_t result =
        Constant(instructions, form.constant);
    for (const auto& [column, coefficient] :
         form.terms) {
        const uint32_t term =
            Mul(
                instructions,
                Constant(instructions, coefficient),
                Current(instructions, column));
        result = Add(instructions, result, term);
    }
    return result;
}

cb::Program Program(
    uint32_t ordinal,
    const LayoutV1& layout,
    aq::AirKind kind,
    uint32_t degree)
{
    cb::Program out;
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.constraint_ordinal = ordinal;
    out.kind = kind;
    out.declared_degree = degree;
    out.current_width = layout.End();
    out.next_width = layout.End();
    out.challenge_width = 0;
    return out;
}

template <typename Emit>
void Append(
    cb::ProgramTable& table,
    const LayoutV1& layout,
    aq::AirKind kind,
    uint32_t degree,
    Emit&& emit)
{
    cb::Program program =
        Program(
            static_cast<uint32_t>(
                table.programs.size()),
            layout, kind, degree);
    emit(program.instructions);
    table.programs.push_back(std::move(program));
}

} // namespace

bool BuildCanonicalProgramTableV1(
    cb::ProgramTable& out,
    std::string* why)
{
    const LayoutV1 layout = CanonicalLayoutV1();
    cb::ProgramTable poseidon;
    if (!p2bc::BuildFixedProgramTable(
            poseidon, why)) {
        return false;
    }

    out = {};
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = layout.End();
    out.next_width = layout.End();
    out.challenge_width = 0;
    out.programs.reserve(
        poseidon.programs.size() + 197);

    for (auto& program : poseidon.programs) {
        program.current_width = layout.End();
        program.next_width = layout.End();
        program.constraint_ordinal =
            static_cast<uint32_t>(
                out.programs.size());
        out.programs.push_back(std::move(program));
    }

    const uint32_t one = 1;
    for (uint32_t slot = 0;
         slot < kRecordsPerRowV1; ++slot) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Append(
                out, layout,
                aq::AirKind::kEverywhere, 2,
                [&, slot, bit](
                    std::vector<cb::Instruction>& ins) {
                    const uint32_t value =
                        Current(
                            ins,
                            layout.Bit(slot, bit));
                    Mul(
                        ins, value,
                        Sub(
                            ins, value,
                            Constant(ins, Fp3::One())));
                });
        }
        Append(
            out, layout,
            aq::AirKind::kEverywhere, 1,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                uint32_t recomposed =
                    Constant(ins, Fp3::Zero());
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    recomposed = Add(
                        ins, recomposed,
                        Mul(
                            ins,
                            Constant(
                                ins,
                                Fp3::FromFp(
                                    gf::FromU64(
                                        weight))),
                            Current(
                                ins,
                                layout.Bit(
                                    slot, bit))));
                    weight <<= 1;
                }
                Sub(
                    ins,
                    Current(
                        ins, layout.Value(slot)),
                    recomposed);
            });
        Append(
            out, layout,
            aq::AirKind::kEverywhere, 1,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                Sub(
                    ins,
                    Current(
                        ins, layout.Address(slot)),
                    Current(
                        ins,
                        layout.ExpectedAddress(slot)));
            });
        Append(
            out, layout,
            aq::AirKind::kEverywhere, 2,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                Mul(
                    ins,
                    Current(
                        ins,
                        layout.FixedValue(slot)),
                    Sub(
                        ins,
                        Current(
                            ins, layout.Value(slot)),
                        Current(
                            ins,
                            layout.ExpectedValue(
                                slot))));
            });
        Append(
            out, layout,
            aq::AirKind::kEverywhere, 2,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                const uint32_t eq =
                    Current(
                        ins,
                        layout.HighIsMax(slot));
                Mul(
                    ins, eq,
                    Sub(
                        ins, eq,
                        Constant(ins, Fp3::One())));
            });

        const aq::AirKind pair_kind =
            slot + one < kRecordsPerRowV1
            ? aq::AirKind::kEverywhere
            : aq::AirKind::kTransition;
        const auto high =
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                return slot + one <
                        kRecordsPerRowV1
                    ? Current(
                          ins,
                          layout.Value(slot + one))
                    : Next(ins, layout.Value(0));
            };
        Append(
            out, layout, pair_kind, 3,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                Mul(
                    ins,
                    Current(
                        ins, layout.FpLow(slot)),
                    Mul(
                        ins,
                        Current(
                            ins,
                            layout.HighIsMax(slot)),
                        Sub(
                            ins,
                            Constant(
                                ins,
                                Fp3::FromFp(
                                    gf::FromU64(
                                        UINT32_MAX))),
                            high(ins))));
            });
        Append(
            out, layout, pair_kind, 3,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                const uint32_t eq =
                    Current(
                        ins,
                        layout.HighIsMax(slot));
                const uint32_t delta =
                    Sub(
                        ins,
                        Constant(
                            ins,
                            Fp3::FromFp(
                                gf::FromU64(
                                    UINT32_MAX))),
                        high(ins));
                Mul(
                    ins,
                    Current(
                        ins, layout.FpLow(slot)),
                    Sub(
                        ins,
                        Mul(
                            ins, delta,
                            Current(
                                ins,
                                layout.
                                    HighDeltaInverse(
                                        slot))),
                        Sub(
                            ins,
                            Constant(
                                ins, Fp3::One()),
                            eq)));
            });
        Append(
            out, layout, pair_kind, 3,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                Mul(
                    ins,
                    Current(
                        ins, layout.FpLow(slot)),
                    Mul(
                        ins,
                        Current(
                            ins,
                            layout.HighIsMax(slot)),
                        Current(
                            ins,
                            layout.Value(slot))));
            });
        for (bool inverse : {false, true}) {
            Append(
                out, layout,
                aq::AirKind::kEverywhere, 2,
                [&, slot, inverse](
                    std::vector<cb::Instruction>& ins) {
                    Mul(
                        ins,
                        Sub(
                            ins,
                            Constant(
                                ins, Fp3::One()),
                            Current(
                                ins,
                                layout.FpLow(slot))),
                        Current(
                            ins,
                            inverse
                                ? layout.
                                    HighDeltaInverse(
                                        slot)
                                : layout.HighIsMax(
                                      slot)));
                });
        }
        Append(
            out, layout, pair_kind, 2,
            [&, slot](
                std::vector<cb::Instruction>& ins) {
                const uint32_t following =
                    slot + one <
                            kRecordsPerRowV1
                    ? Current(
                          ins,
                          layout.Address(slot + one))
                    : Next(ins, layout.Address(0));
                Mul(
                    ins,
                    Current(
                        ins,
                        layout.Successor(slot)),
                    Sub(
                        ins,
                        Sub(
                            ins, following,
                            Current(
                                ins,
                                layout.Address(slot))),
                        Constant(ins, Fp3::One())));
            });
    }

    std::vector<AffineForm> outputs;
    outputs.reserve(alg_hash::kAlgHashT);
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT; ++lane) {
        outputs.push_back(
            RecoverPermOutput(layout, lane));
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate; ++lane) {
        Append(
            out, layout,
            aq::AirKind::kFirstRow, 1,
            [&, lane](
                std::vector<cb::Instruction>& ins) {
                const uint32_t slot = lane / 2;
                const uint32_t column =
                    (lane & 1U) == 0
                    ? layout.Address(slot)
                    : layout.Value(slot);
                Sub(
                    ins,
                    Current(
                        ins,
                        layout.poseidon.perm.
                            InputCol(lane)),
                    Current(ins, column));
            });
        Append(
            out, layout,
            aq::AirKind::kTransition, 1,
            [&, lane](
                std::vector<cb::Instruction>& ins) {
                const uint32_t slot = lane / 2;
                const uint32_t column =
                    (lane & 1U) == 0
                    ? layout.Address(slot)
                    : layout.Value(slot);
                Sub(
                    ins,
                    Next(
                        ins,
                        layout.poseidon.perm.
                            InputCol(lane)),
                    Add(
                        ins,
                        EmitAffine(
                            ins, outputs[lane]),
                        Next(ins, column)));
            });
    }
    for (uint32_t lane = alg_hash::kAlgHashRate;
         lane < alg_hash::kAlgHashT; ++lane) {
        Append(
            out, layout,
            aq::AirKind::kFirstRow, 1,
            [&, lane](
                std::vector<cb::Instruction>& ins) {
                Current(
                    ins,
                    layout.poseidon.perm.
                        InputCol(lane));
            });
        Append(
            out, layout,
            aq::AirKind::kTransition, 1,
            [&, lane](
                std::vector<cb::Instruction>& ins) {
                Sub(
                    ins,
                    Next(
                        ins,
                        layout.poseidon.perm.
                            InputCol(lane)),
                    EmitAffine(
                        ins, outputs[lane]));
            });
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen; ++lane) {
        Append(
            out, layout,
            aq::AirKind::kLastRow, 1,
            [&, lane](
                std::vector<cb::Instruction>& ins) {
                Sub(
                    ins,
                    EmitAffine(
                        ins, outputs[lane]),
                    Current(
                        ins,
                        layout.ExpectedTapeRoot(
                            lane)));
            });
    }
    Append(
        out, layout,
        aq::AirKind::kEverywhere, 1,
        [&](std::vector<cb::Instruction>& ins) {
            Current(ins, layout.dependent_zero);
        });

    if (out.programs.size() != 669) {
        return Fail(why, "program_count");
    }
    if (!cb::ValidateProgramTable(out, why)) {
        return false;
    }
    if (!cb::ProgramTableIsChallengeIndependent(out)) {
        return Fail(why, "challenge_independence");
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air
