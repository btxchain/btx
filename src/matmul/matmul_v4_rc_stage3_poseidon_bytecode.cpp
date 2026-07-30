// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_poseidon_bytecode.h>

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace matmul::v4::rc::stage3_poseidon_air {
namespace {

namespace cb = constraint_bytecode;
namespace aq = air_quotient;
namespace ar = air_recurse;
namespace gf = gkr_field;
using gf::Fp3;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:poseidon_bytecode:" + message;
    return false;
}

/** Degree-1 affine form A_s over the 484 committed cells: constant + terms. */
struct AffineForm {
    Fp3 constant{};
    std::vector<std::pair<uint32_t, Fp3>> terms; // (column, coefficient)
};

/**
 * Recover A_s from the existing public evaluator by unit-vector probing:
 *   constant  = A_s(0)
 *   coeff[i]  = A_s(e_i) - A_s(0)
 * Because A_s is Fp-affine, every recovered coefficient is a base-field scalar
 * embedded in Fp3, so Constant(coeff)*Current(col) reproduces the native
 * MulScalar term bit-for-bit.
 */
AffineForm RecoverAffine(const Layout& layout, uint32_t s)
{
    const uint32_t width = layout.End();
    std::vector<Fp3> row(width, Fp3::Zero());
    AffineForm form;
    form.constant = ar::PermSboxInput(layout.perm, row, s);
    for (uint32_t col = 0; col < width; ++col) {
        row[col] = Fp3::One();
        const Fp3 coeff =
            gf::Sub(ar::PermSboxInput(layout.perm, row, s), form.constant);
        row[col] = Fp3::Zero();
        if (!gf::IsZero(coeff)) {
            form.terms.emplace_back(col, coeff);
        }
    }
    return form;
}

uint32_t EmitConst(std::vector<cb::Instruction>& ins, const Fp3& value)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Constant;
    instruction.constant = value;
    ins.push_back(instruction);
    return static_cast<uint32_t>(ins.size()) - 1;
}

uint32_t EmitLoad(std::vector<cb::Instruction>& ins, uint32_t column)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Current;
    instruction.lhs = column;
    ins.push_back(instruction);
    return static_cast<uint32_t>(ins.size()) - 1;
}

uint32_t EmitBinary(std::vector<cb::Instruction>& ins, cb::Opcode op,
                    uint32_t lhs, uint32_t rhs)
{
    cb::Instruction instruction;
    instruction.opcode = op;
    instruction.lhs = lhs;
    instruction.rhs = rhs;
    ins.push_back(instruction);
    return static_cast<uint32_t>(ins.size()) - 1;
}

/** Append A_s = constant + sum coeff_i * cell_i; return the result register. */
uint32_t EmitAffine(std::vector<cb::Instruction>& ins, const AffineForm& form)
{
    uint32_t acc = EmitConst(ins, form.constant);
    for (const auto& [col, coeff] : form.terms) {
        const uint32_t k = EmitConst(ins, coeff);
        const uint32_t x = EmitLoad(ins, col);
        const uint32_t term = EmitBinary(ins, cb::Opcode::Mul, k, x);
        acc = EmitBinary(ins, cb::Opcode::Add, acc, term);
    }
    return acc;
}

cb::Program NewProgram(uint32_t ordinal, uint32_t width)
{
    cb::Program program;
    program.version = cb::kConstraintBytecodeVersion;
    program.role = RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal = ordinal;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 2;
    program.current_width = width;
    program.next_width = 0;
    program.challenge_width = 0;
    return program;
}

} // namespace

bool BuildFixedProgramTable(cb::ProgramTable& out, std::string* why)
{
    const Layout layout = CanonicalLayout(0);
    if (!layout.IsCanonical(why)) return false;
    const uint32_t width = layout.End(); // 484

    out = {};
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = width;
    out.next_width = 0;
    out.challenge_width = 0;
    out.programs.reserve(kFixedConstraints);

    uint32_t ordinal = 0;
    for (uint32_t s = 0; s < ar::kPermSboxCells; ++s) {
        const AffineForm affine = RecoverAffine(layout, s);
        const uint32_t x2col = layout.X2Col(s);
        const uint32_t x4col = layout.X4Col(s);
        const uint32_t x6col = layout.X6Col(s);
        const uint32_t ycol = layout.perm.SboxCol(s);

        // x2:  X2Col - x*x
        {
            cb::Program p = NewProgram(ordinal++, width);
            const uint32_t x = EmitAffine(p.instructions, affine);
            const uint32_t xsq = EmitBinary(p.instructions, cb::Opcode::Mul, x, x);
            const uint32_t x2r = EmitLoad(p.instructions, x2col);
            EmitBinary(p.instructions, cb::Opcode::Sub, x2r, xsq);
            out.programs.push_back(std::move(p));
        }
        // x4:  X4Col - X2Col*X2Col
        {
            cb::Program p = NewProgram(ordinal++, width);
            const uint32_t x4r = EmitLoad(p.instructions, x4col);
            const uint32_t x2r = EmitLoad(p.instructions, x2col);
            const uint32_t sq = EmitBinary(p.instructions, cb::Opcode::Mul, x2r, x2r);
            EmitBinary(p.instructions, cb::Opcode::Sub, x4r, sq);
            out.programs.push_back(std::move(p));
        }
        // x6:  X6Col - X4Col*X2Col
        {
            cb::Program p = NewProgram(ordinal++, width);
            const uint32_t x6r = EmitLoad(p.instructions, x6col);
            const uint32_t x4r = EmitLoad(p.instructions, x4col);
            const uint32_t x2r = EmitLoad(p.instructions, x2col);
            const uint32_t prod = EmitBinary(p.instructions, cb::Opcode::Mul, x4r, x2r);
            EmitBinary(p.instructions, cb::Opcode::Sub, x6r, prod);
            out.programs.push_back(std::move(p));
        }
        // output:  SboxCol - X6Col*x
        {
            cb::Program p = NewProgram(ordinal++, width);
            const uint32_t x = EmitAffine(p.instructions, affine);
            const uint32_t x6r = EmitLoad(p.instructions, x6col);
            const uint32_t prod = EmitBinary(p.instructions, cb::Opcode::Mul, x6r, x);
            const uint32_t yr = EmitLoad(p.instructions, ycol);
            EmitBinary(p.instructions, cb::Opcode::Sub, yr, prod);
            out.programs.push_back(std::move(p));
        }
    }

    if (out.programs.size() != kFixedConstraints) {
        return Fail(why, "program_count");
    }
    if (!cb::ValidateProgramTable(out, why)) return false;
    return true;
}

} // namespace matmul::v4::rc::stage3_poseidon_air
