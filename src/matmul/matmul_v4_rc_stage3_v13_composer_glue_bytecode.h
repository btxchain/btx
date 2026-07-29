// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_COMPOSER_GLUE_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_COMPOSER_GLUE_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace matmul::v4::rc::stage3_v13_composer_glue_bytecode {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Complete low-degree formula inventory used by the V13 parent composers.
 *
 * Keeping this as a closed enum is intentional: a new native callback cannot
 * silently become consensus-relevant composer glue.  It must first acquire a
 * canonical bytecode formula here and a differential test.
 */
enum class FormulaV1 : uint8_t {
    /** current[a] - current[b] */
    EqualCurrent = 0,
    /** current[a] - 1 */
    EqualOne = 1,
    /** current[a] - current[b] * current[c] */
    Product = 2,
    /** next[a] - current[a] */
    CarryTransition = 3,
    /** current[a] * (current[b] - current[c]) */
    SelectedEqual = 4,
};

struct ConstraintV1 {
    FormulaV1 formula{FormulaV1::EqualCurrent};
    aq::AirKind kind{aq::AirKind::kEverywhere};
    uint32_t a{0};
    uint32_t b{0};
    uint32_t c{0};
};

inline bool FailV1(
    std::string* why,
    const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_composer_glue_bytecode:" +
            detail;
    }
    return false;
}

inline cb::Instruction LoadV1(
    cb::Opcode opcode,
    uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

inline cb::Instruction ConstantV1(
    const gf::Fp3& value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = value;
    return out;
}

inline cb::Instruction BinaryV1(
    cb::Opcode opcode,
    uint32_t lhs,
    uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

inline bool BuildCanonicalProgramTableV1(
    uint32_t width,
    const std::vector<ConstraintV1>& constraints,
    cb::ProgramTable& out,
    std::string* why = nullptr)
{
    out = {};
    if (width == 0 || constraints.empty()) {
        return FailV1(why, "shape");
    }
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = width;
    out.next_width = width;
    out.challenge_width = 0;
    out.programs.reserve(constraints.size());

    for (uint32_t ordinal = 0;
         ordinal < constraints.size();
         ++ordinal) {
        const ConstraintV1& spec =
            constraints[ordinal];
        cb::Program program;
        program.version =
            cb::kConstraintBytecodeVersion;
        program.role = out.role;
        program.constraint_ordinal = ordinal;
        program.kind = spec.kind;
        program.current_width = width;
        program.next_width = width;
        program.challenge_width = 0;

        const auto current =
            [&program](uint32_t column) {
                program.instructions.push_back(
                    LoadV1(
                        cb::Opcode::Current,
                        column));
                return static_cast<uint32_t>(
                    program.instructions.size() - 1);
            };
        const auto next =
            [&program](uint32_t column) {
                program.instructions.push_back(
                    LoadV1(
                        cb::Opcode::Next,
                        column));
                return static_cast<uint32_t>(
                    program.instructions.size() - 1);
            };
        const auto constant =
            [&program](const gf::Fp3& value) {
                program.instructions.push_back(
                    ConstantV1(value));
                return static_cast<uint32_t>(
                    program.instructions.size() - 1);
            };
        const auto binary =
            [&program](
                cb::Opcode opcode,
                uint32_t lhs,
                uint32_t rhs) {
                program.instructions.push_back(
                    BinaryV1(
                        opcode, lhs, rhs));
                return static_cast<uint32_t>(
                    program.instructions.size() - 1);
            };
        const auto column_ok =
            [width](uint32_t column) {
                return column < width;
            };

        switch (spec.formula) {
        case FormulaV1::EqualCurrent: {
            if (!column_ok(spec.a) ||
                !column_ok(spec.b)) {
                return FailV1(
                    why, "equal_current_column");
            }
            program.declared_degree = 1;
            const uint32_t lhs = current(spec.a);
            const uint32_t rhs = current(spec.b);
            binary(cb::Opcode::Sub, lhs, rhs);
            break;
        }
        case FormulaV1::EqualOne: {
            if (!column_ok(spec.a)) {
                return FailV1(
                    why, "equal_one_column");
            }
            program.declared_degree = 1;
            const uint32_t lhs = current(spec.a);
            const uint32_t rhs =
                constant(gf::Fp3::One());
            binary(cb::Opcode::Sub, lhs, rhs);
            break;
        }
        case FormulaV1::Product: {
            if (!column_ok(spec.a) ||
                !column_ok(spec.b) ||
                !column_ok(spec.c)) {
                return FailV1(
                    why, "product_column");
            }
            program.declared_degree = 2;
            const uint32_t output =
                current(spec.a);
            const uint32_t lhs = current(spec.b);
            const uint32_t rhs = current(spec.c);
            const uint32_t product =
                binary(cb::Opcode::Mul, lhs, rhs);
            binary(
                cb::Opcode::Sub,
                output, product);
            break;
        }
        case FormulaV1::CarryTransition: {
            if (!column_ok(spec.a) ||
                spec.kind !=
                    aq::AirKind::kTransition) {
                return FailV1(
                    why, "carry_transition");
            }
            program.declared_degree = 1;
            const uint32_t after = next(spec.a);
            const uint32_t before =
                current(spec.a);
            binary(
                cb::Opcode::Sub,
                after, before);
            break;
        }
        case FormulaV1::SelectedEqual: {
            if (!column_ok(spec.a) ||
                !column_ok(spec.b) ||
                !column_ok(spec.c)) {
                return FailV1(
                    why, "selected_equal_column");
            }
            program.declared_degree = 2;
            const uint32_t selector =
                current(spec.a);
            const uint32_t lhs = current(spec.b);
            const uint32_t rhs = current(spec.c);
            const uint32_t difference =
                binary(
                    cb::Opcode::Sub,
                    lhs, rhs);
            binary(
                cb::Opcode::Mul,
                selector, difference);
            break;
        }
        }
        out.programs.push_back(
            std::move(program));
    }
    if (!cb::ValidateProgramTable(out, why)) {
        out = {};
        return FailV1(why, "program_table");
    }
    return true;
}

/**
 * Append the canonical adapter constraints to an existing parent CS.
 * Diagnostic names are restored after adaptation; they are not consensus
 * inputs, while role/ordinal/formula are committed by ProgramTable.
 */
inline bool AppendCanonicalConstraintsV1(
    const cb::ProgramTable& table,
    uint32_t n_rows,
    const std::vector<const char*>& names,
    aq::AirConstraintSystem<gf::Fp3>& parent,
    alg_hash::Digest* program_root = nullptr,
    std::string* why = nullptr)
{
    if (parent.n_rows != n_rows ||
        parent.n_columns != table.current_width ||
        (!names.empty() &&
         names.size() != table.programs.size())) {
        return FailV1(why, "adapter_shape");
    }
    aq::AirConstraintSystem<gf::Fp3> adapter;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            table, n_rows, adapter, why) ||
        adapter.constraints.size() !=
            table.programs.size()) {
        return FailV1(why, "adapter");
    }
    for (uint32_t index = 0;
         index < adapter.constraints.size();
         ++index) {
        if (!names.empty()) {
            adapter.constraints[index].name =
                names[index];
        }
        parent.constraints.push_back(
            std::move(
                adapter.constraints[index]));
    }
    if (program_root != nullptr) {
        *program_root =
            cb::CommitProgramTableAlgHash(table);
        if (std::all_of(
                program_root->begin(),
                program_root->end(),
                [](gf::Fp value) {
                    return gf::Canonical(value) == 0;
                })) {
            return FailV1(why, "program_root");
        }
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_v13_composer_glue_bytecode

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_COMPOSER_GLUE_BYTECODE_H
