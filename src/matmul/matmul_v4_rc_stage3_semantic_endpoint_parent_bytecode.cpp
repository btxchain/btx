// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_parent_bytecode.h>

#include <functional>
#include <utility>

namespace matmul::v4::rc::
    stage3_semantic_endpoint_parent_bytecode {
namespace {

namespace ah = alg_hash;
namespace aq = air_quotient;

using Fp3 = gf::Fp3;
using Layout = fp::SemanticEndpointReceiptTerminalLayoutV1;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:semantic_endpoint_parent_bytecode:" +
            detail;
    }
    return false;
}

struct ExpressionBuilder {
    cb::Program program;

    uint32_t Load(cb::Opcode opcode, uint32_t column)
    {
        cb::Instruction instruction;
        instruction.opcode = opcode;
        instruction.lhs = column;
        program.instructions.push_back(instruction);
        return static_cast<uint32_t>(
            program.instructions.size() - 1);
    }

    uint32_t Current(uint32_t column)
    {
        return Load(cb::Opcode::Current, column);
    }

    uint32_t Next(uint32_t column)
    {
        return Load(cb::Opcode::Next, column);
    }

    uint32_t Challenge(uint32_t ordinal)
    {
        return Load(cb::Opcode::Challenge, ordinal);
    }

    uint32_t Constant(const Fp3& value)
    {
        cb::Instruction instruction;
        instruction.opcode = cb::Opcode::Constant;
        instruction.constant = value;
        program.instructions.push_back(instruction);
        return static_cast<uint32_t>(
            program.instructions.size() - 1);
    }

    uint32_t Binary(
        cb::Opcode opcode, uint32_t left, uint32_t right)
    {
        cb::Instruction instruction;
        instruction.opcode = opcode;
        instruction.lhs = left;
        instruction.rhs = right;
        program.instructions.push_back(instruction);
        return static_cast<uint32_t>(
            program.instructions.size() - 1);
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
};

Fp3 ChallengeAt(
    const std::vector<Fp3>& challenge,
    uint32_t ordinal)
{
    return challenge[ordinal];
}

} // namespace

bool BuildCanonicalProgramTableV1(
    const Layout& layout,
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    if (layout.End() <= layout.base ||
        layout.authenticated_source_base +
                ah::kAlgHashRate >
            layout.base ||
        Layout::kRoles !=
            kRCStage3RelationClosureRoleCount ||
        Layout::kTerminalLanes != 2 ||
        Layout::kExtensionCoordinates != 3) {
        return Fail(why, "layout");
    }

    out.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = layout.End();
    out.next_width = layout.End();
    out.challenge_width = kChallengeWidthV1;
    out.programs.reserve(
        kCanonicalConstraintCountV1);

    auto add_program =
        [&](aq::AirKind kind,
            uint32_t degree,
            const std::function<void(ExpressionBuilder&)>&
                build) {
            ExpressionBuilder expression;
            expression.program.version = out.version;
            expression.program.role = out.role;
            expression.program.constraint_ordinal =
                static_cast<uint32_t>(
                    out.programs.size());
            expression.program.kind = kind;
            expression.program.declared_degree = degree;
            expression.program.current_width =
                out.current_width;
            expression.program.next_width =
                out.next_width;
            expression.program.challenge_width =
                out.challenge_width;
            build(expression);
            out.programs.push_back(
                std::move(expression.program));
        };

    // active * (root_value - verifier_owned_root) = 0.
    add_program(
        aq::AirKind::kEverywhere, 2,
        [&](ExpressionBuilder& b) {
            const uint32_t active =
                b.Current(layout.active);
            const uint32_t value =
                b.Current(layout.root_value);
            const uint32_t expected =
                b.Current(layout.root_expected);
            b.Mul(active, b.Sub(value, expected));
        });

    for (uint32_t lane = 0;
         lane < Layout::kTerminalLanes;
         ++lane) {
        const uint32_t inverse =
            lane == 0
            ? layout.inverse1
            : layout.inverse2;
        const uint32_t running =
            lane == 0
            ? layout.running1
            : layout.running2;
        const uint32_t gamma =
            lane == 0 ? kGamma0 : kGamma1;
        const uint32_t alpha =
            lane == 0 ? kAlpha0 : kAlpha1;

        // inv * (gamma + value + alpha*address) - active = 0.
        add_program(
            aq::AirKind::kEverywhere, 2,
            [&](ExpressionBuilder& b) {
                const uint32_t denominator =
                    b.Add(
                        b.Challenge(gamma),
                        b.Add(
                            b.Current(layout.root_value),
                            b.Mul(
                                b.Challenge(alpha),
                                b.Current(layout.address))));
                b.Sub(
                    b.Mul(
                        b.Current(inverse),
                        denominator),
                    b.Current(layout.active));
            });

        // next_running =
        //   (1-role_end) * (running + active*inverse).
        add_program(
            aq::AirKind::kTransition, 3,
            [&](ExpressionBuilder& b) {
                const uint32_t not_end =
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(layout.role_end));
                const uint32_t accumulated =
                    b.Add(
                        b.Current(running),
                        b.Mul(
                            b.Current(layout.active),
                            b.Current(inverse)));
                b.Sub(
                    b.Next(running),
                    b.Mul(not_end, accumulated));
            });

        add_program(
            aq::AirKind::kFirstRow, 1,
            [&](ExpressionBuilder& b) {
                b.Current(running);
            });

        for (uint32_t slot = 0;
             slot < Layout::kRoles;
             ++slot) {
            add_program(
                aq::AirKind::kEverywhere, 2,
                [&](ExpressionBuilder& b) {
                    const uint32_t accumulated =
                        b.Add(
                            b.Current(running),
                            b.Current(inverse));
                    const uint32_t residual =
                        b.Sub(
                            accumulated,
                            b.Current(
                                layout.RoleTerminal(
                                    slot, lane)));
                    b.Mul(
                        b.Current(
                            layout.RoleEndSelector(
                                slot)),
                        residual);
                });
        }
    }

    add_program(
        aq::AirKind::kEverywhere, 1,
        [&](ExpressionBuilder& b) {
            uint32_t sum =
                b.Current(layout.RoleEndSelector(0));
            for (uint32_t slot = 1;
                 slot < Layout::kRoles;
                 ++slot) {
                sum = b.Add(
                    sum,
                    b.Current(
                        layout.RoleEndSelector(slot)));
            }
            b.Sub(b.Current(layout.role_end), sum);
        });

    for (uint32_t lane = 0;
         lane < Layout::kTerminalLanes;
         ++lane) {
        add_program(
            aq::AirKind::kEverywhere, 1,
            [&](ExpressionBuilder& b) {
                b.Sub(
                    b.Current(
                        layout.LinkTerminal(0, lane)),
                    b.Current(
                        layout.LinkTerminal(1, lane)));
            });
        add_program(
            aq::AirKind::kEverywhere, 1,
            [&](ExpressionBuilder& b) {
                uint32_t sum =
                    b.Current(
                        layout.RoleTerminal(0, lane));
                for (uint32_t slot = 1;
                     slot < Layout::kRoles;
                     ++slot) {
                    sum = b.Add(
                        sum,
                        b.Current(
                            layout.RoleTerminal(
                                slot, lane)));
                }
                b.Sub(
                    b.Current(
                        layout.LinkTerminal(0, lane)),
                    sum);
            });
    }

    for (uint32_t port = 0;
         port < ah::kAlgHashRate;
         ++port) {
        add_program(
            aq::AirKind::kEverywhere, 2,
            [&](ExpressionBuilder& b) {
                const uint32_t residual =
                    b.Sub(
                        b.Current(
                            layout.authenticated_source_base +
                            port),
                        b.Current(
                            layout.AliasPortExpected(
                                port)));
                b.Mul(
                    b.Current(
                        layout.AliasPortSelector(port)),
                    residual);
            });
    }

    if (out.programs.size() !=
            kCanonicalConstraintCountV1 ||
        !cb::ValidateProgramTable(out, why) ||
        !cb::ProgramTableIsChallengeIndependent(out) ||
        cb::CommitProgramTable(out).IsNull()) {
        return Fail(why, "program_table");
    }
    return true;
}

bool IsCanonicalProgramTableV1(
    const Layout& layout,
    const cb::ProgramTable& candidate,
    std::string* why)
{
    cb::ProgramTable expected;
    if (!BuildCanonicalProgramTableV1(
            layout, expected, why) ||
        !cb::ValidateProgramTable(candidate, why) ||
        candidate != expected ||
        cb::CommitProgramTable(candidate) !=
            cb::CommitProgramTable(expected)) {
        return Fail(why, "canonical_table");
    }
    return true;
}

bool EvaluateNativeConstraintV1(
    const Layout& layout,
    uint32_t ordinal,
    const std::vector<Fp3>& current,
    const std::vector<Fp3>& next,
    const std::vector<Fp3>& challenge,
    Fp3& out,
    std::string* why)
{
    out = Fp3::Zero();
    if (current.size() < layout.End() ||
        next.size() < layout.End() ||
        challenge.size() < kChallengeWidthV1 ||
        ordinal >= kCanonicalConstraintCountV1) {
        return Fail(why, "native_shape");
    }
    uint32_t cursor = 0;
    if (ordinal == cursor++) {
        out = gf::Mul(
            current[layout.active],
            gf::Sub(
                current[layout.root_value],
                current[layout.root_expected]));
        return true;
    }
    for (uint32_t lane = 0;
         lane < Layout::kTerminalLanes;
         ++lane) {
        const uint32_t inverse =
            lane == 0
            ? layout.inverse1
            : layout.inverse2;
        const uint32_t running =
            lane == 0
            ? layout.running1
            : layout.running2;
        const uint32_t gamma =
            lane == 0 ? kGamma0 : kGamma1;
        const uint32_t alpha =
            lane == 0 ? kAlpha0 : kAlpha1;
        if (ordinal == cursor++) {
            const Fp3 denominator =
                gf::Add(
                    ChallengeAt(challenge, gamma),
                    gf::Add(
                        current[layout.root_value],
                        gf::Mul(
                            ChallengeAt(
                                challenge, alpha),
                            current[layout.address])));
            out = gf::Sub(
                gf::Mul(
                    current[inverse], denominator),
                current[layout.active]);
            return true;
        }
        if (ordinal == cursor++) {
            const Fp3 accumulated =
                gf::Add(
                    current[running],
                    gf::Mul(
                        current[layout.active],
                        current[inverse]));
            out = gf::Sub(
                next[running],
                gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        current[layout.role_end]),
                    accumulated));
            return true;
        }
        if (ordinal == cursor++) {
            out = current[running];
            return true;
        }
        for (uint32_t slot = 0;
             slot < Layout::kRoles;
             ++slot) {
            if (ordinal == cursor++) {
                out = gf::Mul(
                    current[
                        layout.RoleEndSelector(slot)],
                    gf::Sub(
                        gf::Add(
                            current[running],
                            current[inverse]),
                        current[
                            layout.RoleTerminal(
                                slot, lane)]));
                return true;
            }
        }
    }
    if (ordinal == cursor++) {
        Fp3 sum = Fp3::Zero();
        for (uint32_t slot = 0;
             slot < Layout::kRoles;
             ++slot) {
            sum = gf::Add(
                sum,
                current[
                    layout.RoleEndSelector(slot)]);
        }
        out = gf::Sub(
            current[layout.role_end], sum);
        return true;
    }
    for (uint32_t lane = 0;
         lane < Layout::kTerminalLanes;
         ++lane) {
        if (ordinal == cursor++) {
            out = gf::Sub(
                current[
                    layout.LinkTerminal(0, lane)],
                current[
                    layout.LinkTerminal(1, lane)]);
            return true;
        }
        if (ordinal == cursor++) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t slot = 0;
                 slot < Layout::kRoles;
                 ++slot) {
                sum = gf::Add(
                    sum,
                    current[
                        layout.RoleTerminal(
                            slot, lane)]);
            }
            out = gf::Sub(
                current[
                    layout.LinkTerminal(0, lane)],
                sum);
            return true;
        }
    }
    for (uint32_t port = 0;
         port < ah::kAlgHashRate;
         ++port) {
        if (ordinal == cursor++) {
            out = gf::Mul(
                current[
                    layout.AliasPortSelector(port)],
                gf::Sub(
                    current[
                        layout.authenticated_source_base +
                        port],
                    current[
                        layout.AliasPortExpected(port)]));
            return true;
        }
    }
    return Fail(why, "native_ordinal");
}

} // namespace matmul::v4::rc::
  // stage3_semantic_endpoint_parent_bytecode
