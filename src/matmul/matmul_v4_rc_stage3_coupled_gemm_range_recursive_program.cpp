// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_range_recursive_program.h>

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_gated_ctl_alias.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>

#include <utility>

namespace matmul::v4::rc::coupled_gemm_range_recursive_program {
namespace {

namespace aq = air_quotient;
namespace gated = gated_ctl_alias;
using gf::Fp3;

class Builder {
public:
    Builder(
        uint16_t version,
        RCStage3RelationRole role,
        uint32_t ordinal,
        aq::AirKind kind,
        uint32_t degree,
        uint32_t width,
        uint32_t challenge_width)
    {
        m_program.version = version;
        m_program.role = role;
        m_program.constraint_ordinal = ordinal;
        m_program.kind = kind;
        m_program.declared_degree = degree;
        m_program.current_width = width;
        m_program.next_width = width;
        m_program.challenge_width = challenge_width;
    }

    uint32_t Current(uint32_t column)
    {
        return Push(
            {cb::Opcode::Current, column, 0, Fp3::Zero()});
    }
    uint32_t Next(uint32_t column)
    {
        return Push(
            {cb::Opcode::Next, column, 0, Fp3::Zero()});
    }
    uint32_t Challenge(uint32_t column)
    {
        return Push(
            {cb::Opcode::Challenge, column, 0, Fp3::Zero()});
    }
    uint32_t Constant(const Fp3& value)
    {
        return Push(
            {cb::Opcode::Constant, 0, 0, value});
    }
    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Push(
            {cb::Opcode::Add, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Push(
            {cb::Opcode::Sub, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Push(
            {cb::Opcode::Mul, lhs, rhs, Fp3::Zero()});
    }
    cb::Program Take() { return std::move(m_program); }

private:
    uint32_t Push(cb::Instruction instruction)
    {
        const uint32_t result =
            static_cast<uint32_t>(
                m_program.instructions.size());
        m_program.instructions.push_back(
            std::move(instruction));
        return result;
    }

    cb::Program m_program;
};

template <typename Fn>
void Append(
    cb::ProgramTable& table,
    aq::AirKind kind,
    uint32_t degree,
    Fn&& emit)
{
    Builder builder{
        table.version,
        table.role,
        static_cast<uint32_t>(table.programs.size()),
        kind,
        degree,
        table.current_width,
        table.challenge_width};
    emit(builder);
    table.programs.push_back(builder.Take());
}

template <typename Fn>
void Append(
    cb::ProgramTable& table,
    uint32_t degree,
    Fn&& emit)
{
    Append(
        table, aq::AirKind::kEverywhere,
        degree, std::forward<Fn>(emit));
}

void Boolean(cb::ProgramTable& table, uint32_t column)
{
    Append(table, 2, [column](Builder& b) {
        const uint32_t value = b.Current(column);
        b.Mul(
            value,
            b.Sub(value, b.Constant(Fp3::One())));
    });
}

uint32_t SumBits(
    Builder& b,
    uint32_t base,
    uint32_t count)
{
    uint32_t sum = b.Constant(Fp3::Zero());
    uint64_t weight = 1;
    for (uint32_t bit = 0; bit < count; ++bit) {
        sum = b.Add(
            sum,
            b.Mul(
                b.Constant(gf::FromU64_3(weight)),
                b.Current(base + bit)));
        weight <<= 1;
    }
    return sum;
}

void AppendGemmRelation(cb::ProgramTable& table)
{
    using C = RCStage3CoupledGemmDotColumn;
    for (uint32_t column :
         {C::kRCStage3CoupledGemmActive,
          C::kRCStage3CoupledGemmStart,
          C::kRCStage3CoupledGemmEnd}) {
        Boolean(table, column);
    }
    // Preserve the corrected production relation's raw degree metadata
    // exactly. QuotientLen is part of the child proof statement.
    Append(table, 3, [](Builder& b) {
        b.Mul(
            b.Current(kRCStage3CoupledGemmActive),
            b.Sub(
                b.Current(kRCStage3CoupledGemmProduct),
                b.Mul(
                    b.Current(kRCStage3CoupledGemmA),
                    b.Current(kRCStage3CoupledGemmB))));
    });
    Append(table, 2, [](Builder& b) {
        b.Mul(
            b.Current(kRCStage3CoupledGemmActive),
            b.Sub(
                b.Current(
                    kRCStage3CoupledGemmAccumulatorAfter),
                b.Add(
                    b.Current(
                        kRCStage3CoupledGemmAccumulatorBefore),
                    b.Current(
                        kRCStage3CoupledGemmProduct))));
    });
    Append(table, 2, [](Builder& b) {
        b.Mul(
            b.Current(kRCStage3CoupledGemmStart),
            b.Current(
                kRCStage3CoupledGemmAccumulatorBefore));
    });
    Append(table, 2, [](Builder& b) {
        b.Mul(
            b.Current(kRCStage3CoupledGemmEnd),
            b.Sub(
                b.Current(kRCStage3CoupledGemmY),
                b.Current(
                    kRCStage3CoupledGemmAccumulatorAfter)));
    });
    for (uint32_t column :
         {kRCStage3CoupledGemmA,
          kRCStage3CoupledGemmB}) {
        Append(table, 2, [column](Builder& b) {
            b.Mul(
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(
                        kRCStage3CoupledGemmActive)),
                b.Current(column));
        });
    }
    Append(table, 2, [](Builder& b) {
        b.Mul(
            b.Sub(
                b.Constant(Fp3::One()),
                b.Current(kRCStage3CoupledGemmEnd)),
            b.Current(kRCStage3CoupledGemmY));
    });
    Append(
        table, aq::AirKind::kTransition, 3,
        [](Builder& b) {
            b.Mul(
                b.Mul(
                    b.Current(
                        kRCStage3CoupledGemmActive),
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(
                            kRCStage3CoupledGemmEnd))),
                b.Sub(
                    b.Next(
                        kRCStage3CoupledGemmAccumulatorBefore),
                    b.Current(
                        kRCStage3CoupledGemmAccumulatorAfter)));
        });
    for (uint32_t column :
         {kRCStage3CoupledGemmProduct,
          kRCStage3CoupledGemmAccumulatorBefore,
          kRCStage3CoupledGemmAccumulatorAfter}) {
        Append(table, 2, [column](Builder& b) {
            b.Mul(
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(
                        kRCStage3CoupledGemmActive)),
                b.Current(column));
        });
    }
}

void AppendRangeRelation(cb::ProgramTable& table)
{
    Boolean(table, kRCStage3RangeActive);
    Boolean(table, kRCStage3RangeSign);
    Boolean(table, kRCStage3RangeZero);
    for (uint32_t bit = 0;
         bit < kRCStage3SignedRangeBits;
         ++bit) {
        Boolean(
            table,
            kRCStage3RangeMagnitudeBits + bit);
        Boolean(
            table,
            kRCStage3RangeDifferenceBits + bit);
    }
    Append(table, 1, [](Builder& b) {
        b.Sub(
            b.Current(kRCStage3RangeMagnitude),
            SumBits(
                b, kRCStage3RangeMagnitudeBits,
                kRCStage3SignedRangeBits));
    });
    Append(table, 2, [](Builder& b) {
        const uint32_t signed_factor =
            b.Sub(
                b.Constant(Fp3::One()),
                b.Mul(
                    b.Constant(gf::FromU64_3(2)),
                    b.Current(kRCStage3RangeSign)));
        b.Sub(
            b.Current(kRCStage3RangeValue),
            b.Mul(
                b.Current(kRCStage3RangeMagnitude),
                signed_factor));
    });
    Append(table, 2, [](Builder& b) {
        b.Mul(
            b.Current(kRCStage3RangeMagnitude),
            b.Current(kRCStage3RangeZero));
    });
    Append(table, 2, [](Builder& b) {
        b.Sub(
            b.Mul(
                b.Current(kRCStage3RangeMagnitude),
                b.Current(
                    kRCStage3RangeMagnitudeInverse)),
            b.Sub(
                b.Constant(Fp3::One()),
                b.Current(kRCStage3RangeZero)));
    });
    Append(table, 2, [](Builder& b) {
        b.Mul(
            b.Current(kRCStage3RangeSign),
            b.Current(kRCStage3RangeZero));
    });
    Append(table, 1, [](Builder& b) {
        b.Sub(
            b.Add(
                b.Current(kRCStage3RangeMagnitude),
                SumBits(
                    b,
                    kRCStage3RangeDifferenceBits,
                    kRCStage3SignedRangeBits)),
            b.Challenge(MAX_ABS));
    });
    Append(
        table, aq::AirKind::kTransition, 2,
        [](Builder& b) {
            b.Mul(
                b.Next(kRCStage3RangeActive),
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(kRCStage3RangeActive)));
        });
    Append(
        table, aq::AirKind::kTransition, 1,
        [](Builder& b) {
            b.Sub(
                b.Next(kRCStage3RangeRemaining),
                b.Sub(
                    b.Current(kRCStage3RangeRemaining),
                    b.Current(kRCStage3RangeActive)));
        });
    Append(
        table, aq::AirKind::kFirstRow, 1,
        [](Builder& b) {
            b.Sub(
                b.Current(kRCStage3RangeRemaining),
                b.Challenge(LOGICAL_ROWS));
        });
    Append(
        table, aq::AirKind::kFirstRow, 1,
        [](Builder& b) {
            b.Sub(
                b.Current(kRCStage3RangeActive),
                b.Constant(Fp3::One()));
        });
    Append(
        table, aq::AirKind::kLastRow, 1,
        [](Builder& b) {
            b.Sub(
                b.Current(kRCStage3RangeRemaining),
                b.Current(kRCStage3RangeActive));
        });

    const auto inactive =
        [&table](
            uint32_t column,
            uint64_t expected) {
            Append(
                table, 2,
                [column, expected](Builder& b) {
                    b.Mul(
                        b.Sub(
                            b.Constant(Fp3::One()),
                            b.Current(
                                kRCStage3RangeActive)),
                        b.Sub(
                            b.Current(column),
                            b.Constant(
                                gf::FromU64_3(expected))));
                });
        };
    inactive(kRCStage3RangeValue, 0);
    inactive(kRCStage3RangeSign, 0);
    inactive(kRCStage3RangeZero, 1);
    inactive(kRCStage3RangeMagnitudeInverse, 0);
    inactive(kRCStage3RangeMagnitude, 0);
    for (uint32_t bit = 0;
         bit < kRCStage3SignedRangeBits;
         ++bit) {
        inactive(
            kRCStage3RangeMagnitudeBits + bit, 0);
        Append(table, 2, [bit](Builder& b) {
            b.Mul(
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(kRCStage3RangeActive)),
                b.Sub(
                    b.Current(
                        kRCStage3RangeDifferenceBits +
                        bit),
                    b.Challenge(
                        MAX_ABS_BITS + bit)));
        });
    }
}

uint32_t Compress(
    Builder& b,
    uint32_t base,
    uint32_t source,
    uint32_t gamma_column)
{
    const uint32_t gamma =
        b.Challenge(gamma_column);
    const uint32_t gamma2 =
        b.Mul(gamma, gamma);
    const uint32_t gamma3 =
        b.Mul(gamma2, gamma);
    return b.Add(
        b.Current(base + gated::col::NAMESPACE),
        b.Add(
            b.Mul(
                gamma,
                b.Current(base + gated::col::STAGE)),
            b.Add(
                b.Mul(
                    gamma2,
                    b.Current(
                        base + gated::col::ADDRESS)),
                b.Mul(
                    gamma3,
                    b.Current(source)))));
}

void AppendGatedCtl(
    cb::ProgramTable& table,
    uint32_t relation_columns,
    uint32_t source,
    uint32_t selector,
    int8_t sign)
{
    const uint32_t base = relation_columns;
    Boolean(table, selector);
    Append(table, 1, [base, selector, sign](Builder& b) {
        b.Sub(
            b.Current(base + gated::col::MULTIPLICITY),
            b.Mul(
                b.Constant(gf::FromSigned3(sign)),
                b.Current(selector)));
    });
    const auto inverse_lane =
        [&table, base, source, selector](
            uint32_t inverse,
            uint32_t gamma,
            uint32_t alpha) {
            // Challenge loads are verifier constants.  Keep the native
            // post-FS trace degree (three) exactly: quotient sizing is part
            // of the child proof statement, not advisory metadata.
            Append(table, 3, [=](Builder& b) {
                const uint32_t denominator =
                    b.Sub(
                        b.Challenge(alpha),
                        Compress(
                            b, base, source, gamma));
                b.Mul(
                    b.Current(selector),
                    b.Sub(
                        b.Mul(
                            b.Current(base + inverse),
                            denominator),
                        b.Constant(Fp3::One())));
            });
            Append(table, 2, [=](Builder& b) {
                b.Mul(
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(selector)),
                    b.Current(base + inverse));
            });
        };
    inverse_lane(
        gated::col::INVERSE1, GAMMA1, ALPHA1);
    inverse_lane(
        gated::col::INVERSE2, GAMMA2, ALPHA2);

    const auto lane =
        [&table, base](
            uint32_t inverse,
            uint32_t term,
            uint32_t running,
            uint32_t expected) {
            Append(table, 2, [=](Builder& b) {
                b.Sub(
                    b.Current(base + term),
                    b.Mul(
                        b.Current(
                            base +
                            gated::col::MULTIPLICITY),
                        b.Current(base + inverse)));
            });
            Append(
                table, aq::AirKind::kFirstRow, 1,
                [=](Builder& b) {
                    b.Current(base + running);
                });
            Append(
                table, aq::AirKind::kTransition, 1,
                [=](Builder& b) {
                    b.Sub(
                        b.Next(base + running),
                        b.Add(
                            b.Current(base + running),
                            b.Current(base + term)));
                });
            Append(
                table, aq::AirKind::kLastRow, 1,
                [=](Builder& b) {
                    b.Sub(
                        b.Add(
                            b.Current(base + running),
                            b.Current(base + term)),
                        b.Challenge(expected));
                });
        };
    lane(
        gated::col::INVERSE1,
        gated::col::TERM1,
        gated::col::RUNNING1,
        EXPECTED_TERMINAL1);
    lane(
        gated::col::INVERSE2,
        gated::col::TERM2,
        gated::col::RUNNING2,
        EXPECTED_TERMINAL2);
}

bool Finalize(cb::ProgramTable& table, std::string* why)
{
    std::string detail;
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size();
         ++ordinal) {
        if (!cb::ValidateProgram(
                table.programs[ordinal], &detail)) {
            if (why != nullptr) {
                *why =
                    "stage3:coupled_gemm_range_recursive_program:"
                    "program_validation:" +
                    std::to_string(ordinal) + ":" +
                    detail;
            }
            table = {};
            return false;
        }
    }
    if (!cb::ValidateProgramTable(table, &detail) ||
        !cb::ProgramTableIsChallengeIndependent(table) ||
        cb::CommitProgramTable(table).IsNull() ||
        cb::CommitProgramTableAlgHash(table) ==
            alg_hash::Digest{}) {
        table = {};
        if (why != nullptr) {
            *why =
                "stage3:coupled_gemm_range_recursive_program:"
                "program_validation:" +
                detail;
        }
        return false;
    }
    return true;
}

} // namespace

bool BuildGemmProgramV1(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    out.role = RCStage3RelationRole::CoupledGemm;
    out.current_width =
        static_cast<uint32_t>(
            kRCStage3CoupledGemmColumns) +
        gated::col::NUM_COLUMNS;
    out.next_width = out.current_width;
    out.challenge_width = 6;
    AppendGemmRelation(out);
    AppendGatedCtl(
        out,
        kRCStage3CoupledGemmColumns,
        kRCStage3CoupledGemmY,
        kRCStage3CoupledGemmEnd,
        1);
    return Finalize(out, why);
}

bool BuildRangeProgramV1(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width =
        static_cast<uint32_t>(
            kRCStage3SignedRangeColumns) +
        gated::col::NUM_COLUMNS;
    out.next_width = out.current_width;
    out.challenge_width = NUM_CHALLENGES;
    AppendRangeRelation(out);
    AppendGatedCtl(
        out,
        kRCStage3SignedRangeColumns,
        kRCStage3RangeValue,
        kRCStage3RangeActive,
        -1);
    return Finalize(out, why);
}

std::vector<Fp3> BuildGemmChallengesV1(
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal)
{
    return {
        challenges.gamma1,
        challenges.gamma2,
        challenges.alpha1,
        challenges.alpha2,
        terminal.alpha1_sum,
        terminal.alpha2_sum,
    };
}

std::vector<Fp3> BuildRangeChallengesV1(
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    uint64_t max_abs,
    uint32_t logical_rows)
{
    auto out =
        BuildGemmChallengesV1(challenges, terminal);
    out.push_back(gf::FromU64_3(max_abs));
    for (uint32_t bit = 0;
         bit < kRCStage3SignedRangeBits;
         ++bit) {
        out.push_back(
            gf::FromU64_3(
                (max_abs >> bit) & 1U));
    }
    out.push_back(
        gf::FromU64_3(logical_rows));
    return out;
}

} // namespace matmul::v4::rc::coupled_gemm_range_recursive_program
