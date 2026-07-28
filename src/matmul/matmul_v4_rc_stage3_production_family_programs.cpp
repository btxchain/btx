// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>

#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <functional>
#include <set>

namespace matmul::v4::rc::universal_topology {
namespace {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace sites = soundness_scenarios;
using gf::Fp3;

class FragmentProgramBuilder {
public:
    explicit FragmentProgramBuilder(cb::Program& program)
        : m_program(program)
    {
    }

    uint32_t Current(uint32_t column)
    {
        return Emit({cb::Opcode::Current, column, 0, Fp3::Zero()});
    }

    uint32_t Next(uint32_t column)
    {
        return Emit({cb::Opcode::Next, column, 0, Fp3::Zero()});
    }

    uint32_t Challenge(uint32_t column)
    {
        return Emit({cb::Opcode::Challenge, column, 0, Fp3::Zero()});
    }

    uint32_t Constant(const Fp3& value)
    {
        return Emit({cb::Opcode::Constant, 0, 0, value});
    }

    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Emit({cb::Opcode::Add, lhs, rhs, Fp3::Zero()});
    }

    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Emit({cb::Opcode::Sub, lhs, rhs, Fp3::Zero()});
    }

    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Emit({cb::Opcode::Mul, lhs, rhs, Fp3::Zero()});
    }

private:
    uint32_t Emit(cb::Instruction instruction)
    {
        m_program.instructions.push_back(std::move(instruction));
        return static_cast<uint32_t>(m_program.instructions.size() - 1);
    }

    cb::Program& m_program;
};

void AppendFragment(
    cb::ProgramTable& table,
    aq::AirKind kind,
    uint32_t degree,
    const std::function<void(FragmentProgramBuilder&)>& emit)
{
    cb::Program program;
    program.role = table.role;
    program.constraint_ordinal =
        static_cast<uint32_t>(table.programs.size());
    program.kind = kind;
    program.declared_degree = degree;
    program.current_width = table.current_width;
    program.next_width = table.next_width;
    program.challenge_width = table.challenge_width;
    FragmentProgramBuilder builder(program);
    emit(builder);
    table.programs.push_back(std::move(program));
}

void AppendFragmentBoolean(cb::ProgramTable& table, uint32_t column)
{
    AppendFragment(
        table, aq::AirKind::kEverywhere, 2,
        [column](FragmentProgramBuilder& b) {
            const uint32_t value = b.Current(column);
            b.Mul(value, b.Sub(value, b.Constant(Fp3::One())));
        });
}

/**
 * Pin-independent portion of ResolveRCStage3SignedRangeKernelConstraintSystem.
 *
 * The table is intentionally a PARTIAL family: it contains, in byte-for-byte
 * native order, all 143 signed-range constraints. The native pin constants
 * MAX_ABS and LOGICAL_ROWS become explicit trace parameters, with a canonical
 * 31-bit decomposition and transition constancy. This yields one immutable
 * 177-constraint ProgramTable for every production shard shape. What remains
 * outside the fragment is ownership: the recursive parent must root-pin those
 * parameter columns and the 69 relation columns to the canonical manifest.
 */
bool BuildSignedRangeLocalFragment(
    cb::ProgramTable& out,
    std::string* why)
{
    constexpr uint32_t MAX_ABS =
        kRCStage3SignedRangeColumns;
    constexpr uint32_t MAX_ABS_BITS = MAX_ABS + 1;
    constexpr uint32_t LOGICAL_ROWS =
        MAX_ABS_BITS + kRCStage3SignedRangeBits;
    constexpr uint32_t COLUMNS = LOGICAL_ROWS + 1;
    out = {};
    out.role = RCStage3RelationRole::EpisodeGemm;
    out.current_width = COLUMNS;
    out.next_width = COLUMNS;
    AppendFragmentBoolean(out, kRCStage3RangeActive);
    AppendFragmentBoolean(out, kRCStage3RangeSign);
    AppendFragmentBoolean(out, kRCStage3RangeZero);
    for (uint32_t bit = 0; bit < kRCStage3SignedRangeBits; ++bit) {
        AppendFragmentBoolean(
            out, kRCStage3RangeMagnitudeBits + bit);
        AppendFragmentBoolean(
            out, kRCStage3RangeDifferenceBits + bit);
    }
    AppendFragment(
        out, aq::AirKind::kEverywhere, 1,
        [](FragmentProgramBuilder& b) {
            uint32_t sum = b.Constant(Fp3::Zero());
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < kRCStage3SignedRangeBits;
                 ++bit) {
                sum = b.Add(
                    sum,
                    b.Mul(
                        b.Constant(gf::FromU64_3(weight)),
                        b.Current(
                            kRCStage3RangeMagnitudeBits + bit)));
                weight <<= 1;
            }
            b.Sub(b.Current(kRCStage3RangeMagnitude), sum);
        });
    AppendFragment(
        out, aq::AirKind::kEverywhere, 2,
        [](FragmentProgramBuilder& b) {
            const uint32_t signed_factor = b.Sub(
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
    AppendFragment(
        out, aq::AirKind::kEverywhere, 2,
        [](FragmentProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3RangeMagnitude),
                b.Current(kRCStage3RangeZero));
        });
    AppendFragment(
        out, aq::AirKind::kEverywhere, 2,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Mul(
                    b.Current(kRCStage3RangeMagnitude),
                    b.Current(kRCStage3RangeMagnitudeInverse)),
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(kRCStage3RangeZero)));
        });
    AppendFragment(
        out, aq::AirKind::kEverywhere, 2,
        [](FragmentProgramBuilder& b) {
            b.Mul(
                b.Current(kRCStage3RangeSign),
                b.Current(kRCStage3RangeZero));
        });
    // Native constraint 70: magnitude + difference == MAX_ABS.
    AppendFragment(
        out, aq::AirKind::kEverywhere, 1,
        [](FragmentProgramBuilder& b) {
            uint32_t difference = b.Constant(Fp3::Zero());
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < kRCStage3SignedRangeBits;
                 ++bit) {
                difference = b.Add(
                    difference,
                    b.Mul(
                        b.Constant(gf::FromU64_3(weight)),
                        b.Current(
                            kRCStage3RangeDifferenceBits + bit)));
                weight <<= 1;
            }
            b.Sub(
                b.Add(
                    b.Current(kRCStage3RangeMagnitude),
                    difference),
                b.Current(MAX_ABS));
        });
    AppendFragment(
        out, aq::AirKind::kTransition, 2,
        [](FragmentProgramBuilder& b) {
            b.Mul(
                b.Next(kRCStage3RangeActive),
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(kRCStage3RangeActive)));
        });
    AppendFragment(
        out, aq::AirKind::kTransition, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Next(kRCStage3RangeRemaining),
                b.Sub(
                    b.Current(kRCStage3RangeRemaining),
                    b.Current(kRCStage3RangeActive)));
        });
    AppendFragment(
        out, aq::AirKind::kFirstRow, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Current(kRCStage3RangeRemaining),
                b.Current(LOGICAL_ROWS));
        });
    AppendFragment(
        out, aq::AirKind::kFirstRow, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Current(kRCStage3RangeActive),
                b.Constant(Fp3::One()));
        });
    AppendFragment(
        out, aq::AirKind::kLastRow, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Current(kRCStage3RangeRemaining),
                b.Current(kRCStage3RangeActive));
        });
    const auto inactive_value =
        [&out](uint32_t column, uint32_t expected_column,
               uint64_t expected_constant, bool use_column) {
            AppendFragment(
                out, aq::AirKind::kEverywhere, 2,
                [=](FragmentProgramBuilder& b) {
                    const uint32_t expected =
                        use_column
                        ? b.Current(expected_column)
                        : b.Constant(
                              gf::FromU64_3(expected_constant));
                    b.Mul(
                        b.Sub(
                            b.Constant(Fp3::One()),
                            b.Current(kRCStage3RangeActive)),
                        b.Sub(b.Current(column), expected));
                });
        };
    inactive_value(kRCStage3RangeValue, 0, 0, false);
    inactive_value(kRCStage3RangeSign, 0, 0, false);
    inactive_value(kRCStage3RangeZero, 0, 1, false);
    inactive_value(kRCStage3RangeMagnitudeInverse, 0, 0, false);
    inactive_value(kRCStage3RangeMagnitude, 0, 0, false);
    for (uint32_t bit = 0;
         bit < kRCStage3SignedRangeBits;
         ++bit) {
        inactive_value(
            kRCStage3RangeMagnitudeBits + bit,
            0, 0, false);
        inactive_value(
            kRCStage3RangeDifferenceBits + bit,
            MAX_ABS_BITS + bit, 0, true);
    }
    // Parameter canonicity. These are extra to the 143 native constraints:
    // MAX_ABS is a unique 31-bit integer, and both public parameters are
    // constant over the trace before the recursive parent root-pins them.
    for (uint32_t bit = 0;
         bit < kRCStage3SignedRangeBits;
         ++bit) {
        AppendFragmentBoolean(out, MAX_ABS_BITS + bit);
    }
    AppendFragment(
        out, aq::AirKind::kEverywhere, 1,
        [](FragmentProgramBuilder& b) {
            uint32_t sum = b.Constant(Fp3::Zero());
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < kRCStage3SignedRangeBits;
                 ++bit) {
                sum = b.Add(
                    sum,
                    b.Mul(
                        b.Constant(gf::FromU64_3(weight)),
                        b.Current(MAX_ABS_BITS + bit)));
                weight <<= 1;
            }
            b.Sub(b.Current(MAX_ABS), sum);
        });
    AppendFragment(
        out, aq::AirKind::kTransition, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(b.Next(MAX_ABS), b.Current(MAX_ABS));
        });
    AppendFragment(
        out, aq::AirKind::kTransition, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Next(LOGICAL_ROWS),
                b.Current(LOGICAL_ROWS));
        });
    if (!cb::ValidateProgramTable(out, why)) {
        out = {};
        return false;
    }
    return true;
}

/**
 * All-tile parametric form of
 * BuildRCStage3EpisodeExtractStreamTransportProgramTable. TILE is a canonical
 * u32 and MULTIPLICITY is constrained to {-1,+1}; both are constant across
 * the trace. The first twelve programs are the native dual-LogUp relation
 * with those parameters loaded from columns rather than baked constants.
 * Exact tile-set aggregation and manifest ownership remain parent duties.
 */
bool BuildRangeExtractCtlParametricFragment(
    cb::ProgramTable& out,
    std::string* why)
{
    constexpr uint32_t SOURCE = 0;
    constexpr uint32_t MASK = 1;
    constexpr uint32_t ADDRESS = 2;
    constexpr uint32_t INVERSE_1 = 3;
    constexpr uint32_t INVERSE_2 = 4;
    constexpr uint32_t RUNNING_1 = 5;
    constexpr uint32_t RUNNING_2 = 6;
    constexpr uint32_t TILE = 7;
    constexpr uint32_t MULTIPLICITY = 8;
    constexpr uint32_t TILE_BITS = 9;
    constexpr uint32_t COLUMNS = TILE_BITS + 32;
    constexpr uint32_t CHALLENGE_WIDTH = 6;
    out = {};
    out.role = RCStage3RelationRole::EpisodeExtract;
    out.current_width = COLUMNS;
    out.next_width = COLUMNS;
    out.challenge_width = CHALLENGE_WIDTH;

    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse =
            lane == 0 ? INVERSE_1 : INVERSE_2;
        const uint32_t running =
            lane == 0 ? RUNNING_1 : RUNNING_2;
        const uint32_t gamma_idx = 2 * lane;
        const uint32_t alpha_idx = 2 * lane + 1;
        const uint32_t sum_idx = 4 + lane;
        AppendFragmentBoolean(out, MASK);
        AppendFragment(
            out, aq::AirKind::kEverywhere, 5,
            [=](FragmentProgramBuilder& b) {
                const uint32_t gamma =
                    b.Challenge(gamma_idx);
                const uint32_t gamma2 =
                    b.Mul(gamma, gamma);
                const uint32_t gamma3 =
                    b.Mul(gamma2, gamma);
                const uint32_t tuple = b.Add(
                    b.Constant(gf::FromU64_3(
                        kRCStage3ExtractStreamCtlBusId)),
                    b.Add(
                        b.Mul(gamma, b.Current(TILE)),
                        b.Add(
                            b.Mul(
                                gamma2,
                                b.Current(ADDRESS)),
                            b.Mul(
                                gamma3,
                                b.Current(SOURCE)))));
                b.Sub(
                    b.Mul(
                        b.Current(inverse),
                        b.Sub(
                            b.Challenge(alpha_idx),
                            tuple)),
                    b.Current(MASK));
            });
        AppendFragment(
            out, aq::AirKind::kEverywhere, 2,
            [inverse](FragmentProgramBuilder& b) {
                b.Mul(
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(MASK)),
                    b.Current(inverse));
            });
        AppendFragment(
            out, aq::AirKind::kFirstRow, 1,
            [running](FragmentProgramBuilder& b) {
                b.Current(running);
            });
        AppendFragment(
            out, aq::AirKind::kTransition, 3,
            [running, inverse](FragmentProgramBuilder& b) {
                const uint32_t contribution = b.Mul(
                    b.Current(MULTIPLICITY),
                    b.Mul(
                        b.Current(MASK),
                        b.Current(inverse)));
                b.Sub(
                    b.Next(running),
                    b.Add(
                        b.Current(running),
                        contribution));
            });
        AppendFragment(
            out, aq::AirKind::kLastRow, 3,
            [running, inverse, sum_idx](
                FragmentProgramBuilder& b) {
                const uint32_t contribution = b.Mul(
                    b.Current(MULTIPLICITY),
                    b.Mul(
                        b.Current(MASK),
                        b.Current(inverse)));
                b.Sub(
                    b.Add(
                        b.Current(running),
                        contribution),
                    b.Challenge(sum_idx));
            });
    }
    for (uint32_t bit = 0; bit < 32; ++bit) {
        AppendFragmentBoolean(out, TILE_BITS + bit);
    }
    AppendFragment(
        out, aq::AirKind::kEverywhere, 1,
        [](FragmentProgramBuilder& b) {
            uint32_t sum = b.Constant(Fp3::Zero());
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = b.Add(
                    sum,
                    b.Mul(
                        b.Constant(
                            gf::FromU64_3(
                                uint64_t{1} << bit)),
                        b.Current(TILE_BITS + bit)));
            }
            b.Sub(b.Current(TILE), sum);
        });
    AppendFragment(
        out, aq::AirKind::kEverywhere, 2,
        [](FragmentProgramBuilder& b) {
            const uint32_t multiplicity =
                b.Current(MULTIPLICITY);
            b.Sub(
                b.Mul(multiplicity, multiplicity),
                b.Constant(Fp3::One()));
        });
    AppendFragment(
        out, aq::AirKind::kTransition, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(b.Next(TILE), b.Current(TILE));
        });
    AppendFragment(
        out, aq::AirKind::kTransition, 1,
        [](FragmentProgramBuilder& b) {
            b.Sub(
                b.Next(MULTIPLICITY),
                b.Current(MULTIPLICITY));
        });
    if (!cb::ValidateProgramTable(out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool RetagProgramTable(
    cb::ProgramTable& table,
    RCStage3RelationRole role,
    std::string* why)
{
    table.role = role;
    for (auto& program : table.programs) {
        program.role = role;
    }
    return cb::ValidateProgramTable(table, why);
}

/**
 * The fixed SHA/ChaCha instruction AIR is one opcode kernel; immutable
 * preprocessed selector rows choose the canonical Sha256Compression or
 * ChaCha20Block schedule. BuildRCStage3CoupledHashKernelProgramTable emits
 * that exact 462-constraint opcode table. Retagging only its committed role is
 * therefore the canonical partial kernel for every registered fixed-program
 * site. It does NOT bind the selected schedule, public boundary, SSA-copy
 * provenance, or multi-instance manifest, so callers must keep the site's
 * semantic_relation_complete bit false.
 */
bool BuildFixedProgramLocalFragment(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledHashKernelProgramTable(
            RCStage3RelationRole::EpisodeDigest, out, why)) {
        return false;
    }
    return RetagProgramTable(out, role, why);
}

/** The exact structural stub the tests used (matmul_v4_rc_stage3_universal_
 * topology_tests.cpp OneColumnProgram), reproduced here so the honest
 * production path never depends on a *_tests.cpp translation unit. Unlike
 * that helper, callers below never mark this complete. */
cb::ProgramTable OneColumnStubProgram(RCStage3RelationRole role)
{
    cb::ProgramTable table;
    table.role = role;
    table.current_width = 1;
    table.next_width = 1;
    cb::Program program;
    program.role = role;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back(
        {cb::Opcode::Current, 0, 0, Fp3::Zero()});
    table.programs.push_back(std::move(program));
    return table;
}

ProductionFamilyProgramSourceV1 StubSource(
    const sites::ProductionProofSiteEntry& site, uint32_t family_index)
{
    ProductionFamilyProgramSourceV1 source;
    source.family_index = family_index;
    source.kind = site.kind;
    source.role = site.role;
    source.program = OneColumnStubProgram(site.role);
    source.public_input_schema = {
        static_cast<unsigned char>(family_index),
        static_cast<unsigned char>(static_cast<uint16_t>(site.role))};
    // Deliberately empty/false: a 1-column program proves nothing about the
    // relation this site names, so it must not claim any endpoint or
    // completeness. This is the honest counterpart of the *_tests.cpp
    // OneColumnProgram helper, which claims every role endpoint complete.
    source.semantic_endpoints.clear();
    source.semantic_relation_complete = false;
    return source;
}

/** One real, already-unit-tested bytecode program plus the exact single
 * endpoint it closes. Returns false when this site is served by a canonical
 * partial fragment instead of a semantically complete local program. */
bool RealFamilyFor(
    sites::ProductionProofSiteKind kind,
    RCStage3RelationRole role,
    cb::ProgramTable& program,
    RCStage3RelationEndpoint& endpoint,
    std::string* why)
{
    switch (kind) {
    case sites::ProductionProofSiteKind::EpisodeBuilderCounterXof:
        if (role != RCStage3RelationRole::EpisodeDeterministicBuilder) {
            return false;
        }
        if (!BuildRCStage3EpisodeBuilderTraceProgramTable(program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeBuilderTrace;
        return true;
    case sites::ProductionProofSiteKind::EpisodeDigestSha256d:
        if (role != RCStage3RelationRole::EpisodeDigest) return false;
        if (!BuildRCStage3EpisodePowProgramTable(program, why)) return false;
        endpoint = RCStage3RelationEndpoint::EpisodeDigestPow;
        return true;
    case sites::ProductionProofSiteKind::EpisodeTileTreeSha256d:
        if (role != RCStage3RelationRole::EpisodeTileTree) return false;
        if (!BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeTileTreeStream;
        return true;
    case sites::ProductionProofSiteKind::EpisodeGemmSumcheck:
        if (role != RCStage3RelationRole::EpisodeGemm) return false;
        if (!BuildRCStage3EpisodeLocalKernelProgramTable(
                RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeGemmSumcheck;
        return true;
    case sites::ProductionProofSiteKind::EpisodeWiring:
        if (role != RCStage3RelationRole::EpisodeWiring) return false;
        if (!BuildRCStage3EpisodeLocalKernelProgramTable(
                RCStage3EpisodeAirFamily::WiringEqualityFp3V1,
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeWiringCopy;
        return true;
    case sites::ProductionProofSiteKind::EpisodeExtractCore:
        if (role != RCStage3RelationRole::EpisodeExtract) return false;
        // scale_e=0 is the canonical wired default (matches
        // ResolveRCStage3EpisodeAirConstraintSystem's ExtractSamplerCoreFp3V1
        // case); other public scale exponents are proved by the same
        // builder at a different scale_e, not a different table shape.
        if (!BuildRCStage3EpisodeExtractLocalKernelProgramTable(
                /*scale_e=*/0, program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeExtractSampler;
        return true;
    case sites::ProductionProofSiteKind::CoupledBank:
        if (role != RCStage3RelationRole::CoupledBank) return false;
        if (!BuildRCStage3CoupledBankDequantProgramTableCanonical(
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledBankPages;
        return true;
    case sites::ProductionProofSiteKind::CoupledGemm:
        if (role != RCStage3RelationRole::CoupledGemm) return false;
        if (!BuildRCStage3CoupledLocalKernelProgramTable(
                RCStage3RelationRole::CoupledGemm, program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledGemmOutputY;
        return true;
    case sites::ProductionProofSiteKind::CoupledExtractCore:
        if (role != RCStage3RelationRole::CoupledExtract) return false;
        // scale_e=0 is the canonical wired default, matching the
        // EpisodeExtractCore family above.
        if (!BuildRCStage3CoupledExtractLocalKernelProgramTable(
                /*scale_e=*/0, program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledExtractSampler;
        return true;
    case sites::ProductionProofSiteKind::CoupledBarrierSha256d:
        if (role != RCStage3RelationRole::CoupledBarrier) return false;
        if (!BuildRCStage3HashKernelOutputProgramTable(
                RCStage3RelationRole::CoupledBarrier, program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledBarrierHash;
        return true;
    case sites::ProductionProofSiteKind::CoupledDigestSha256d:
        if (role != RCStage3RelationRole::CoupledDigest) return false;
        if (!BuildRCStage3HashKernelOutputProgramTable(
                RCStage3RelationRole::CoupledDigest, program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledDigestHash;
        return true;
    case sites::ProductionProofSiteKind::CoupledExchange:
        if (role != RCStage3RelationRole::CoupledExchange) return false;
        if (!BuildRCStage3CoupledExchangeTransportProgramTable(
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledExchangeOutput;
        return true;
    case sites::ProductionProofSiteKind::CoupledPermutation:
        if (role != RCStage3RelationRole::CoupledPermutation) return false;
        if (!BuildRCStage3CoupledPermutationTransportProgramTable(
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledPermutationOutput;
        return true;
    case sites::ProductionProofSiteKind::CoupledMix:
        if (role != RCStage3RelationRole::CoupledMix) return false;
        if (!BuildRCStage3CoupledLocalKernelProgramTable(
                RCStage3RelationRole::CoupledMix, program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::CoupledMixArithmetic;
        return true;
    default:
        return false;
    }
}

/**
 * Canonical but deliberately incomplete fragments for the fourteen sites
 * which previously had a structural one-column placeholder. A successful
 * return replaces that placeholder with executable relation bytecode, but it
 * never grants a semantic endpoint or completeness claim.
 */
bool PartialFamilyFor(
    sites::ProductionProofSiteKind kind,
    RCStage3RelationRole role,
    cb::ProgramTable& program,
    std::string* why)
{
    switch (kind) {
    case sites::ProductionProofSiteKind::EpisodeGemmOpenings:
        return role == RCStage3RelationRole::EpisodeGemm &&
            BuildRCStage3EpisodeSemanticMemoryProgramTable(
                role, program, why);
    case sites::ProductionProofSiteKind::EpisodeSignedRange:
        return role == RCStage3RelationRole::EpisodeGemm &&
            BuildSignedRangeLocalFragment(program, why);
    case sites::ProductionProofSiteKind::EpisodeRangeExtractCtl:
        return role == RCStage3RelationRole::EpisodeExtract &&
            BuildRangeExtractCtlParametricFragment(program, why);
    case sites::ProductionProofSiteKind::EpisodeScaleSha:
    case sites::ProductionProofSiteKind::EpisodeExtractChaCha:
    case sites::ProductionProofSiteKind::CoupledBankCounterXof:
    case sites::ProductionProofSiteKind::CoupledBankCommitmentSha256d:
    case sites::ProductionProofSiteKind::CoupledLobeInitCounterXof:
    case sites::ProductionProofSiteKind::CoupledPageScheduleXof:
    case sites::ProductionProofSiteKind::CoupledExchangeXof:
    case sites::ProductionProofSiteKind::CoupledPermutationXof:
    case sites::ProductionProofSiteKind::CoupledMixXof:
    case sites::ProductionProofSiteKind::CoupledExtractScaleSha:
    case sites::ProductionProofSiteKind::CoupledExtractChaCha:
        return BuildFixedProgramLocalFragment(role, program, why);
    default:
        return false;
    }
}

std::vector<unsigned char> PartialFamilySchemaSuffix(
    sites::ProductionProofSiteKind kind)
{
    // "P1", fragment class, fixed-program kind. The schema is an ABI
    // description (not witness data) and is committed by the registry.
    // Keeping SHA/XOF and ChaCha schedule classes distinct prevents two
    // identical local opcode tables under one role from becoming an
    // ambiguous verifying key.
    constexpr unsigned char LOCAL_MEMORY = 1;
    constexpr unsigned char LOCAL_RANGE = 2;
    constexpr unsigned char LOCAL_CTL = 3;
    constexpr unsigned char FIXED_PROGRAM = 4;
    constexpr unsigned char NONE = 0;
    constexpr unsigned char SHA256_COMPRESSION = 1;
    constexpr unsigned char CHACHA20_BLOCK = 2;
    switch (kind) {
    case sites::ProductionProofSiteKind::EpisodeGemmOpenings:
        return {'P', '1', LOCAL_MEMORY, NONE};
    case sites::ProductionProofSiteKind::EpisodeSignedRange:
        return {'P', '1', LOCAL_RANGE, NONE};
    case sites::ProductionProofSiteKind::EpisodeRangeExtractCtl:
        return {'P', '1', LOCAL_CTL, NONE};
    case sites::ProductionProofSiteKind::EpisodeExtractChaCha:
    case sites::ProductionProofSiteKind::CoupledExtractChaCha:
        return {
            'P', '1', FIXED_PROGRAM, CHACHA20_BLOCK};
    case sites::ProductionProofSiteKind::EpisodeScaleSha:
    case sites::ProductionProofSiteKind::CoupledBankCounterXof:
    case sites::ProductionProofSiteKind::CoupledBankCommitmentSha256d:
    case sites::ProductionProofSiteKind::CoupledLobeInitCounterXof:
    case sites::ProductionProofSiteKind::CoupledPageScheduleXof:
    case sites::ProductionProofSiteKind::CoupledExchangeXof:
    case sites::ProductionProofSiteKind::CoupledPermutationXof:
    case sites::ProductionProofSiteKind::CoupledMixXof:
    case sites::ProductionProofSiteKind::CoupledExtractScaleSha:
        return {
            'P', '1', FIXED_PROGRAM, SHA256_COMPRESSION};
    default:
        return {};
    }
}

uint32_t PartialResidualMask(
    sites::ProductionProofSiteKind kind)
{
    constexpr uint32_t PARAM =
        ProductionResidualPublicParameterOwnership;
    constexpr uint32_t SOURCE =
        ProductionResidualSourceRootProvenance;
    constexpr uint32_t SCHEDULE =
        ProductionResidualImmutableScheduleBinding;
    constexpr uint32_t COPY =
        ProductionResidualInternalCopyProvenance;
    constexpr uint32_t ALL =
        ProductionResidualExactAllInstanceAggregation;
    constexpr uint32_t RECURSE =
        ProductionResidualRecursiveConsumption;
    switch (kind) {
    case sites::ProductionProofSiteKind::EpisodeGemmOpenings:
        return SOURCE | ALL | RECURSE;
    case sites::ProductionProofSiteKind::EpisodeSignedRange:
        return PARAM | SOURCE | ALL | RECURSE;
    case sites::ProductionProofSiteKind::EpisodeRangeExtractCtl:
        return PARAM | SOURCE | SCHEDULE | ALL | RECURSE;
    case sites::ProductionProofSiteKind::EpisodeScaleSha:
    case sites::ProductionProofSiteKind::EpisodeExtractChaCha:
    case sites::ProductionProofSiteKind::CoupledBankCounterXof:
    case sites::ProductionProofSiteKind::CoupledBankCommitmentSha256d:
    case sites::ProductionProofSiteKind::CoupledLobeInitCounterXof:
    case sites::ProductionProofSiteKind::CoupledPageScheduleXof:
    case sites::ProductionProofSiteKind::CoupledExchangeXof:
    case sites::ProductionProofSiteKind::CoupledPermutationXof:
    case sites::ProductionProofSiteKind::CoupledMixXof:
    case sites::ProductionProofSiteKind::CoupledExtractScaleSha:
    case sites::ProductionProofSiteKind::CoupledExtractChaCha:
        return PARAM | SOURCE | SCHEDULE | COPY | ALL | RECURSE;
    default:
        return 0;
    }
}

bool SameSource(
    const ProductionFamilyProgramSourceV1& lhs,
    const ProductionFamilyProgramSourceV1& rhs)
{
    return lhs.family_index == rhs.family_index &&
        lhs.kind == rhs.kind &&
        lhs.role == rhs.role &&
        lhs.program == rhs.program &&
        lhs.public_input_schema == rhs.public_input_schema &&
        lhs.semantic_endpoints == rhs.semantic_endpoints &&
        lhs.semantic_relation_complete ==
            rhs.semantic_relation_complete;
}

} // namespace

bool BuildProductionSignedRangeLocalProgramTableV1(
    cb::ProgramTable& out,
    std::string* why)
{
    return BuildSignedRangeLocalFragment(out, why);
}

std::vector<ProductionFamilyProgramSourceV1>
BuildProductionFamilyProgramSourcesV1(
    const sites::ProductionProofSiteManifest& manifest)
{
    std::vector<ProductionFamilyProgramSourceV1> out;
    out.reserve(manifest.entries.size());
    for (size_t i = 0; i < manifest.entries.size(); ++i) {
        const auto& site = manifest.entries[i];
        ProductionFamilyProgramSourceV1 source =
            StubSource(site, static_cast<uint32_t>(i));

        cb::ProgramTable real;
        RCStage3RelationEndpoint endpoint{};
        std::string why;
        if (RealFamilyFor(site.kind, site.role, real, endpoint, &why) &&
            cb::ValidateProgramTable(real, &why)) {
            source.program = std::move(real);
            source.semantic_endpoints = {
                static_cast<uint16_t>(endpoint)};
            source.semantic_relation_complete = true;
        } else if (
            PartialFamilyFor(
                site.kind, site.role, real, &why) &&
            cb::ValidateProgramTable(real, &why)) {
            source.program = std::move(real);
            const auto suffix =
                PartialFamilySchemaSuffix(site.kind);
            source.public_input_schema.insert(
                source.public_input_schema.end(),
                suffix.begin(), suffix.end());
            // A partial canonical kernel is materially different from the
            // old structural placeholder, but still makes no endpoint-level
            // completeness claim.
            source.semantic_endpoints.clear();
            source.semantic_relation_complete = false;
        }
        out.push_back(std::move(source));
    }
    return out;
}

bool ValidateProductionFamilyProgramSourcesV1(
    const sites::ProductionProofSiteManifest& manifest,
    const std::vector<ProductionFamilyProgramSourceV1>& sources,
    std::string* why)
{
    std::string manifest_why;
    if (!sites::ValidateProductionProofSiteManifest(
            manifest, &manifest_why)) {
        if (why != nullptr) {
            *why =
                "stage3:production_family_programs:"
                "manifest:" + manifest_why;
        }
        return false;
    }
    const std::vector<ProductionFamilyProgramSourceV1> expected =
        BuildProductionFamilyProgramSourcesV1(manifest);
    if (expected.size() != manifest.entries.size() ||
        sources.size() != expected.size()) {
        if (why != nullptr) {
            *why =
                "stage3:production_family_programs:"
                "canonical_family_count";
        }
        return false;
    }
    for (size_t i = 0; i < expected.size(); ++i) {
        if (!SameSource(sources[i], expected[i])) {
            if (why != nullptr) {
                *why =
                    "stage3:production_family_programs:"
                    "canonical_family_substitution:" +
                    std::to_string(i);
            }
            return false;
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:production_family_programs:"
            "canonical_sources";
    }
    return true;
}

ProductionFamilyProgramMigrationStatusV1
AssessProductionFamilyProgramMigrationV1(
    const std::vector<ProductionFamilyProgramSourceV1>& sources)
{
    ProductionFamilyProgramMigrationStatusV1 out;
    out.families_total = static_cast<uint32_t>(sources.size());
    std::set<RCStage3RelationRole> roles;
    std::set<uint16_t> endpoints;
    for (const auto& source : sources) {
        const bool structural_stub =
            !source.semantic_relation_complete &&
            source.semantic_endpoints.empty() &&
            source.program.current_width == 1 &&
            source.program.next_width == 1 &&
            source.program.programs.size() == 1 &&
            source.program.programs[0].instructions.size() == 1 &&
            source.program.programs[0].instructions[0].opcode ==
                cb::Opcode::Current;
        if (structural_stub) {
            ++out.families_structural_stubs;
        } else {
            ++out.families_non_stub;
            if (!source.semantic_relation_complete) {
                ++out.families_partial;
                out.partial_residuals.push_back({
                    source.kind,
                    PartialResidualMask(source.kind)});
            }
        }
        if (!source.semantic_relation_complete ||
            source.semantic_endpoints.empty()) {
            continue;
        }
        ++out.families_real;
        roles.insert(source.role);
        endpoints.insert(
            source.semantic_endpoints.begin(),
            source.semantic_endpoints.end());
    }
    out.roles_with_real_program = static_cast<uint32_t>(roles.size());
    out.real_roles.assign(roles.begin(), roles.end());
    out.real_endpoints.assign(endpoints.begin(), endpoints.end());
    return out;
}

} // namespace matmul::v4::rc::universal_topology
