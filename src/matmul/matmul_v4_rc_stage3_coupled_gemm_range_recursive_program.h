// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_GEMM_RANGE_RECURSIVE_PROGRAM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_GEMM_RANGE_RECURSIVE_PROGRAM_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::coupled_gemm_range_recursive_program {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Verifier-owned values used by the two exact child relations.
 *
 * The first six entries are the dual-Fp3 CTL challenges/claimed terminal.
 * MAX_ABS and LOGICAL_ROWS replace the two pin-captured constants in the
 * signed-range callbacks.  They remain outside the committed ProgramTable,
 * so every shard uses the same canonical bytecode root.
 */
enum ChallengeColumnV1 : uint32_t {
    GAMMA1 = 0,
    GAMMA2,
    ALPHA1,
    ALPHA2,
    EXPECTED_TERMINAL1,
    EXPECTED_TERMINAL2,
    MAX_ABS,
    MAX_ABS_BITS,
    LOGICAL_ROWS =
        MAX_ABS_BITS + kRCStage3SignedRangeBits,
    NUM_CHALLENGES,
};

/** Exact bytecode for BuildRCStage3CoupledGemmDotConstraintSystem followed by
 * the producer (+1) gated dual-Fp3 CTL relation. */
[[nodiscard]] bool BuildGemmProgramV1(
    cb::ProgramTable& out,
    std::string* why = nullptr);

/** Exact bytecode for ResolveRCStage3SignedRangeKernelConstraintSystem
 * followed by the receiver (-1) gated dual-Fp3 CTL relation. */
[[nodiscard]] bool BuildRangeProgramV1(
    cb::ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] std::vector<gf::Fp3> BuildGemmChallengesV1(
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal);

[[nodiscard]] std::vector<gf::Fp3> BuildRangeChallengesV1(
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    uint64_t max_abs,
    uint32_t logical_rows);

inline constexpr bool kExactNativeRelationV1 = true;
inline constexpr bool kChallengeIndependentProgramV1 = true;
inline constexpr bool kNormalizedParentConsumedV1 = false;

static_assert(!kNormalizedParentConsumedV1);

} // namespace matmul::v4::rc::coupled_gemm_range_recursive_program

#endif
