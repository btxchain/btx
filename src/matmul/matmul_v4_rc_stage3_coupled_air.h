// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_coupled.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Proof-only coupled AIR registry.
 *
 * These builders consume only public shape/challenge data. They never call
 * BuildCoupledWires, RecomputeCoupledPuzzleReference, or any native puzzle
 * execution path. The returned systems are immutable relation kernels; a
 * later proof carrier must bind their trace columns to the Stage-3 receipt
 * roots and recursively aggregate every scheduled instance.
 */
enum class RCStage3CoupledAirGapCode : uint8_t {
    CommitmentOpeningBridge = 1,
    BankSeedXof = 2,
    BankPageInclusion = 3,
    PublicScheduleBinding = 4,
    MaterialExchangeHashXof = 5,
    ExtractChaChaAndScaleSha = 6,
    ExtractInt64AndRangeLookups = 7,
    BarrierSha256d = 8,
    DigestSha256d = 9,
    RecursiveAggregation = 10,
};

struct RCStage3CoupledAirGap {
    RCStage3CoupledAirGapCode code{};
    std::string detail;

    bool operator==(const RCStage3CoupledAirGap&) const = default;
};

struct RCStage3CoupledAirCoverage {
    RCStage3CoupledRelationCounts required{};
    /** Counts governed by the local algebraic kernel when instantiated over
     * the complete schedule. These are zero when no AIR exists. */
    RCStage3CoupledRelationCounts kernel{};

    bool operator==(const RCStage3CoupledAirCoverage&) const = default;
};

struct RCStage3CoupledAirRequest {
    RCStage3RelationRole role{RCStage3RelationRole::CoupledBank};
    RCStage3CoupledShape shape{};
    /** Fp3 Fiat-Shamir challenges fixed before the relation proof. */
    gkr_field::Fp3 gamma{};
    gkr_field::Fp3 alpha{};
    /** Public Extract scale exponent for a sampler shard (0..3). Other
     * relations ignore it. */
    uint8_t extract_scale_e{0};
};

struct RCStage3CoupledAirEntry {
    RCStage3RelationRole role{};
    bool constraint_system_available{false};
    /** True only for the local kernel, not for the whole registered role. */
    bool local_kernel_complete{false};
    /** False while any residual gap remains. */
    bool proof_only_complete{false};
    RCStage3CoupledAirCoverage coverage{};
    air_quotient::AirConstraintSystem<gkr_field::Fp3> constraints;
    std::vector<RCStage3CoupledAirGap> gaps;
};

/** Build one immutable registry entry, including exact coverage and residuals.
 * Unknown/non-coupled roles and malformed shapes fail closed. */
[[nodiscard]] bool ResolveRCStage3CoupledAir(
    const RCStage3CoupledAirRequest& request,
    RCStage3CoupledAirEntry& out,
    std::string* why = nullptr);

/** Deterministic eight-role audit in canonical coupled-role order. */
[[nodiscard]] std::vector<RCStage3CoupledAirEntry>
AssessRCStage3CoupledAirRegistry(const RCStage3CoupledShape& shape,
                                 const gkr_field::Fp3& gamma,
                                 const gkr_field::Fp3& alpha,
                                 uint8_t extract_scale_e = 0);

/** Hard completeness predicate. It remains false until all entries have a
 * complete system, no residual gaps, and exact required/kernel coverage. */
[[nodiscard]] bool RCStage3CoupledAirRegistryReady(
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    std::string* why = nullptr);

/**
 * Canonical relation source for the five migrated coupled local kernels.
 * Extract and the two hash roles deliberately fail until their registered
 * callback systems have exact bytecode equivalents.
 */
[[nodiscard]] bool BuildRCStage3CoupledLocalKernelProgramTable(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

// Stable local-kernel column layouts, exposed for prover construction and
// mutation tests. They are not a consensus proof encoding.
namespace coupled_air_col {

enum Bank : uint32_t {
    BANK_NIB = 0,
    BANK_NB0,
    BANK_NB1,
    BANK_NB2,
    BANK_NB3,
    BANK_ACC,
    BANK_MU,
    BANK_E0,
    BANK_E1,
    BANK_OUT,
    BANK_NUM_COLS,
};

enum Gemm : uint32_t {
    GEMM_A = 0,
    GEMM_B,
    GEMM_ACC,
    GEMM_OUT,
    GEMM_ACTIVE,
    GEMM_NUM_COLS,
};

enum Copy : uint32_t {
    COPY_INPUT = 0,
    COPY_OUTPUT,
    COPY_NUM_COLS,
};

/** Four little-endian 16-bit limbs each for a, b, a+b mod 2^64, b-a mod
 * 2^64, followed by their 256 boolean decomposition cells and 8 carry/borrow
 * bits. */
inline constexpr uint32_t MIX_A_LIMB = 0;
inline constexpr uint32_t MIX_B_LIMB = 4;
inline constexpr uint32_t MIX_SUM_LIMB = 8;
inline constexpr uint32_t MIX_DIFF_LIMB = 12;
inline constexpr uint32_t MIX_BITS = 16;
inline constexpr uint32_t MIX_CARRY = MIX_BITS + 16U * 16U;
inline constexpr uint32_t MIX_BORROW = MIX_CARRY + 4U;
inline constexpr uint32_t MIX_NUM_COLS = MIX_BORROW + 4U;

} // namespace coupled_air_col

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_AIR_H
