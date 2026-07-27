// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_FAMILY_PROGRAMS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_FAMILY_PROGRAMS_H

#include <matmul/matmul_v4_rc_stage3_universal_topology.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Production family program sources for the universal Stage-3 program
// registry (matmul_v4_rc_stage3_universal_topology.h).
//
// ValidateProductionProgramRegistryV1 is PURELY STRUCTURAL: it accepts any
// registry built from `cb::ProgramTable`s that decode, canonicalize, and
// root-pin, including 1-column stub programs that constrain nothing about the
// relation they claim to sit at. Before this module every real caller of
// BuildProductionProgramRegistryV1 was a *_tests.cpp file constructing those
// stubs (`OneColumnProgram`).
//
// This is the PRODUCTION (non-test) family-source builder. For every one of
// the 28 manifest sites it emits either:
//
//   (a) a REAL ProgramTable, reused byte-for-byte from an existing,
//       independently unit-tested role_bytecode.{h,cpp} builder that is
//       already exercised by production code elsewhere in the tree (the
//       episode PoW borrow-chain CS backs BuildRCStage3EpisodePowConstraintSystem,
//       the dequant CS backs the episode builder-trace product, etc.) -- with
//       `semantic_endpoints` set to EXACTLY the endpoint(s) that table's
//       constraints close, and `semantic_relation_complete=true` only for
//       that honestly-scoped claim; or
//   (b) the same structural 1-column stub the tests used, but with
//       `semantic_endpoints={}` and `semantic_relation_complete=false` --
//       i.e. it does NOT claim completeness it cannot back, unlike the test
//       helper it replaces.
//
// This is deliberately partial. It does not flip any `*_ready` constant, does
// not claim the registry is production-complete, and does not claim any
// episode relation Gap() is closed: the wired families are per-ENDPOINT
// sub-relations, not whole-role recursive authority engines. See
// AssessProductionFamilyProgramMigrationV1 for the exact honest count.
// ============================================================================

namespace matmul::v4::rc::universal_topology {

/**
 * Real (non-stub) family sources currently wired into the production
 * registry path, keyed by the exact ProductionProofSiteKind they replace a
 * OneColumnProgram stub for. Extending this list is the concrete, checkable
 * unit of "registry migration" progress: each entry must cite the
 * role_bytecode builder it reuses and the exact endpoint(s) it closes.
 */
enum class RealProductionFamilyProgramV1 : uint8_t {
    /** BuildRCStage3EpisodeBuilderTraceProgramTable: the endpoint-4
     * mantissa/scale dequantization relation (5 constraints, 6 columns).
     * Closes RCStage3RelationEndpoint::EpisodeBuilderTrace only; Params,
     * SeedChain and OperandXof remain unclosed by any family. */
    EpisodeBuilderTraceDequant = 1,
    /** BuildRCStage3EpisodePowProgramTable: the twelve-column digest<=target
     * borrow-chain relation (14 constraints incl. booleanity), the same
     * table BuildRCStage3EpisodePowConstraintSystem uses in production.
     * Closes RCStage3RelationEndpoint::EpisodeDigestPow only; RoundRoots,
     * Value and HeaderTarget remain unclosed by any family. */
    EpisodeDigestPowBorrowChain = 2,
    /** BuildRCStage3EpisodeTileTreeByteBridgeProgramTable: the signed-byte
     * <-> octet bridge for tile-stream values (16 constraints, 15 columns).
     * Closes RCStage3RelationEndpoint::EpisodeTileTreeStream only; LeafHash,
     * InternalHash and Root remain unclosed by any family. */
    EpisodeTileTreeStreamByteBridge = 3,
    /** BuildRCStage3EpisodeLocalKernelProgramTable(GemmEndpointFp3V1): the
     * one-constraint gf=a*b identity that is the terminal check of the GKR
     * sumcheck reduction, already exercised in production by
     * ResolveRCStage3EpisodeAirConstraintSystem / VerifyRCStage3EpisodeAirShard.
     * Closes RCStage3RelationEndpoint::EpisodeGemmSumcheck only; OperandA,
     * OperandB, OutputY and SignedRange remain unclosed by any family. */
    EpisodeGemmSumcheckEndpoint = 4,
    /** BuildRCStage3EpisodeLocalKernelProgramTable(WiringEqualityFp3V1): the
     * one-constraint direct row-copy equality u=v, already exercised in
     * production by the same AIR-shard verifier as the Gemm endpoint above.
     * Closes RCStage3RelationEndpoint::EpisodeWiringCopy only; Transpose,
     * Residual and RoundOrder remain unclosed by any family. */
    EpisodeWiringCopyEquality = 5,
    /** BuildRCStage3EpisodeExtractLocalKernelProgramTable(scale_e=0): the
     * complete 47-constraint, 40-column RcSampler relation as bytecode
     * (bit-identical to air_quotient::BuildRcSamplerConstraintSystem),
     * already exercised in production by the same AIR-shard verifier
     * (ResolveRCStage3EpisodeAirConstraintSystem's ExtractSamplerCoreFp3V1
     * case delegates to this exact builder at scale_e=0).
     * Closes RCStage3RelationEndpoint::EpisodeExtractSampler only; Input,
     * ChaCha, Scale and Output remain unclosed by any family. */
    EpisodeExtractSamplerCore = 6,
    /** BuildRCStage3CoupledBankDequantProgramTableCanonical: the six-column
     * bank dequantization relation, the role-separated twin of
     * EpisodeBuilderTraceDequant above and already exercised in production
     * by BuildRCStage3CoupledBankDequantProgramTable / ProveRCStage3-
     * CoupledBankProduct / VerifyRCStage3CoupledBankProduct.
     * Closes RCStage3RelationEndpoint::CoupledBankPages only; SeedXof and
     * Root remain unclosed by any family. */
    CoupledBankPagesDequant = 7,
    /** BuildRCStage3CoupledLocalKernelProgramTable(CoupledGemm): the
     * five-column running-accumulation identity (per-row a*b accumulate,
     * terminal ACC==OUT), already exercised in production by
     * matmul_v4_rc_stage3_relation_closure.cpp's coupled-gemm endpoint
     * resolvers. Closes RCStage3RelationEndpoint::CoupledGemmOutputY only;
     * OperandA, OperandB and SignedRange remain unclosed by any family. */
    CoupledGemmOutputIdentity = 8,
    /** BuildRCStage3CoupledExtractLocalKernelProgramTable(scale_e=0): the
     * coupled analogue of EpisodeExtractSamplerCore above -- the identical
     * 47-constraint, 40-column RcSampler relation committed under the
     * CoupledExtract role instead.
     * Closes RCStage3RelationEndpoint::CoupledExtractSampler only; Input,
     * ChaCha, Scale and Output remain unclosed by any family. */
    CoupledExtractSamplerCore = 9,
    /** BuildRCStage3CoupledHashKernelProgramTable(CoupledBarrier): the
     * selector-pinned SHA-256 compression AIR (462 constraints, 144
     * columns), already exercised in production by the same hash-kernel
     * builder shared with CoupledDigest below.
     * Closes RCStage3RelationEndpoint::CoupledBarrierHash only; Input and
     * Output remain unclosed by any family. */
    CoupledBarrierHashKernel = 10,
    /** BuildRCStage3CoupledHashKernelProgramTable(CoupledDigest): the same
     * SHA-256 compression AIR as CoupledBarrierHashKernel above, committed
     * under the CoupledDigest role instead (the committed table role
     * prevents cross-role replay).
     * Closes RCStage3RelationEndpoint::CoupledDigestHash only;
     * BankAndBarriers and Value remain unclosed by any family. */
    CoupledDigestHashKernel = 11,
    /** BuildRCStage3CoupledLocalKernelProgramTable(CoupledMix): the 280-column
     * limb-reconstructed uint64 add/sub identity (A+B and B-A with per-limb
     * carry/borrow), already exercised in production by
     * BuildRCStage3CoupledMixedRoleAir / the coupled-mix role product.
     * Closes RCStage3RelationEndpoint::CoupledMixArithmetic only; Input,
     * Output and the public butterfly/rotate schedule remain unclosed. */
    CoupledMixArithmeticKernel = 12,
    /** BuildRCStage3CoupledPermutationTransportProgramTable: the six-
     * constraint indexed-permutation LogUp grand-product transport lane
     * (14 columns, challenge-independent beta/gamma class), already
     * differentially tested against the native coupled permutation product.
     * Closes RCStage3RelationEndpoint::CoupledPermutationOutput only; Input
     * and the bit-affine schedule XOF remain unclosed by any family. */
    CoupledPermutationTransport = 13,
    /** BuildRCStage3CoupledExchangeTransportProgramTable: the same two
     * LogUp grand-product lanes as CoupledPermutationTransport, over the
     * 214-column material-exchange layout (mixed-limb source, output-limb
     * destination). Mixing boolean/xor/limb-recompose constraints stay
     * pre-challenge and are not claimed here.
     * Closes RCStage3RelationEndpoint::CoupledExchangeOutput only; Input
     * and HashXof remain unclosed by any family. */
    CoupledExchangeTransport = 14,
};

/**
 * Build the exact 28-entry family source list consumed by
 * BuildProductionProgramRegistryV1, honestly mixing the real programs above
 * with 1-column stubs (marked incomplete, not claimed) for every site this
 * session did not reach.
 */
[[nodiscard]] std::vector<ProductionFamilyProgramSourceV1>
BuildProductionFamilyProgramSourcesV1(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);

struct ProductionFamilyProgramMigrationStatusV1 {
    uint32_t families_total{0};
    uint32_t families_real{0};
    uint32_t roles_total{14};
    uint32_t roles_with_real_program{0};
    std::vector<RCStage3RelationRole> real_roles;
    std::vector<uint16_t> real_endpoints;

    bool operator==(
        const ProductionFamilyProgramMigrationStatusV1&) const = default;
};

/** Recomputed straight from `sources`: never a literal, so it cannot drift
 * from what BuildProductionFamilyProgramSourcesV1 actually emitted. */
[[nodiscard]] ProductionFamilyProgramMigrationStatusV1
AssessProductionFamilyProgramMigrationV1(
    const std::vector<ProductionFamilyProgramSourceV1>& sources);

} // namespace matmul::v4::rc::universal_topology

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_FAMILY_PROGRAMS_H
