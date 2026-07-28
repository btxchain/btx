// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_FAMILY_PROGRAMS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_FAMILY_PROGRAMS_H

#include <matmul/matmul_v4_rc_stage3_fixed_program_provenance_bytecode.h>
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
//   (b) a real canonical PARTIAL kernel, with `semantic_endpoints={}` and
//       `semantic_relation_complete=false`, where schedule/provenance/public
//       pins/all-instance aggregation remain outside the immutable local
//       table; or
//   (c) a defensive fail-closed structural fallback, with no endpoint or
//       completeness claim. The current 28-site manifest reaches neither
//       this fallback nor any other one-column stub.
//
// This is deliberately partial. It does not flip any `*_ready` constant, does
// not claim the registry is production-complete, and does not claim any
// episode relation Gap() is closed: the wired families are per-ENDPOINT
// sub-relations, not whole-role recursive authority engines. See
// AssessProductionFamilyProgramMigrationV1 for the exact honest count.
// ============================================================================

namespace matmul::v4::rc::universal_topology {

namespace fixed_program_abi_v1 {
inline constexpr uint16_t Version = 1;
inline constexpr uint32_t BoundaryExpectedBase =
    stage3_hash_air::kFixedProgramBoundaryExpectedBase;
inline constexpr uint32_t BoundaryExpectedCount = 4;
inline constexpr uint32_t BoundaryMaskBase =
    stage3_hash_air::kFixedProgramBoundaryMaskBase;
inline constexpr uint32_t BoundaryMaskCount = 4;
inline constexpr uint32_t InputAddressBase =
    stage3_hash_air::kFixedProgramProvenanceInputAddressBase;
inline constexpr uint32_t InputMaskBase =
    stage3_hash_air::kFixedProgramProvenanceInputMaskBase;
inline constexpr uint32_t InputSlots = 3;
inline constexpr uint32_t OutputAddress =
    stage3_hash_air::kFixedProgramProvenanceOutputAddress;
inline constexpr uint32_t OutputValue =
    fixed_program_provenance_bytecode::kOutputColumnV1;
} // namespace fixed_program_abi_v1

/**
 * Complete canonical bytecode for one CoupledExtract ChaCha block.
 *
 * The returned table contains the opcode constraints, public-boundary
 * equality constraints, selector-muxed output, dual-Fp3 challenge products
 * and the complete internal SSA producer/consumer relation.  `schema_suffix`
 * commits the exact ChaCha schedule and the trace-column ABI above; it is
 * appended to the production registry's family schema.
 *
 * This closes only the local CoupledExtractChaCha relation. Equality from the
 * caller's CoupledExtract input/output roots, exact all-instance aggregation
 * and recursive receipt consumption remain separate parent obligations.
 */
[[nodiscard]] bool
BuildProductionCoupledExtractChaChaProgramTableV1(
    constraint_bytecode::ProgramTable& out,
    fixed_program_provenance_bytecode::ManifestV1*
        manifest = nullptr,
    std::vector<unsigned char>* schema_suffix = nullptr,
    std::string* why = nullptr);

/**
 * Stable output-column ABI for the role-local direct products below.  Each
 * component occupies disjoint trace columns and disjoint challenge lanes.
 * These constants are consumed by the endpoint/program bridge and are
 * static-asserted against every component width in the builder.
 */
namespace production_family_col_v1 {
inline constexpr uint32_t EpisodeBuilderTrace = 5;
inline constexpr uint32_t EpisodeBuilderParams = 10;
inline constexpr uint32_t EpisodeBuilderSeedChain = 15;
inline constexpr uint32_t EpisodeBuilderOperandXof = 20;
inline constexpr uint32_t EpisodeWiringCopy = 0;
inline constexpr uint32_t EpisodeWiringTranspose = 5;
inline constexpr uint32_t EpisodeWiringResidual = 13;
inline constexpr uint32_t EpisodeWiringRoundOrder = 15;
inline constexpr uint32_t EpisodeTileTreeStream = 4;
inline constexpr uint32_t EpisodeTileTreeHash = 159;
inline constexpr uint32_t EpisodeDigestRoundRoots = 4;
inline constexpr uint32_t EpisodeDigestValue = 176;
inline constexpr uint32_t EpisodeDigestHeaderTarget = 18;
inline constexpr uint32_t EpisodeDigestPow = 20;
inline constexpr uint32_t CoupledGemmOutput = 3;
inline constexpr uint32_t CoupledGemmSignedRange = 7;
inline constexpr uint32_t CoupledRootInput = 3;
inline constexpr uint32_t CoupledRootOutput = 4;
inline constexpr uint32_t CoupledHashOutput = 149;
} // namespace production_family_col_v1

/**
 * Canonical, pin-independent signed-range ProgramTable used by the production
 * EpisodeSignedRange family.  The table includes the complete local range
 * polynomial system and explicit MAX_ABS/LOGICAL_ROWS parameter columns.
 * Ownership of those parameters, the source roots, all-instance aggregation,
 * and recursive consumption remain separate residuals.
 */
[[nodiscard]] bool BuildProductionSignedRangeLocalProgramTableV1(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical role-tagged fixed-program opcode kernel used by every partial
 * SHA/XOF/ChaCha production family.  In addition to the shared 144-column
 * opcode AIR, column kRCStage3HashKernelOutputColumnV1 is constrained to the
 * opcode-selected result slot.  Schedule, boundary, internal-copy,
 * all-instance, and recursive-consumption obligations remain explicit
 * residuals; this function only gives those partial families an unambiguous
 * local output cell. CoupledExtractChaCha now uses the complete provenance
 * table above instead of this fragment.
 */
[[nodiscard]] bool BuildProductionFixedProgramOutputLocalProgramTableV1(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Rebuild the exact ProgramTable selected for one production proof-site.
 * This is the single canonical source used both by the registry builder and
 * by endpoint output routing. It returns false rather than manufacturing the
 * defensive one-column fallback.
 */
[[nodiscard]] bool BuildCanonicalProductionFamilyProgramTableV1(
    soundness_scenarios::ProductionProofSiteKind kind,
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Semantically complete family sources currently wired into the production
 * registry path, keyed by exact ProductionProofSiteKind. Extending this list
 * is the concrete, checkable unit of semantic registry migration: each entry
 * must cite the role_bytecode builder it reuses and the exact endpoint(s) it
 * closes. Nontrivial-but-partial sources are separately classified by
 * AssessProductionFamilyProgramMigrationV1.
 */
enum class RealProductionFamilyProgramV1 : uint8_t {
    /** Challenge-separated direct product of the endpoint-4 mantissa/scale
     * dequantization relation and three expected-vector export relations for
     * Params, SeedChain and OperandXof (21 columns, 17 constraints). The
     * registry completeness claim remains scoped to BuilderTrace; the three
     * vector exports retain verifier-owned expected-column root pins,
     * fixed-program provenance, aggregation and recursive-consumption
     * residuals. */
    EpisodeBuilderTraceDequant = 1,
    /** Challenge-separated direct product of root-vector, preimage-byte,
     * compact-target, digest<=target and fixed-program hash bytecode
     * components (177 columns, 495 constraints). The registry completeness
     * claim remains scoped to the already complete EpisodeDigestPow relation;
     * the other component outputs are named but retain their provenance,
     * schedule, aggregation and recursive-consumption residuals. */
    EpisodeDigestPowBorrowChain = 2,
    /** Direct product of the signed-byte tile-stream bridge and the
     * selector-safe fixed-program hash kernel (160 columns, 479 constraints).
     * The registry completeness claim remains scoped to TileTreeStream;
     * leaf/internal/root hash outputs are named without overclaiming the
     * still-missing schedule/provenance/aggregation/recursion links. */
    EpisodeTileTreeStreamByteBridge = 3,
    /** BuildRCStage3EpisodeLocalKernelProgramTable(GemmEndpointFp3V1): the
     * one-constraint gf=a*b identity that is the terminal check of the GKR
     * sumcheck reduction, already exercised in production by
     * ResolveRCStage3EpisodeAirConstraintSystem / VerifyRCStage3EpisodeAirShard.
     * Closes RCStage3RelationEndpoint::EpisodeGemmSumcheck only; OperandA,
     * OperandB, OutputY and SignedRange remain unclosed by any family. */
    EpisodeGemmSumcheckEndpoint = 4,
    /** Challenge-separated direct product of row-copy equality, dual-LogUp
     * transpose, residual-addition/Extract alias, and round-order producer /
     * consumer equality (16 columns, 4 challenge lanes, 10 constraints).
     * The registry completeness claim remains scoped to WiringCopy; all four
     * local outputs are named while immutable schedules, memory openings and
     * recursive consumption remain explicit residuals. */
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
    /** Direct product of the five-column running-accumulation identity and
     * the canonical 102-column signed-range relation (107 columns,
     * 183 constraints). The registry completeness claim remains scoped to
     * CoupledGemmOutputY; SignedRange gets an exact output cell but retains
     * public-pin, root, aggregation and recursion residuals. */
    CoupledGemmOutputIdentity = 8,
    /** BuildRCStage3CoupledExtractLocalKernelProgramTable(scale_e=0): the
     * coupled analogue of EpisodeExtractSamplerCore above -- the identical
     * 47-constraint, 40-column RcSampler relation committed under the
     * CoupledExtract role instead.
     * Closes RCStage3RelationEndpoint::CoupledExtractSampler only; Input,
     * ChaCha, Scale and Output remain unclosed by any family. */
    CoupledExtractSamplerCore = 9,
    /** Direct product of the five-column root-vector relation and the
     * selector-safe fixed-program hash kernel (150 columns, 467 constraints).
     * The registry completeness claim remains scoped to CoupledBarrierHash;
     * Input/Output cells are now unambiguous but still require the actual
     * cross-component provenance/schedule/recursive links. */
    CoupledBarrierHashKernel = 10,
    /** The corresponding 150-column/467-constraint CoupledDigest direct
     * product, committed under the distinct CoupledDigest role. The registry
     * completeness claim remains scoped to CoupledDigestHash; the named
     * BankAndBarriers/Value cells keep their provenance and recursion
     * residuals. */
    CoupledDigestHashKernel = 11,
    /** BuildRCStage3CoupledExchangeTransportProgramTable: the complete
     * dual-lane indexed-permutation transport relation over the 214-column
     * material trace.  The beta-vector/gamma values are verifier-owned
     * post-challenge columns, so the committed table is challenge independent.
     * This closes the local input-to-output transport at endpoint 36; the
     * separate material hash-XOF producer remains outside this table. */
    CoupledExchangeOutputTransport = 12,
    /** BuildRCStage3CoupledPermutationTransportProgramTable: the complete
     * dual-lane indexed-permutation transport relation over the canonical
     * 14-column permutation trace.  This closes the local transport at
     * endpoint 38; the bit-affine index schedule/provenance remains a
     * separate family obligation. */
    CoupledPermutationOutputTransport = 13,
    /** BuildRCStage3CoupledLocalKernelProgramTable(CoupledMix): the complete
     * 280-column, 288-constraint local limb/range/add/sub kernel.  This closes
     * the local arithmetic relation at endpoint 40; the global butterfly
     * schedule and producer-root equalities remain separate obligations. */
    CoupledMixArithmeticKernel = 14,
};

/**
 * Build the exact 28-entry family source list consumed by
 * BuildProductionProgramRegistryV1, honestly mixing the real programs above
 * with honestly incomplete canonical fragments for sites whose whole
 * schedule/provenance relation is not yet closed. The current builder has no
 * residual one-column structural stubs; that is deliberately distinct from
 * whole-site semantic completeness, which remains 14/28. In particular, the
 * CoupledExtractChaCha table now closes its local provenance relation but
 * remains a partial site until source-root, all-instance and recursive
 * obligations are consumed.
 */
[[nodiscard]] std::vector<ProductionFamilyProgramSourceV1>
BuildProductionFamilyProgramSourcesV1(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);

/**
 * Fail-closed equality to the canonical source list built above.  The generic
 * universal-topology registry validator is intentionally structural and will
 * accept a well-formed one-column table; production callers therefore need
 * this stronger check before treating a family list as the immutable
 * verifying-key inventory.  It rejects stub substitution, role/program
 * substitution, endpoint overclaim and schema drift.
 */
[[nodiscard]] bool ValidateProductionFamilyProgramSourcesV1(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const std::vector<ProductionFamilyProgramSourceV1>& sources,
    std::string* why = nullptr);

enum ProductionFamilyResidualObligationV1 : uint32_t {
    /** Verifier-owned MAX_ABS/tile/program-boundary values are not yet
     * root-pinned by the normalized parent. */
    ProductionResidualPublicParameterOwnership = 1U << 0,
    /** Local VALUE/export cells are not yet equality-linked to the owning
     * producer proof's authenticated columns. */
    ProductionResidualSourceRootProvenance = 1U << 1,
    /** The exact canonical selector/tile/instance schedule is not consumed
     * by this local ProgramTable. */
    ProductionResidualImmutableScheduleBinding = 1U << 2,
    /** Fixed-program internal SSA producer/consumer copies are not part of
     * the opcode kernel. */
    ProductionResidualInternalCopyProvenance = 1U << 3,
    /** Every manifest instance is not yet exact-set aggregated. */
    ProductionResidualExactAllInstanceAggregation = 1U << 4,
    /** A normalized parent does not yet execute this family child. */
    ProductionResidualRecursiveConsumption = 1U << 5,
};

struct ProductionPartialFamilyResidualV1 {
    soundness_scenarios::ProductionProofSiteKind kind{};
    uint32_t missing_obligations{0};

    bool operator==(
        const ProductionPartialFamilyResidualV1&) const = default;
};

struct ProductionFamilyProgramMigrationStatusV1 {
    uint32_t families_total{0};
    /** Families whose table is not the one-column structural placeholder.
     * This includes honestly-labelled partial kernels. */
    uint32_t families_non_stub{0};
    /** Non-stub kernels which deliberately do not claim the entire site's
     * semantic relation (fixed-program schedule/provenance, public pins, or
     * all-instance aggregation is still outside the table). */
    uint32_t families_partial{0};
    /** Exact residual count of the old one-column structural placeholder. */
    uint32_t families_structural_stubs{0};
    /** Backward-compatible count of site-complete tables. */
    uint32_t families_real{0};
    uint32_t roles_total{14};
    uint32_t roles_with_real_program{0};
    std::vector<RCStage3RelationRole> real_roles;
    std::vector<uint16_t> real_endpoints;
    /** One exact, ordered entry per honestly-partial family. Empty masks are
     * forbidden: a partial table must state why it is not complete. */
    std::vector<ProductionPartialFamilyResidualV1> partial_residuals;

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
