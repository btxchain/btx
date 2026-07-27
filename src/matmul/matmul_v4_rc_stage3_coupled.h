// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_H

#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ============================================================================
// Stage-3 coupled relation receipts.
//
// This file defines the proof-only boundary for all eight registered coupled
// relations. A receipt commits one relation's public claim, exact execution
// count, input/output root, trace root, and opaque proof-engine output. The
// verifier first checks the complete relation graph and only then dispatches
// every receipt to a proof engine.
//
// IMPORTANT: a well-formed receipt is not a proof. The repository does not yet
// contain proof-only engines for bank expansion/selection, the uint64 mix,
// committed Extract/range traces, or barrier SHA closure. Consequently the
// engine dispatch is deliberately fail-closed and
// kRCStage3CoupledRelationEnginesReady remains false. Existing native-grounded
// VerifyWinnerCoupledV7 is not called from this module.
// ============================================================================

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3CoupledReceiptMagic = 0x31524343U; // "CCR1"
inline constexpr uint16_t kRCStage3CoupledReceiptVersion = 1;
/** Per-relation opaque engine payload bound. Sized to admit a small
 * BankDequantPagesV1 witness (one lobe_width=32 Split-RAP page) or a toy
 * GemmDotTilesV1 schedule (4×1 tiles of Fri3 AirQuotient) while still
 * rejecting unbounded forgeries. Production shapes must aggregate under
 * recursion before this bound can carry every scheduled instance. */
inline constexpr size_t kRCStage3CoupledMaxEngineReceiptBytes = 16U * 1024U * 1024U;

/** Consensus proof-engine ABI. The identifier reserves a stable encoding; it
 * does not imply that the engine is implemented or ready. */
enum class RCStage3CoupledProofEngine : uint16_t {
    ProofOnlyV1 = 1,
    /**
     * CoupledBank ONLY. A real, executable Split-RAP AirQuotient proof of the
     * six-column endpoint-28 dequant relation
     * (BuildRCStage3CoupledBankDequantProgramTableCanonical /
     * VerifyRCStage3CoupledBankDequantProof) for every one of the receipt's
     * declared bank pages. See BuildRCStage3CoupledBankDequantEngineReceipt /
     * VerifyRCStage3CoupledBankDequantEngineReceipt below for the exact
     * honest scope: it proves mu*(1+e0)*(1+3e1)=output for every declared
     * page and binds `trace_root` to the ordered page commitments, but does
     * NOT prove the mantissa/scale witness is the honest SHA-XOF expansion
     * of the bank seed (BankSeedXof gap) or that the proved pages are the
     * ones the barrier/lobe schedule actually selects (BankPageInclusion
     * gap) -- see RCStage3CoupledAirGapCode. It therefore does not, by
     * itself, retire CoupledBank's Gap() or move
     * kRCStage3CoupledRelationEnginesReady.
     */
    BankDequantPagesV1 = 2,
    /**
     * CoupledGemm ONLY. A real Fri3 AirQuotient proof of every scheduled
     * GEMM dot-product tile (BuildRCStage3CoupledGemmDotConstraintSystem /
     * VerifyRCStage3CoupledGemmDotProof), reused from
     * ProveRCStage3CoupledGemmProduct. Proves the nine-column accumulate
     * relation for each shape-derived schedule entry and binds `trace_root`
     * to the ordered pin commitments, but does NOT close bank-page or prior-
     * state producer provenance (see RCStage3CoupledGemmProductAudit) and
     * therefore does not, by itself, move
     * kRCStage3CoupledRelationEnginesReady.
     */
    GemmDotTilesV1 = 3,
};

/** Public coupled shape/options copied into every relation receipt. Test-only
 * skip hooks and execution-policy modes are intentionally absent. */
struct RCStage3CoupledShape {
    uint32_t barriers{0};
    uint32_t lobes{0};
    uint32_t lobe_width{0};
    uint32_t bank_pages{0};
    uint32_t rows_per_lobe{0};
    uint32_t pages_per_barrier_lobe{0};

    uint32_t transcript_version{0};
    bool full_bank_schedule{false};
    bool material_exchange{false};
    uint32_t exchange_rows{0};
    uint32_t exchange_rounds{0};
    bool force_signed_mix{false};

    bool operator==(const RCStage3CoupledShape&) const = default;
};

/**
 * Canonical typed payload stored in the corresponding outer Stage-3 section.
 *
 * The root graph is:
 *   header commitment -> bank -> GEMM -> exchange -> permutation -> mix
 *   -> Extract -> barrier roots -> coupled digest.
 *
 * `aggregate_root` commits all fields except itself. The outer envelope's
 * per-role commitment in turn commits the complete serialized receipt.
 */
struct RCStage3CoupledRelationReceipt {
    uint32_t magic{kRCStage3CoupledReceiptMagic};
    uint16_t version{kRCStage3CoupledReceiptVersion};
    RCStage3RelationRole role{RCStage3RelationRole::CoupledBank};
    RCStage3CoupledProofEngine engine{RCStage3CoupledProofEngine::ProofOnlyV1};
    RCStage3CoupledShape shape{};

    /** Hash of the pre-proof Stage-3 public inputs, under a coupled-specific
     * domain. transcript_commitment is excluded to avoid a proof hash cycle. */
    uint256 statement_commitment{};
    /** Exact outer public params commitment (episode+coupled when composed). */
    uint256 params_commitment{};
    /** Commitment to the coupled shape/options above. */
    uint256 coupled_shape_commitment{};
    uint256 sigma{};

    uint256 input_root{};
    uint256 output_root{};
    uint256 trace_root{};
    uint256 aggregate_root{};

    /** Relation-specific exact counts returned by
     * ExpectedRCStage3CoupledRelationCounts. */
    uint64_t primary_count{0};
    uint64_t secondary_count{0};

    /** Canonical proof-engine object. Never interpreted as a trusted flag. */
    std::vector<unsigned char> engine_receipt;

    bool operator==(const RCStage3CoupledRelationReceipt&) const = default;
};

struct RCStage3CoupledRelationCounts {
    uint64_t primary{0};
    uint64_t secondary{0};

    bool operator==(const RCStage3CoupledRelationCounts&) const = default;
};

[[nodiscard]] RCStage3CoupledShape
MakeRCStage3CoupledShape(const RCCoupParams& params, const RCCoupOptions& options);

[[nodiscard]] uint256
CommitRCStage3CoupledStatement(const RCStage3PublicInputs& public_inputs);
[[nodiscard]] uint256
CommitRCStage3CoupledShape(const RCStage3CoupledShape& shape);
[[nodiscard]] uint256
CommitRCStage3CoupledRelationAggregate(const RCStage3CoupledRelationReceipt& receipt);
[[nodiscard]] uint256
CommitRCStage3CoupledSection(const std::vector<unsigned char>& section);

/** Exact schedule/trace coverage required for each of the eight roles. */
[[nodiscard]] std::optional<RCStage3CoupledRelationCounts>
ExpectedRCStage3CoupledRelationCounts(RCStage3RelationRole role,
                                      const RCStage3CoupledShape& shape,
                                      std::string* why = nullptr);

/** Canonical bounded relation-receipt codec. */
[[nodiscard]] bool
SerializeRCStage3CoupledRelationReceipt(const RCStage3CoupledRelationReceipt& receipt,
                                        std::vector<unsigned char>& out,
                                        std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3CoupledRelationReceipt>
DeserializeRCStage3CoupledRelationReceipt(const std::vector<unsigned char>& bytes,
                                          std::string* why = nullptr);

/**
 * Verify all eight coupled sections of a Coupled or Composed envelope.
 *
 * This rejects Episode-only statements, validates all receipts before engine
 * dispatch, and accepts only if every proof-only engine verifies. It never
 * performs native coupled replay or native witness reconstruction.
 */
[[nodiscard]] bool
VerifyRCStage3CoupledRelations(const RCStage3SuccinctProof& proof,
                               std::string* why = nullptr);

/** Hard readiness predicate for consensus composition. */
[[nodiscard]] bool RCStage3CoupledRelationEnginesReady(std::string* why = nullptr);
inline constexpr bool kRCStage3CoupledRelationEnginesReady = false;

// ============================================================================
// CoupledBank real proof-only engine (BankDequantPagesV1).
//
// This is the first non-stub RCStage3CoupledProofEngine dispatch: a genuine
// Split-RAP AirQuotient proof/verify round trip over the existing production
// six-column dequant relation, reused byte-for-byte from
// BuildRCStage3CoupledBankDequantProgramTableCanonical /
// VerifyRCStage3CoupledBankDequantProof (matmul_v4_rc_stage3_coupled_bank_product.*),
// the same relation already exercised by ProveRCStage3CoupledBankProduct.
//
// Honest scope: for every declared page it proves
//   output = mantissa * (1+e0) * (1+3*e1)   with e0,e1 booleans, e=e0+2*e1,
// over `shape.lobe_width * shape.lobe_width` cells, and binds the proof to
// `statement_commitment` / `coupled_shape_commitment` / `sigma` so a proof
// cannot be replayed across statements or shapes. It returns an aggregate
// `trace_root` (a domain-separated hash of the ordered per-page R0 row-group
// roots); the caller (VerifyProofOnlyEngine) requires this to equal the
// receipt's own `trace_root`, so a receipt cannot claim a trace this engine
// did not verify.
//
// NOT covered (see RCStage3CoupledAirGapCode / RCStage3CoupledBankProductAudit):
//   - BankSeedXof:       the mantissa/scale witness is not tied to the honest
//                        SHA-XOF expansion of the bank root seed.
//   - BankPageInclusion: the proved pages are not tied to the barrier/lobe
//                        selection schedule (`secondary_count` scheduled
//                        instances) -- only their raw byte content.
// Consequently this engine is real cryptography for a real sub-relation, but
// does not by itself retire CoupledBank's Gap(), close
// RCStage3CoupledAirRegistryReady for CoupledBank, or move
// kRCStage3CoupledRelationEnginesReady.
// ============================================================================

/** One page's honest dequant witness: `mantissa`/`scale` must both have
 * exactly `shape.lobe_width * shape.lobe_width` entries, one per output
 * cell, with `scale` values in [0,3]. */
struct RCStage3CoupledBankDequantPageWitness {
    std::vector<int8_t> mantissa;
    std::vector<uint8_t> scale;

    bool operator==(const RCStage3CoupledBankDequantPageWitness&) const = default;
};

/** Bounded prover helper. Builds one real Split-RAP AirQuotient proof per
 * page and serializes them into an opaque `engine_receipt` payload suitable
 * for RCStage3CoupledRelationReceipt::engine_receipt when
 * `engine == BankDequantPagesV1`. `pages.size()` must equal `shape.bank_pages`
 * and pages must be supplied in page-index order. */
[[nodiscard]] bool BuildRCStage3CoupledBankDequantEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<RCStage3CoupledBankDequantPageWitness>& pages,
    std::vector<unsigned char>& out_engine_receipt,
    uint256& out_trace_root,
    std::string* why = nullptr);

/** Verify every page proof in `engine_receipt` and return the aggregate
 * trace root it commits to. Never performs native bank derivation. */
[[nodiscard]] bool VerifyRCStage3CoupledBankDequantEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<unsigned char>& engine_receipt,
    uint256& out_trace_root,
    std::string* why = nullptr);

// ============================================================================
// CoupledGemm real proof-only engine (GemmDotTilesV1).
//
// Second non-stub RCStage3CoupledProofEngine dispatch: Fri3 AirQuotient
// prove/verify over every shape-derived GEMM schedule tile, reused from
// BuildRCStage3CoupledGemmDotConstraintSystem /
// VerifyRCStage3CoupledGemmDotProof (matmul_v4_rc_stage3_coupled_gemm_product.*).
//
// Honest scope: for every scheduled (barrier, lobe, page_slot) instance and
// every output tile, proves the nine-column accumulate relation
//   product = A*B; after = before + product; start ⇒ before=0; end ⇒ Y=after
// over lobe_width*MX contraction rows, binds statement/shape/schedule/sigma,
// and returns an aggregate `trace_root` over ordered pin commitments.
//
// NOT covered (see RCStage3CoupledGemmProductAudit):
//   - bank_page_producer_provenance / prior_state_producer_provenance
//   - production streaming / recursive consumption / TransitivelyComplete
// Consequently this engine is real cryptography for the local GEMM sub-
// relation but does not by itself flip kRCStage3CoupledRelationEnginesReady.
// ============================================================================

/** Prover-supplied flat openings for one scheduled GEMM instance. */
struct RCStage3CoupledGemmDotOpening {
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    std::vector<int64_t> output_y;

    bool operator==(const RCStage3CoupledGemmDotOpening&) const = default;
};

/** Bounded prover helper. Builds one Fri3 AirQuotient proof per scheduled
 * GEMM tile and serializes them into an opaque `engine_receipt` payload
 * suitable for RCStage3CoupledRelationReceipt::engine_receipt when
 * `engine == GemmDotTilesV1`. `openings.size()` must equal the shape-derived
 * GEMM schedule length. */
[[nodiscard]] bool BuildRCStage3CoupledGemmDotEngineReceipt(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmDotOpening>& openings,
    std::vector<unsigned char>& out_engine_receipt,
    uint256& out_trace_root,
    std::string* why = nullptr);

/** Verify every tile proof in `engine_receipt` and return the aggregate
 * trace root it commits to. Never performs native GEMM. */
[[nodiscard]] bool VerifyRCStage3CoupledGemmDotEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<unsigned char>& engine_receipt,
    uint256& out_trace_root,
    std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_H
