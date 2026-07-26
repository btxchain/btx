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
inline constexpr size_t kRCStage3CoupledMaxEngineReceiptBytes = 2U * 1024U * 1024U;

/** Consensus proof-engine ABI. The identifier reserves a stable encoding; it
 * does not imply that the engine is implemented or ready. */
enum class RCStage3CoupledProofEngine : uint16_t {
    ProofOnlyV1 = 1,
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

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_H
