// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCER_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <string>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

/**
 * PR-89 item 5 — PRODUCER side of the mandatory succinct-proof authority.
 *
 * matmul_v4_rc_stage3_consensus.{h,cpp} already owns the *consumer* side: the
 * canonical matrix_c_data wire format (PackRCStage3ProofWords), the
 * public-input binding check (ValidateRCStage3ConsensusBinding), and the
 * validation entry point (VerifyRCStage3ConsensusAttachment, reached from
 * validation.cpp ContextualCheckBlock). What did not exist was the mirror
 * image: nothing in any miner path ever CALLED AttachRCStage3ConsensusProof,
 * so an RC-family winner could not carry the proof the validator will demand.
 *
 * This file is that seam, and nothing more. It deliberately does NOT contain a
 * prover: assembling RCStage3SuccinctProof::sections from real role AIR
 * proofs is owned by matmul_v4_rc_stage3_role_sections.{h,cpp}
 * (ProveRCStage3RoleAirSection + AssembleRCStage3SuccinctProofSections). The
 * Legacy section-envelope tests consume that work through the
 * RCStage3ProofSource indirection. The production miner does not: it owns a
 * separate normalized-receipt provider lifecycle declared below, so a test
 * callback can never silently become consensus authority.
 *
 * FAIL-CLOSED CONTRACT. Production is gated on exactly the same compile-time
 * constant as verification (kRCStage3SuccinctAuthorityReady, currently false).
 * That symmetry is load-bearing, not decorative: while the gate is false,
 * validation.cpp REJECTS a non-empty matrix_c_data at DIGEST_RECOMPUTE heights
 * ("v4-encdr-nonempty-sketch"). A producer that attached a proof early would
 * mine blocks that its own node rejects. So ProduceAndAttachRCStage3-
 * ConsensusProof returns AuthorityDisabled and leaves the block byte-identical
 * until the gate is deliberately closed.
 *
 * ---------------------------------------------------------------------------
 * SIZE IS AN OPEN PROBLEM, AND THIS FILE REFUSES TO HIDE IT.
 * ---------------------------------------------------------------------------
 * In-block carriage of the Stage-3 proof is bounded by three DIFFERENT ceilings
 * that are not currently reconciled:
 *
 *   1. kRCStage3MaxProofBytes = 16 MiB — the codec / untrusted-parse ceiling in
 *      matmul_v4_rc_stage3.h. Enforced by SerializeRCStage3Proof on write and
 *      by UnpackRCStage3ProofWords/DeserializeRCStage3Proof on read, before any
 *      allocation, in the same spirit as recursive.cpp's MAX_VECTOR_ITEMS =
 *      kRCFri3AlgBatchMaxColumns.
 *   2. Consensus::Params::nMaxBlockSerializedSize / nMaxBlockWeight = 24 MB.
 *      WITNESS_SCALE_FACTOR == 1 on BTX, so every proof byte is a full weight
 *      unit and competes 1:1 with transactions.
 *   3. The actual size of a real-width recursive proof, which is the problem.
 *
 * THE CURRENT ENVELOPE DOES NOT FIT, and that is MEASURED, not projected.
 * The section-assembly lane assembled a real consensus envelope from six real
 * role-section proofs and got 35,363,636 bytes against the 16,777,216-byte cap
 * — 2.1x over — failing closed as "stage3:relation_proofs_oversize". Per
 * section: builder 4.81 MB, gemm 11.08 MB, extract 10.97 MB, wiring 7.39 MB,
 * tiletree 0.55 MB, digest 0.55 MB.
 *
 * The driver is structural, not a tuning problem. The row-wise Alg-FRI backend
 * opens a FULL TRACE ROW per query (~192 queries x ~1100 columns x 24 B ~= 5 MB
 * per opening set), so trace width W is roughly 99% of the payload and query
 * count Q only ~5.9%. Reducing Q is therefore the wrong lever, and raising the
 * cap would only move the failure. The fix has to be one of: a non-row-wise
 * opening layout, proof compression, or the recursion collapsing the six
 * sections into one. Separately, a codec lane MEASURED the NARROW parent shape
 * (W=546) at 13,227,936 B = 0.827x the wire — so the narrow path does fit, with
 * ~17% headroom, at the shipped Q=136. Narrow is the shape to design for; the
 * full-wide path (computed at 3.30-6.12 GiB, 211x-392x over) is dead.
 *
 * Caveat carried forward: part of that narrow figure still rests on
 * EstimateAlgAirProofBytes (matmul_v4_rc_air_recurse.cpp:2995-3018), which is
 * single-lane only — AirQuotientProof has no whole-proof serializer, only its
 * `batch` member does, and `next_openings` / `trace_commit` are size-estimated
 * on a path with no dual-lane estimator at all.
 *
 * CONSEQUENCE FOR THIS FORMAT. The old 35,363,636-byte flat six-section
 * experiment is useful diagnostic evidence, but it is not a production proof
 * shape and must not be used as the block assembler's reservation. The
 * production reservation is instead the codec-enforced maximum: every proof
 * SerializeRCStage3Proof can accept is at most kRCStage3MaxProofBytes, and its
 * two-word envelope, word padding, and CompactSize prefix have exact bounded
 * sizes. This gives the assembler a true upper bound before a proof exists,
 * while MeasureRCStage3Attachment still reports the exact cost of the proof
 * actually produced.
 *
 * The recursion shape is expected to change. Nothing in this seam depends on
 * the proof's internal structure — it moves an opaque, length-prefixed byte
 * string — so a shape change costs a version bump in matmul_v4_rc_stage3.h and
 * nothing here.
 */

enum class RCStage3ProduceStatus : uint8_t {
    /** Height is outside the RC family: no Stage-3 attachment is required and
     *  the block was left untouched. Not an error. */
    NotRequired = 0,
    /** kRCStage3SuccinctAuthorityReady is false. The block was left untouched.
     *  Not an error — this is the current, expected state on every network. */
    AuthorityDisabled = 1,
    /** Authority is on and the height requires a proof, but the production
     *  normalized-receipt provider was not initialized. FATAL for an RC-family
     *  winner: the block would be rejected as missing-matmul-stage3-proof. */
    NoProver = 2,
    /** The registered prover declined or failed. FATAL for an RC-family winner. */
    ProverFailed = 3,
    /** The prover returned a proof whose public inputs do not bind this exact
     *  block/height/params/target, or which does not serialize canonically.
     *  FATAL, and a prover bug: AttachRCStage3ConsensusProof is atomic, so the
     *  block is unchanged. */
    BindingRejected = 4,
    /** The proof bound this block and encoded canonically, but the encoded
     *  payload does not fit: either over the 16 MiB codec ceiling, or over the
     *  block's own remaining serialized-size / weight budget. FATAL, and the
     *  expected outcome at real proof widths today. The exact numbers are in
     *  the RCStage3AttachmentSizeReport out-param. */
    ExceedsSizeBudget = 5,
    /** block.matrix_c_data now carries the canonical Stage-3 payload. */
    Attached = 6,
};

/**
 * Exact, surfaced size accounting for one in-block Stage-3 attachment. Every
 * field is COMPUTED from the actual encoded bytes — nothing here is an estimate
 * or a rule of thumb. This is the checkable artifact the size question should be
 * argued over.
 */
struct RCStage3AttachmentSizeReport {
    /** Serialized proof bytes, before the uint32 word packing. */
    size_t payload_bytes{0};
    /** uint32 words actually written to CBlock::matrix_c_data (2 envelope words
     *  + ceil(payload_bytes/4)). */
    size_t payload_words{0};
    /** Exact bytes the attachment adds to the serialized block, including the
     *  CompactSize length prefix. Measured by serializing both blocks, not
     *  derived from a formula, so it cannot drift from CBlock's wire format. */
    size_t block_serialized_delta{0};
    /** Full serialized size / weight of the block WITH the attachment. */
    size_t block_serialized_total{0};
    int64_t block_weight_total{0};

    /** The three ceilings, carried alongside the measurements so a report is
     *  self-contained in a log line or a test failure. */
    size_t codec_cap_bytes{0};
    size_t consensus_serialized_cap{0};
    int64_t consensus_weight_cap{0};

    bool within_codec_cap{false};
    bool within_consensus_caps{false};

    [[nodiscard]] bool Fits() const
    {
        return within_codec_cap && within_consensus_caps;
    }
    /** One-line, log-ready rendering of every number above. */
    [[nodiscard]] std::string ToString() const;
};

/**
 * Measure what attaching `packed_payload` to `block_without_attachment` would
 * cost, against all three ceilings. Pure: touches nothing, allocates one
 * scratch serialization. Safe to call at any time, gate or no gate — this is
 * deliberately usable for capacity planning before a prover exists.
 */
[[nodiscard]] RCStage3AttachmentSizeReport MeasureRCStage3Attachment(
    const CBlock& block_without_attachment,
    const std::vector<uint32_t>& packed_payload,
    const Consensus::Params& params);

/**
 * What the BLOCK ASSEMBLER must subtract from its size/weight budget before it
 * selects transactions, so the attachment step cannot push the miner's own
 * block over the consensus limits.
 *
 * This has to be a WORST-CASE bound rather than a per-block measurement, because
 * the assembler runs before the proof exists. It is derived from
 * kRCStage3MaxProofBytes using the exact same two-word envelope and word padding
 * as PackRCStage3ProofWords, plus the exact CompactSize framing used by
 * CBlock::matrix_c_data. SerializeRCStage3Proof enforces the byte ceiling, so
 * every accepted attachment is bounded by this reservation.
 */
struct RCStage3ReservationReport {
    /** Maximum serialized proof bytes planned for. */
    size_t envelope_bytes{0};
    /** uint32 words those bytes occupy in matrix_c_data. */
    size_t payload_words{0};
    /** Exact serialized footprint of the reserved vector, CompactSize prefix
     *  included. This is a conservative upper bound on the attachment delta:
     *  an empty matrix_c_data already occupies its one-byte zero prefix. */
    size_t block_serialized_delta{0};
    /** Whether the codec maximum is encodable / carriable on this network. */
    bool fits_codec_cap{false};
    bool fits_block_cap{false};
    /** Provenance of envelope_bytes, so a log line is self-explaining. */
    const char* basis{"none"};

    [[nodiscard]] bool Usable() const { return fits_codec_cap && fits_block_cap; }
};

/**
 * Reservation for the statement consensus requires at `height`, or a report with
 * envelope_bytes == 0 and basis "not_required" outside the RC family.
 *
 * A report with Usable() == false means the network's block caps cannot carry
 * even the codec-bounded proof reservation, and the assembler must surface that
 * configuration error rather than mine a block it could never complete.
 */
[[nodiscard]] RCStage3ReservationReport RCStage3PlannedReservation(
    const Consensus::Params& params, int32_t height);

[[nodiscard]] const char* RCStage3ProduceStatusName(RCStage3ProduceStatus status);

/**
 * The consensus verdict validation.cpp reaches for a given attachment status.
 *
 * Extracted from ContextualCheckBlock so the mapping is TESTABLE. The call site
 * there sits inside an `if constexpr (kRCStage3SuccinctAuthorityReady)` and is
 * therefore compiled out today; without this function there is no way to assert
 * "a missing proof is rejected as a mutation" without flipping the gate, which
 * must not be done. validation.cpp translates the action into the concrete
 * BlockValidationResult; this header deliberately does not depend on it.
 */
enum class RCStage3ConsensusAction : uint8_t {
    /** Proof accepted; continue with the ordinary contextual body checks. */
    AcceptProceed = 0,
    /** BLOCK_MUTATED. The header hash is untouched and a correct body may still
     *  exist, so this must never be a permanent mark against the header. */
    RejectMutation = 1,
    /** BLOCK_CONSENSUS. Fail-closed: the node cannot decide, so it does not. */
    RejectConsensus = 2,
};

struct RCStage3ConsensusVerdict {
    RCStage3ConsensusAction action{RCStage3ConsensusAction::RejectConsensus};
    /** Stable reject reason string, or "" for AcceptProceed. */
    const char* reject_reason{""};
};

/** Total over RCStage3AttachmentStatus. Anything unexpected fails closed to
 *  RejectConsensus rather than accepting. */
[[nodiscard]] RCStage3ConsensusVerdict
RCStage3ConsensusVerdictFor(RCStage3AttachmentStatus status);

/** True for the statuses that mean "this RC-family winner MUST NOT be
 *  submitted": the validator would classify the body as a mutation. NotRequired
 *  and AuthorityDisabled are both non-fatal no-ops. */
[[nodiscard]] bool RCStage3ProduceIsFatal(RCStage3ProduceStatus status);

/**
 * Optional solver inputs shared by the production normalized provider and the
 * legacy section-envelope test seam.
 */
struct RCStage3ProducerHints {
    /** The episode transcript the solver already computed for THIS header, or
     *  null. Cost optimization only. */
    const std::vector<RCRoundTranscript>* episode_rounds{nullptr};
};

/**
 * Production-owned normalized receipt provider lifecycle.
 *
 * InitializeRCStage3ProductionProofProvider is called once from node startup.
 * It does not install a mutable callback. The implementation is process-owned
 * and must eventually build the exact byte string produced by
 * normalized_authority::SerializeNormalizedAuthorityReceiptV3. Consensus must
 * parse those same bytes, independently rebuild RebuiltVerifierInputsV3 and
 * the parent CS, call ValidateAndDecodeVerifierInputsV3, and execute
 * AirQuotientVerifyRowsSplitRapSafeFixedV3.
 *
 * The typed canonical-parent consumer now exists and proves, serializes,
 * decodes and executes the supplied parent before emitting bytes. The
 * remaining producer dependency is the block-to-complete-parent assembler:
 * it must materialize the fourteen-role CS/witness and verifier-rebuilt public
 * inventory through normalized_production_parent_builder's typed, callback-
 * free input. Until that assembler is complete the provider reports BuildFailed
 * with the precise parent-build status and emits no bytes.
 */
void InitializeRCStage3ProductionProofProvider();
[[nodiscard]] bool HasRCStage3ProductionProofProvider();

enum class RCStage3NormalizedProviderStatus : uint8_t {
    NotInitialized = 0,
    NotRequired = 1,
    /** Retained as a stable diagnostic value for older callers. The production
     * provider now reaches the typed canonical-parent builder and reports its
     * concrete failure as BuildFailed instead. */
    BuilderUnavailable = 2,
    BuildFailed = 3,
    Produced = 4,
};

[[nodiscard]] const char* RCStage3NormalizedProviderStatusName(
    RCStage3NormalizedProviderStatus status);

/**
 * Build the strict canonical NAV3 receipt bytes for a finalized winner.
 *
 * On Produced, `receipt_bytes` must be exactly the output of
 * SerializeNormalizedAuthorityReceiptV3 and must round-trip through the strict
 * decoder. On every other status it is empty. This split makes the outstanding
 * boundary explicit: producing a canonical receipt is separate from attaching
 * it, because attachment is forbidden until consensus consumes and executes
 * that same normalized proof.
 */
[[nodiscard]] RCStage3NormalizedProviderStatus
BuildRCStage3NormalizedAuthorityReceipt(
    const CBlock& solved_block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::vector<unsigned char>& receipt_bytes,
    std::string* why = nullptr,
    const RCStage3ProducerHints& hints = {});

/**
 * MECHANISM layer for the production provider, intentionally callable in tests
 * while authority is disabled. Atomic: until both the normalized builder and
 * the matching consensus consumer exist, it returns ProverFailed and leaves
 * the block byte-identical.
 */
[[nodiscard]] RCStage3ProduceStatus
AttachRCStage3ProofFromProductionProvider(
    CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why = nullptr,
    RCStage3AttachmentSizeReport* size_out = nullptr,
    const RCStage3ProducerHints& hints = {});

/**
 * LEGACY TEST/R&D prover seam. An implementation must return a COMPLETE proof
 * object — every
 * public input filled (see BuildRCStage3StatementForHeader) and every required
 * relation section assembled (see AssembleRCStage3SuccinctProofSections). It
 * must not mutate the block.
 *
 * `target` is the canonical integer from DeriveTarget(header.nBits,
 * params.powLimit), passed in so the prover and the binding check cannot
 * disagree about how the target was derived.
 *
 * The producer re-checks the returned proof with ValidateRCStage3ConsensusBinding
 * before it touches the block, so a buggy source cannot corrupt a winner — it
 * can only fail to produce one.
 *
 * This callback exists so the old REP3/OAS3 codecs and binding layer remain
 * testable. It is NOT consulted by ProduceAndAttachRCStage3ConsensusProof and
 * must not be registered from node initialization.
 *
 * Assumptions this seam makes, all checked downstream rather than trusted:
 *   - the source produces a COMPLETE object; a partially filled proof is
 *     rejected by ValidateRCStage3ProofStructure inside the binding check;
 *   - the source does not need the solvers 8*m^2 product sketch. The miner
 *     path clears block.matrix_c_data before calling, so the sketch is NOT
 *     available through the block. If a prover needs it, it must become an
 *     explicit argument here — see the note in pow.cpp
 *     FinalizeMatMulSolvedBlockForProduction;
 *   - `target` is authoritative; the source must not re-derive it.
 */
using RCStage3ProofSource =
    std::function<bool(const CBlock& solved_block,
                       const Consensus::Params& params,
                       int32_t height,
                       const uint256& target,
                       const RCStage3ProducerHints& hints,
                       RCStage3SuccinctProof& out,
                       std::string* why)>;

/** Install (or, with a default-constructed source, clear) the legacy
 *  process-wide test/R&D prover. Never called by node init. Thread-safe. */
void SetRCStage3ProofSource(RCStage3ProofSource source);
[[nodiscard]] bool HasRCStage3ProofSource();

/**
 * MECHANISM layer — NOT gated on kRCStage3SuccinctAuthorityReady.
 *
 * Runs the registered legacy test/R&D prover and, if its proof binds, packs it into
 * block.matrix_c_data. Exists as a separate entry point so the producer wiring
 * is exercisable by tests while the authority gate is (correctly) still off;
 * no consensus or miner path calls it directly. Still refuses at non-RC
 * heights, and is atomic: on any failure the block is unchanged.
 */
[[nodiscard]] RCStage3ProduceStatus AttachRCStage3ProofFromSource(
    CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why = nullptr,
    RCStage3AttachmentSizeReport* size_out = nullptr,
    const RCStage3ProducerHints& hints = {});

/**
 * CONSENSUS/MINER entry point — gated.
 *
 * Returns AuthorityDisabled (block untouched) while
 * kRCStage3SuccinctAuthorityReady is false. Otherwise derives the target from
 * the block's own nBits and delegates exclusively to
 * AttachRCStage3ProofFromProductionProvider. Test callbacks are never consulted.
 *
 * Call ONLY after the solver has finalized the header: the proof binds
 * header.matmul_digest, nNonce64 and the seeds, so any later header edit
 * invalidates the attachment.
 */
[[nodiscard]] RCStage3ProduceStatus ProduceAndAttachRCStage3ConsensusProof(
    CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    std::string* why = nullptr,
    RCStage3AttachmentSizeReport* size_out = nullptr,
    const RCStage3ProducerHints& hints = {});

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCER_H
