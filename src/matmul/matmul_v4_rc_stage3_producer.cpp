// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_producer.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <pow.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>

#include <mutex>
#include <optional>

namespace matmul::v4::rc {
namespace {

std::mutex g_proof_source_mutex;
RCStage3ProofSource g_proof_source;

RCStage3ProofSource SnapshotProofSource()
{
    std::lock_guard<std::mutex> lock(g_proof_source_mutex);
    return g_proof_source;
}

void Note(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3-producer:" + message;
}

} // namespace

std::string RCStage3AttachmentSizeReport::ToString() const
{
    return strprintf(
        "stage3-size: payload=%u B (%u words) block_delta=%u B "
        "block_total=%u B weight=%d codec_cap=%u B (%s) "
        "consensus_size_cap=%u B consensus_weight_cap=%d (%s)",
        payload_bytes, payload_words, block_serialized_delta,
        block_serialized_total, block_weight_total, codec_cap_bytes,
        within_codec_cap ? "ok" : "OVER", consensus_serialized_cap,
        consensus_weight_cap, within_consensus_caps ? "ok" : "OVER");
}

RCStage3AttachmentSizeReport MeasureRCStage3Attachment(
    const CBlock& block_without_attachment,
    const std::vector<uint32_t>& packed_payload,
    const Consensus::Params& params)
{
    RCStage3AttachmentSizeReport report;
    report.codec_cap_bytes = kRCStage3MaxProofBytes;
    report.consensus_serialized_cap = params.nMaxBlockSerializedSize;
    report.consensus_weight_cap = static_cast<int64_t>(params.nMaxBlockWeight);

    report.payload_words = packed_payload.size();
    // The envelope's word[1] is the authoritative byte length. Recovering it
    // from the words (rather than from the proof object) keeps this measurement
    // honest about what actually goes on the wire.
    report.payload_bytes =
        packed_payload.size() >= 2 ? static_cast<size_t>(packed_payload[1]) : 0;

    // Measure the delta by serializing both shapes. A formula would drift the
    // moment CBlock::SERIALIZE_METHODS changes; this cannot.
    CBlock with = block_without_attachment;
    with.matrix_c_data = packed_payload;
    const size_t without_size =
        ::GetSerializeSize(TX_WITH_WITNESS(block_without_attachment));
    report.block_serialized_total = ::GetSerializeSize(TX_WITH_WITNESS(with));
    report.block_serialized_delta =
        report.block_serialized_total > without_size
            ? report.block_serialized_total - without_size
            : 0;
    report.block_weight_total = GetBlockWeight(with);

    report.within_codec_cap =
        report.payload_bytes != 0 && report.payload_bytes <= report.codec_cap_bytes;
    report.within_consensus_caps =
        report.block_serialized_total <= report.consensus_serialized_cap &&
        report.block_weight_total <= report.consensus_weight_cap;
    return report;
}

RCStage3ConsensusVerdict RCStage3ConsensusVerdictFor(
    RCStage3AttachmentStatus status)
{
    switch (status) {
    case RCStage3AttachmentStatus::Valid:
        return {RCStage3ConsensusAction::AcceptProceed, ""};

    // Body mutations. matrix_c_data is not covered by CBlockHeader::GetHash(),
    // so another body with the SAME header may carry the valid proof (notably
    // after a BIP152 compact reconstruction, whose wire format has no Stage-3
    // body at all). These must never permanently mark the header invalid.
    case RCStage3AttachmentStatus::Missing:
        return {RCStage3ConsensusAction::RejectMutation,
                "missing-matmul-stage3-proof"};
    case RCStage3AttachmentStatus::Malformed:
    case RCStage3AttachmentStatus::BindingMismatch:
    case RCStage3AttachmentStatus::MathematicalVerificationFailed:
        return {RCStage3ConsensusAction::RejectMutation,
                "bad-matmul-stage3-proof"};

    // Fail-closed. The node could not reach a verdict, so it does not pretend
    // to have one. Notably NotRequired: reaching this mapping at all means the
    // caller already decided a proof WAS required, so a NotRequired verdict is
    // a params inconsistency and must not be read as acceptance.
    case RCStage3AttachmentStatus::AuthorityUnavailable:
    case RCStage3AttachmentStatus::ReadyForMathematicalVerification:
    case RCStage3AttachmentStatus::NotRequired:
        return {RCStage3ConsensusAction::RejectConsensus,
                "matmul-stage3-authority-unavailable"};
    }
    return {RCStage3ConsensusAction::RejectConsensus,
            "matmul-stage3-authority-unavailable"};
}

RCStage3ReservationReport RCStage3PlannedReservation(
    const Consensus::Params& params, int32_t height)
{
    RCStage3ReservationReport out;
    const auto required = RequiredRCStage3Statement(params, height);
    if (!required.has_value()) {
        out.basis = "not_required";
        return out;
    }

    // Both Episode and Composed are planned against the measured Episode
    // envelope. For Composed that is an UNDER-estimate — it adds the coupled
    // relations on top — but no Composed envelope has been assembled, so there
    // is nothing measured to quote. Since the Episode figure alone already
    // exceeds every ceiling, Usable() is false either way and the assembler
    // stops for the right reason; this comment exists so that stops being true
    // silently if the sizes ever come down.
    out.envelope_bytes = kRCStage3MeasuredEpisodeEnvelopeBytes;
    out.basis = *required == RCStage3StatementKind::Composed
                    ? "measured-episode-envelope (LOWER BOUND for Composed)"
                    : "measured-episode-envelope";

    // Identical arithmetic to PackRCStage3ProofWords: 2 envelope words plus
    // ceil(bytes/4).
    out.payload_words = 2 + (out.envelope_bytes + 3) / 4;
    out.block_serialized_delta =
        ::GetSizeOfCompactSize(out.payload_words) +
        out.payload_words * sizeof(uint32_t);

    out.fits_codec_cap = out.envelope_bytes <= kRCStage3MaxProofBytes;
    // A block also has to hold a coinbase and a header, so "fits" here means
    // strictly less than the cap, not equal to it.
    out.fits_block_cap =
        out.block_serialized_delta < params.nMaxBlockSerializedSize &&
        out.block_serialized_delta <
            static_cast<size_t>(params.nMaxBlockWeight);
    return out;
}

const char* RCStage3ProduceStatusName(RCStage3ProduceStatus status)
{
    switch (status) {
    case RCStage3ProduceStatus::NotRequired: return "not_required";
    case RCStage3ProduceStatus::AuthorityDisabled: return "authority_disabled";
    case RCStage3ProduceStatus::NoProver: return "no_prover";
    case RCStage3ProduceStatus::ProverFailed: return "prover_failed";
    case RCStage3ProduceStatus::BindingRejected: return "binding_rejected";
    case RCStage3ProduceStatus::ExceedsSizeBudget: return "exceeds_size_budget";
    case RCStage3ProduceStatus::Attached: return "attached";
    }
    return "unknown";
}

bool RCStage3ProduceIsFatal(RCStage3ProduceStatus status)
{
    return status == RCStage3ProduceStatus::NoProver ||
           status == RCStage3ProduceStatus::ProverFailed ||
           status == RCStage3ProduceStatus::BindingRejected ||
           status == RCStage3ProduceStatus::ExceedsSizeBudget;
}

void SetRCStage3ProofSource(RCStage3ProofSource source)
{
    std::lock_guard<std::mutex> lock(g_proof_source_mutex);
    g_proof_source = std::move(source);
}

bool HasRCStage3ProofSource()
{
    std::lock_guard<std::mutex> lock(g_proof_source_mutex);
    return static_cast<bool>(g_proof_source);
}

RCStage3ProduceStatus AttachRCStage3ProofFromSource(
    CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why,
    RCStage3AttachmentSizeReport* size_out,
    const RCStage3ProducerHints& hints)
{
    if (size_out != nullptr) *size_out = {};

    // Mirror of the consumer's first question (InspectRCStage3ConsensusAttachment):
    // if consensus does not require a Stage-3 statement at this height, the
    // producer must not invent one. Attaching outside the RC family would put a
    // non-empty body on an ENC-DR block, which validation.cpp rejects as
    // "v4-encdr-nonempty-sketch".
    const auto required = RequiredRCStage3Statement(params, height);
    if (!required.has_value()) {
        Note(why, "not_rc_height");
        return RCStage3ProduceStatus::NotRequired;
    }

    const RCStage3ProofSource source = SnapshotProofSource();
    if (!source) {
        Note(why, "no_proof_source_registered");
        return RCStage3ProduceStatus::NoProver;
    }

    RCStage3SuccinctProof proof;
    std::string prover_why;
    // The source gets a CONST block: a prover has no business editing the
    // header it is proving about, and the caller's block stays pristine so a
    // failed attempt is a true no-op.
    if (!source(block, params, height, target, hints, proof, &prover_why)) {
        Note(why, "prover:" + prover_why);
        return RCStage3ProduceStatus::ProverFailed;
    }

    // Bind + encode onto a SCRATCH copy. AttachRCStage3ConsensusProof re-runs
    // ValidateRCStage3ConsensusBinding and PackRCStage3ProofWords and is atomic,
    // so this both (a) refuses to trust the source's own binding claim and
    // (b) gives us the exact encoded bytes to measure before the caller's block
    // is touched at all. Copying a CBlock is cheap: vtx are shared_ptrs.
    CBlock scratch = block;
    std::string attach_why;
    if (!AttachRCStage3ConsensusProof(scratch, proof, params, height, target,
                                      &attach_why)) {
        Note(why, "attach:" + attach_why);
        return RCStage3ProduceStatus::BindingRejected;
    }

    // SIZE IS CHECKED, NOT ASSUMED. See the header for why this is the part
    // that currently blocks in-block carriage at real proof widths: the encoded
    // artifact is computed to be two-plus orders of magnitude over the codec
    // ceiling. When that is true, this is where it surfaces — with numbers.
    const RCStage3AttachmentSizeReport report = MeasureRCStage3Attachment(
        block, scratch.matrix_c_data, params);
    if (size_out != nullptr) *size_out = report;
    if (!report.Fits()) {
        Note(why, "size_budget:" + report.ToString());
        return RCStage3ProduceStatus::ExceedsSizeBudget;
    }

    block.matrix_c_data = std::move(scratch.matrix_c_data);
    Note(why, "attached:" + report.ToString());
    return RCStage3ProduceStatus::Attached;
}

RCStage3ProduceStatus ProduceAndAttachRCStage3ConsensusProof(
    CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    std::string* why,
    RCStage3AttachmentSizeReport* size_out,
    const RCStage3ProducerHints& hints)
{
    if (size_out != nullptr) *size_out = {};

    // Compile-time fail-closed, symmetric with VerifyRCStage3ConsensusAttachment.
    // While the gate is false the entire body below is discarded, so no live
    // producer path can differ by a single byte from the pre-Stage-3 build.
    if constexpr (!kRCStage3SuccinctAuthorityReady) {
        Note(why, "authority_unavailable");
        return RCStage3ProduceStatus::AuthorityDisabled;
    } else {
        if (!params.IsMatMulRCFamilyActive(height)) {
            Note(why, "not_rc_height");
            return RCStage3ProduceStatus::NotRequired;
        }
        // Same derivation the validator uses (validation.cpp ContextualCheckBlock
        // and ValidateRCStage3ConsensusBinding's `target` contract). A
        // noncanonical nBits is the validator's "bad-matmul-stage3-target"; a
        // producer that reached here with one has a broken template.
        const auto target = DeriveTarget(block.nBits, params.powLimit);
        if (!target.has_value()) {
            Note(why, "noncanonical_nbits");
            return RCStage3ProduceStatus::ProverFailed;
        }
        return AttachRCStage3ProofFromSource(block, params, height,
                                             ArithToUint256(*target), why,
                                             size_out, hints);
    }
}

} // namespace matmul::v4::rc
