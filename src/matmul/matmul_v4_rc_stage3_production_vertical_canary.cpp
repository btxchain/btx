// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_production_vertical_canary.h>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc_stage3_canonical_parent_production_verifier.h>
#include <matmul/matmul_v4_rc_stage3_coupled_winner_capture.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>
#include <matmul/matmul_v4_rc_stage3_normalized_block_transport.h>
#include <matmul/matmul_v4_rc_stage3_normalized_consensus_binding.h>
#include <primitives/block.h>
#include <streams.h>

#include <utility>
#include <vector>

namespace matmul::v4::rc::production_vertical_canary {
namespace {

namespace canonical =
    canonical_parent_production_verifier;
namespace consensus_binding =
    normalized_consensus_binding;
namespace nav3 = normalized_authority;
namespace transport = normalized_block_transport;

bool Stop(
    ReportV1& out,
    FailureV1 failure,
    const std::string& detail,
    std::string* why)
{
    out.failure = failure;
    out.note =
        std::string{"stage3:production_vertical_canary_v1:"} +
        FailureNameV1(failure) + ":" + detail;
    if (why != nullptr) *why = out.note;
    return false;
}

} // namespace

const char* StageNameV1(StageV1 stage)
{
    switch (stage) {
    case StageV1::None: return "none";
    case StageV1::RequestChecked: return "request_checked";
    case StageV1::WinnerCapturesChecked:
        return "winner_captures_checked";
    case StageV1::HeaderStatementRebuilt:
        return "header_statement_rebuilt";
    case StageV1::ReceiptAttached: return "receipt_attached";
    case StageV1::BlockRoundTripped:
        return "block_round_tripped";
    case StageV1::StrictReceiptDecoded:
        return "strict_receipt_decoded";
    case StageV1::CanonicalParentVerified:
        return "canonical_parent_verified";
    case StageV1::ConsensusVerified:
        return "consensus_verified";
    }
    return "unknown";
}

const char* FailureNameV1(FailureV1 failure)
{
    switch (failure) {
    case FailureV1::None: return "none";
    case FailureV1::InvalidRequest: return "invalid_request";
    case FailureV1::NotRequired: return "not_required";
    case FailureV1::UnsupportedStatement:
        return "unsupported_statement";
    case FailureV1::ProviderNotInitialized:
        return "provider_not_initialized";
    case FailureV1::EpisodeCaptureMissing:
        return "episode_capture_missing";
    case FailureV1::EpisodeCaptureIncomplete:
        return "episode_capture_incomplete";
    case FailureV1::CoupledCaptureMissing:
        return "coupled_capture_missing";
    case FailureV1::CoupledCaptureIncomplete:
        return "coupled_capture_incomplete";
    case FailureV1::CoupledCaptureBinding:
        return "coupled_capture_binding";
    case FailureV1::HeaderStatementBinding:
        return "header_statement_binding";
    case FailureV1::ReceiptBuildOrAttach:
        return "receipt_build_or_attach";
    case FailureV1::BlockRoundTrip:
        return "block_round_trip";
    case FailureV1::StrictReceiptDecode:
        return "strict_receipt_decode";
    case FailureV1::CanonicalParent:
        return "canonical_parent";
    case FailureV1::Consensus: return "consensus";
    }
    return "unknown";
}

bool ExecuteV1(
    const CBlock& solved_block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    ReportV1& out,
    std::string* why,
    const RCStage3ProducerHints& hints)
{
    out = {};
    if (why != nullptr) why->clear();
    if (height < 0 || target.IsNull()) {
        return Stop(
            out, FailureV1::InvalidRequest,
            "height_or_target", why);
    }
    const auto required =
        RequiredRCStage3Statement(params, height);
    if (!required.has_value()) {
        return Stop(
            out, FailureV1::NotRequired,
            "not_rc_height", why);
    }
    if (*required != RCStage3StatementKind::Composed) {
        return Stop(
            out, FailureV1::UnsupportedStatement,
            "normalized_authority_requires_composed", why);
    }
    if (!HasRCStage3ProductionProofProvider()) {
        return Stop(
            out, FailureV1::ProviderNotInitialized,
            "production_provider_not_initialized", why);
    }
    out.reached = StageV1::RequestChecked;

    const uint256 winner_key = solved_block.GetHash();
    const auto episode =
        RCStage3EpisodeWitnessStoreGet(winner_key);
    if (episode == nullptr) {
        return Stop(
            out, FailureV1::EpisodeCaptureMissing,
            "header_key", why);
    }
    std::string capture_why;
    if (!episode->Complete(&capture_why)) {
        return Stop(
            out, FailureV1::EpisodeCaptureIncomplete,
            capture_why, why);
    }
    out.episode_capture_complete = true;

    const auto coupled =
        RCStage3CoupledWinnerStoreGetV1(winner_key);
    if (coupled == nullptr) {
        return Stop(
            out, FailureV1::CoupledCaptureMissing,
            "header_key", why);
    }
    if (!coupled->Complete(&capture_why)) {
        return Stop(
            out, FailureV1::CoupledCaptureIncomplete,
            capture_why, why);
    }
    const auto coupled_params =
        ResolveRCCoupParams(params);
    const auto coupled_options =
        ResolveRCCoupOptions(params);
    if (!VerifyRCStage3CoupledWinnerReceiptV2(
            solved_block, height, coupled_params,
            coupled_options, coupled->Receipt(),
            &capture_why)) {
        return Stop(
            out, FailureV1::CoupledCaptureBinding,
            capture_why, why);
    }
    out.coupled_capture_complete = true;
    out.reached = StageV1::WinnerCapturesChecked;

    consensus_binding::DirectReceiptConsensusStatementV3
        direct_statement;
    nav3::ComposedPublicStatementV3 public_statement;
    std::string statement_why;
    if (!consensus_binding::RebuildComposedPublicStatementV3(
            solved_block, params, height, target,
            episode->EpisodeDigest(),
            coupled->Receipt().coupled_digest,
            public_statement, &statement_why)) {
        return Stop(
            out, FailureV1::HeaderStatementBinding,
            statement_why, why);
    }
    direct_statement.public_statement =
        public_statement;
    out.header_statement_rebuilt = true;
    out.reached = StageV1::HeaderStatementRebuilt;

    CBlock attached = solved_block;
    std::string produce_why;
    out.produce_status =
        AttachRCStage3ProofFromProductionProvider(
            attached, params, height, target,
            &produce_why, &out.size, hints);
    switch (out.produce_status) {
    case RCStage3ProduceStatus::NotRequired:
        out.provider_status =
            RCStage3NormalizedProviderStatus::NotRequired;
        break;
    case RCStage3ProduceStatus::NoProver:
        out.provider_status =
            RCStage3NormalizedProviderStatus::NotInitialized;
        break;
    case RCStage3ProduceStatus::ProverFailed:
        out.provider_status =
            RCStage3NormalizedProviderStatus::BuildFailed;
        break;
    case RCStage3ProduceStatus::Attached:
        out.provider_status =
            RCStage3NormalizedProviderStatus::Produced;
        break;
    default:
        out.provider_status =
            RCStage3NormalizedProviderStatus::BuildFailed;
        break;
    }
    if (out.produce_status !=
        RCStage3ProduceStatus::Attached) {
        return Stop(
            out, FailureV1::ReceiptBuildOrAttach,
            produce_why, why);
    }
    out.reached = StageV1::ReceiptAttached;

    // Exercise the actual block serialization boundary.  Proof bytes are body
    // data and must survive without changing the finalized header hash.
    DataStream stream;
    stream << TX_WITH_WITNESS(attached);
    CBlock decoded;
    stream >> TX_WITH_WITNESS(decoded);
    if (decoded.GetHash() !=
            solved_block.GetHash() ||
        decoded.matrix_c_data !=
            attached.matrix_c_data) {
        return Stop(
            out, FailureV1::BlockRoundTrip,
            "block_or_attachment_changed", why);
    }
    out.reached = StageV1::BlockRoundTripped;

    std::string unpack_why;
    const auto receipt_bytes =
        transport::UnpackReceiptWordsV3(
            decoded.matrix_c_data, &unpack_why);
    if (!receipt_bytes.has_value()) {
        return Stop(
            out, FailureV1::StrictReceiptDecode,
            unpack_why, why);
    }
    out.receipt_bytes = receipt_bytes->size();
    std::string decode_why;
    const auto receipt =
        nav3::DeserializeNormalizedAuthorityReceiptV3(
            *receipt_bytes, &decode_why);
    if (!receipt.has_value()) {
        return Stop(
            out, FailureV1::StrictReceiptDecode,
            decode_why, why);
    }
    std::vector<unsigned char> canonical_bytes;
    if (nav3::SerializeNormalizedAuthorityReceiptV3(
            *receipt, canonical_bytes) == 0 ||
        canonical_bytes != *receipt_bytes) {
        return Stop(
            out, FailureV1::StrictReceiptDecode,
            "noncanonical_reencode", why);
    }
    out.strict_round_trip = true;
    out.reached = StageV1::StrictReceiptDecoded;

    canonical::FrozenSpecAssessmentV1 assessment;
    std::string canonical_why;
    const auto mechanism =
        canonical::
            VerifyAttachedCanonicalParentMechanismV1(
                decoded, params, height, target,
                &assessment, nullptr, &canonical_why);
    out.canonical_mechanism_status =
        static_cast<uint8_t>(mechanism);
    if (mechanism !=
        canonical::MechanismVerifyStatusV1::
            AuthorityVerified) {
        return Stop(
            out, FailureV1::CanonicalParent,
            canonical_why, why);
    }
    out.canonical_parent_authority = true;
    out.reached = StageV1::CanonicalParentVerified;

    std::string consensus_why;
    out.consensus_status =
        VerifyRCStage3ConsensusAttachment(
            decoded, params, height, target,
            &consensus_why);
    if (out.consensus_status !=
        RCStage3AttachmentStatus::Valid) {
        return Stop(
            out, FailureV1::Consensus,
            consensus_why, why);
    }
    out.consensus_accepted = true;
    out.reached = StageV1::ConsensusVerified;
    out.failure = FailureV1::None;
    out.note =
        "stage3:production_vertical_canary_v1:"
        "mine_prove_attach_fresh_consensus_verify";
    if (why != nullptr) *why = out.note;
    return true;
}

} // namespace matmul::v4::rc::production_vertical_canary
