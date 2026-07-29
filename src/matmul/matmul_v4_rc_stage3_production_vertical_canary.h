// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_VERTICAL_CANARY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_VERTICAL_CANARY_H

#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_producer.h>

#include <cstddef>
#include <cstdint>
#include <string>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc::production_vertical_canary {

inline constexpr uint16_t kProductionVerticalCanaryVersionV1 = 1;

/**
 * Ordered checkpoints in the real production lifecycle.
 *
 * This is an opt-in diagnostic path.  It calls the same provider, BNV3
 * transport, independent canonical-parent rebuild and consensus verifier as
 * the miner/validator.  It never changes a readiness or activation flag.
 */
enum class StageV1 : uint8_t {
    None = 0,
    RequestChecked = 1,
    WinnerCapturesChecked = 2,
    HeaderStatementRebuilt = 3,
    ReceiptAttached = 4,
    BlockRoundTripped = 5,
    StrictReceiptDecoded = 6,
    CanonicalParentVerified = 7,
    ConsensusVerified = 8,
};

enum class FailureV1 : uint8_t {
    None = 0,
    InvalidRequest = 1,
    NotRequired = 2,
    UnsupportedStatement = 3,
    ProviderNotInitialized = 4,
    EpisodeCaptureMissing = 5,
    EpisodeCaptureIncomplete = 6,
    CoupledCaptureMissing = 7,
    CoupledCaptureIncomplete = 8,
    CoupledCaptureBinding = 9,
    HeaderStatementBinding = 10,
    ReceiptBuildOrAttach = 11,
    BlockRoundTrip = 12,
    StrictReceiptDecode = 13,
    CanonicalParent = 14,
    Consensus = 15,
};

struct ReportV1 {
    uint16_t version{kProductionVerticalCanaryVersionV1};
    StageV1 reached{StageV1::None};
    FailureV1 failure{FailureV1::None};
    RCStage3NormalizedProviderStatus provider_status{
        RCStage3NormalizedProviderStatus::NotInitialized};
    RCStage3ProduceStatus produce_status{
        RCStage3ProduceStatus::AuthorityDisabled};
    RCStage3AttachmentStatus consensus_status{
        RCStage3AttachmentStatus::AuthorityUnavailable};
    uint8_t canonical_mechanism_status{0};
    RCStage3AttachmentSizeReport size{};
    size_t receipt_bytes{0};
    bool episode_capture_complete{false};
    bool coupled_capture_complete{false};
    bool header_statement_rebuilt{false};
    bool strict_round_trip{false};
    bool canonical_parent_authority{false};
    bool consensus_accepted{false};
    std::string note;

    [[nodiscard]] bool ProductionCandidateVerified() const
    {
        return reached == StageV1::ConsensusVerified &&
            failure == FailureV1::None &&
            canonical_parent_authority &&
            consensus_accepted;
    }
};

[[nodiscard]] const char* StageNameV1(StageV1 stage);
[[nodiscard]] const char* FailureNameV1(FailureV1 failure);

/**
 * Execute the winner-to-consensus vertical path on a scratch block.
 *
 * Preconditions:
 *  - `solved_block` is the finalized winner header;
 *  - the solver's callback-time episode and coupled captures are present in
 *    their header-keyed stores;
 *  - the process-owned production provider has been initialized.
 *
 * The input block and winner stores are not modified.  On success the report
 * proves that a freshly serialized block was accepted by both the independent
 * canonical-parent verifier and the consensus entry point.  Until authority
 * closes, the function returns false at the precise first open construction.
 */
[[nodiscard]] bool ExecuteV1(
    const CBlock& solved_block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    ReportV1& out,
    std::string* why = nullptr,
    const RCStage3ProducerHints& hints = {});

inline constexpr bool kProductionVerticalCanaryExecutableV1 = true;
inline constexpr bool kProductionVerticalCanaryAuthorityReadyV1 = false;

static_assert(kProductionVerticalCanaryExecutableV1);
static_assert(!kProductionVerticalCanaryAuthorityReadyV1);

} // namespace matmul::v4::rc::production_vertical_canary

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_VERTICAL_CANARY_H
