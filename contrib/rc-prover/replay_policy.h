// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_CONTRIB_RC_PROVER_REPLAY_POLICY_H
#define BITCOIN_CONTRIB_RC_PROVER_REPLAY_POLICY_H

#include <matmul/matmul_v4_rc_gkr.h>

namespace rc_prover {
/** Configure before qualification or replay; match mainnet btxd defaults. */
inline void ConfigureReplayPolicy()
{
    matmul::v4::rc::SetRCExactReplayExecutionPolicy(
        matmul::v4::rc::RCExactReplayExecutionPolicy::StrictDevice);
    matmul::v4::rc::SetRCExactReplayCpuConfirmation(false);
}

/** Mirror btxd's cheap RC header checks before any replay is submitted. */
inline const char* HeaderPrecheck(const CBlockHeader& header, uint32_t dimension)
{
    if (header.matmul_dim != dimension) return "invalid_dimension";
    if (header.seed_a.IsNull() || header.seed_b.IsNull()) return "null_seed";
    if (header.matmul_digest.IsNull()) return "null_digest";
    return nullptr;
}

inline bool CanaryAdmits(const matmul::v4::rc::RCProductionCanaryStatus& status)
{
    // MissingGolden may be admitted by self-qualification, exactly as in btxd.
    return status.passed && status.activation_ready;
}

inline bool ReadyAfterReplay(bool ready, const matmul::v4::rc::ExactReplayVerifyResult& result)
{
    using namespace matmul::v4::rc;
    // A peer's false digest is not evidence that the accelerator is broken.
    // Preserve the restart requirement for actual execution/provider failures.
    if (result.outcome == ExactReplayVerifyOutcome::LocalAcceleratorFailure &&
        (result.failure_kind == RCExactReplayFailureKind::ExecutionFailure ||
         result.failure_kind == RCExactReplayFailureKind::ProviderUnavailable)) return false;
    return ready;
}
} // namespace rc_prover
#endif
