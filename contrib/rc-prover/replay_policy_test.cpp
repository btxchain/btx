// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// CPU-only policy tests. The setters below stand in for library globals;
// no replay, production qualification, node or GPU is started by this test.
#include "replay_policy.h"
#include <cstdio>

namespace {
using namespace matmul::v4::rc;
RCExactReplayExecutionPolicy policy{RCExactReplayExecutionPolicy::AutoFallback};
bool confirm_cpu{true};
unsigned policy_calls{0}, confirmation_calls{0};
}
namespace matmul::v4::rc {
void SetRCExactReplayExecutionPolicy(RCExactReplayExecutionPolicy value)
{
    policy = value;
    ++policy_calls;
}
void SetRCExactReplayCpuConfirmation(bool value)
{
    confirm_cpu = value;
    ++confirmation_calls;
}
}

int main()
{
    using O = ExactReplayVerifyOutcome;
    using F = RCExactReplayFailureKind;
    rc_prover::ConfigureReplayPolicy();
    if (policy != RCExactReplayExecutionPolicy::StrictDevice || confirm_cpu ||
        policy_calls != 1 || confirmation_calls != 1) {
        std::fprintf(stderr, "mainnet strict-device / no-CPU-confirmation configuration failed\n");
        return 1;
    }
    struct Case { const char* name; O outcome; F failure; bool expected_ready; };
    const Case cases[]{
        {"valid replay", O::Valid, F::None, true},
        {"invalid header", O::InvalidConsensus, F::None, true},
        {"cancelled replay", O::Cancelled, F::Cancelled, true},
        {"unconfirmed digest mismatch", O::LocalAcceleratorFailure, F::UnconfirmedDigestMismatch, true},
        {"retryable cancellation", O::LocalAcceleratorFailure, F::Cancelled, true},
        {"unclassified local outcome", O::LocalAcceleratorFailure, F::None, true},
        {"execution fault", O::LocalAcceleratorFailure, F::ExecutionFailure, false},
        {"unavailable provider", O::LocalAcceleratorFailure, F::ProviderUnavailable, false},
    };
    for (const auto& c : cases) {
        ExactReplayVerifyResult result;
        result.outcome = c.outcome;
        result.failure_kind = c.failure;
        if (rc_prover::ReadyAfterReplay(true, result) != c.expected_ready ||
            rc_prover::ReadyAfterReplay(false, result)) {
            std::fprintf(stderr, "readiness transition failed: %s\n", c.name);
            return 2;
        }
    }
    // A mismatch must allow another request; a later real fault must still latch.
    ExactReplayVerifyResult result;
    result.outcome = O::LocalAcceleratorFailure;
    result.failure_kind = F::UnconfirmedDigestMismatch;
    bool ready{rc_prover::ReadyAfterReplay(true, result)};
    result.outcome = O::Valid;
    result.failure_kind = F::None;
    ready = rc_prover::ReadyAfterReplay(ready, result);
    if (!ready) return 3;
    result.outcome = O::LocalAcceleratorFailure;
    result.failure_kind = F::ExecutionFailure;
    ready = rc_prover::ReadyAfterReplay(ready, result);
    result.outcome = O::Valid;
    result.failure_kind = F::None;
    if (rc_prover::ReadyAfterReplay(ready, result)) return 4;
    std::puts("Replay policy, eight readiness cases and sequential recovery guards passed");
    return 0;
}
