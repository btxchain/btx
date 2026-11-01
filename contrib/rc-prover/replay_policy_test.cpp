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
    CBlockHeader header;
    header.matmul_dim = 4096;
    header.seed_a.begin()[0] = 1;
    header.seed_b.begin()[0] = 2;
    header.matmul_digest.begin()[0] = 3;
    if (rc_prover::HeaderPrecheck(header, 4096) != nullptr) return 5;
    header.matmul_dim = 2048;
    if (rc_prover::HeaderPrecheck(header, 4096) == nullptr) return 6;
    header.matmul_dim = 4096;
    header.seed_a.SetNull();
    if (rc_prover::HeaderPrecheck(header, 4096) == nullptr) return 7;
    header.seed_a.begin()[0] = 1;
    header.seed_b.SetNull();
    if (rc_prover::HeaderPrecheck(header, 4096) == nullptr) return 8;
    header.seed_b.begin()[0] = 2;
    header.matmul_digest.SetNull();
    if (rc_prover::HeaderPrecheck(header, 4096) == nullptr) return 9;
    RCProductionCanaryStatus canary;
    canary.outcome = RCProductionCanaryOutcome::Passed;
    if (rc_prover::CanaryAdmits(canary)) return 10;
    canary.passed = true;
    if (rc_prover::CanaryAdmits(canary)) return 11;
    canary.activation_ready = true;
    if (!rc_prover::CanaryAdmits(canary)) return 12;
    canary.outcome = RCProductionCanaryOutcome::MissingGolden;
    if (!rc_prover::CanaryAdmits(canary)) return 13;
    canary.passed = false;
    if (rc_prover::CanaryAdmits(canary)) return 14;
    std::puts("Replay policy, readiness sequences, header prechecks and canary admission passed");
    return 0;
}
