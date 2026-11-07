// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_executor.h>

namespace modelnet {

SwarmExecutorDecision SwarmAdmitExecutor(const SwarmExecutorRequest& request, std::string& err)
{
    SwarmExecutorDecision decision;
    decision.launched = false;
    if (request.remote_manifest && (request.selects_host_interpreter || request.selects_provider_credential)) {
        err = "EXECUTOR";
        return decision;
    }
    if (request.network) {
        err = "NETWORK";
        return decision;
    }
    if (request.requested_threads < 0 || request.requested_threads > 64 || request.requested_mib < 0 || request.requested_mib > 16384) {
        err = "CAPPED";
        return decision;
    }
    if (!request.sandbox_present) {
        err = "SANDBOX_ABSENT";
        return decision;
    }
    decision.admitted = true;
    err.clear();
    return decision;
}

} // namespace modelnet
