// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EXECUTOR_H
#define BTX_MODELNET_SWARM_EXECUTOR_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A requested coding or sysadmin executor. This process does not start a
 * child. A remote manifest that selects a host interpreter or a provider
 * credential is refused. Without a sandbox boundary the request is
 * SANDBOX_ABSENT.
 */
struct SwarmExecutorRequest {
    bool remote_manifest{false};
    bool selects_host_interpreter{false};
    bool selects_provider_credential{false};
    bool sandbox_present{false};
    /** Zero means the caller did not ask for a thread count. Above 64 or below 0 is CAPPED. */
    int64_t requested_threads{0};
    /** Zero means the caller did not ask for memory. Above 16384 or below 0 is CAPPED. */
    int64_t requested_mib{0};
    /** A network request is refused. The sandbox does not open one. */
    bool network{false};
};

struct SwarmExecutorDecision {
    bool admitted{false};
    bool launched{false};
};

SwarmExecutorDecision SwarmAdmitExecutor(const SwarmExecutorRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EXECUTOR_H
