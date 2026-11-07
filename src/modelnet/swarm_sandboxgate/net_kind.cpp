// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/net_kind.h>

#include <modelnet/swarm_sandboxgate/blank.h>
#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/clock.h>
#include <modelnet/swarm_sandboxgate/codes.h>
#include <modelnet/swarm_sandboxgate/record.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

SwarmSandboxGateNetKind SwarmSandboxGateClassifyNet(const SwarmSandboxGateBook& book,
                                                    const std::string& worker,
                                                    const std::string& host_id,
                                                    int64_t now_ms)
{
    if (SwarmSandboxGateBlank(host_id)) return SwarmSandboxGateNetKind::Net;
    if (!book.worker_granted(worker)) return SwarmSandboxGateNetKind::NotGranted;
    if (book.network_live(worker, now_ms)) return SwarmSandboxGateNetKind::Permit;

    const std::vector<SwarmSandboxGateGrant> grants = book.grants_for(worker);
    bool any_live = false;
    bool any_network = false;
    for (const SwarmSandboxGateGrant& grant : grants) {
        if (SwarmSandboxGateLive(grant.until_ms, now_ms)) any_live = true;
        if (grant.network) any_network = true;
    }
    if (!any_live) return SwarmSandboxGateNetKind::Expired;
    if (!any_network) return SwarmSandboxGateNetKind::NetDenied;
    return SwarmSandboxGateNetKind::Expired;
}

const char* SwarmSandboxGateNetKindCode(SwarmSandboxGateNetKind kind)
{
    switch (kind) {
    case SwarmSandboxGateNetKind::Permit:
        return nullptr;
    case SwarmSandboxGateNetKind::Net:
        return kSwarmSandboxGateNet;
    case SwarmSandboxGateNetKind::NotGranted:
        return kSwarmSandboxGateNotGranted;
    case SwarmSandboxGateNetKind::Expired:
        return kSwarmSandboxGateExpired;
    case SwarmSandboxGateNetKind::NetDenied:
        return kSwarmSandboxGateNetDenied;
    }
    return kSwarmSandboxGateNet;
}

} // namespace modelnet
