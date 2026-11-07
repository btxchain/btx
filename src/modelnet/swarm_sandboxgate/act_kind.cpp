// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/act_kind.h>

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/capability.h>
#include <modelnet/swarm_sandboxgate/clock.h>
#include <modelnet/swarm_sandboxgate/codes.h>
#include <modelnet/swarm_sandboxgate/prefix.h>
#include <modelnet/swarm_sandboxgate/record.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

SwarmSandboxGateActKind SwarmSandboxGateClassifyAct(const SwarmSandboxGateBook& book,
                                                    const std::string& worker,
                                                    const std::string& path,
                                                    const std::string& capability,
                                                    int64_t now_ms)
{
    if (!book.worker_granted(worker)) return SwarmSandboxGateActKind::NotGranted;

    const std::vector<SwarmSandboxGateGrant> matches = book.matching(worker, path);
    if (matches.empty()) return SwarmSandboxGateActKind::Denied;

    bool any_live = false;
    bool listed = false;
    for (const SwarmSandboxGateGrant& grant : matches) {
        if (!SwarmSandboxGateLive(grant.until_ms, now_ms)) continue;
        any_live = true;
        if (SwarmSandboxGateCapabilityListed(grant.capabilities, capability)) listed = true;
    }
    if (!any_live) return SwarmSandboxGateActKind::Expired;
    if (SwarmSandboxGatePrivatePath(path)) return SwarmSandboxGateActKind::PrivateData;
    if (SwarmSandboxGateCapabilityBlank(capability)) return SwarmSandboxGateActKind::Capability;
    if (!listed) return SwarmSandboxGateActKind::NotActed;
    return SwarmSandboxGateActKind::Allow;
}

const char* SwarmSandboxGateActKindCode(SwarmSandboxGateActKind kind)
{
    switch (kind) {
    case SwarmSandboxGateActKind::Allow:
        return nullptr;
    case SwarmSandboxGateActKind::NotGranted:
        return kSwarmSandboxGateNotGranted;
    case SwarmSandboxGateActKind::Expired:
        return kSwarmSandboxGateExpired;
    case SwarmSandboxGateActKind::Denied:
        return kSwarmSandboxGateDenied;
    case SwarmSandboxGateActKind::PrivateData:
        return kSwarmSandboxGatePrivateData;
    case SwarmSandboxGateActKind::Capability:
        return kSwarmSandboxGateCapability;
    case SwarmSandboxGateActKind::NotActed:
        return kSwarmSandboxGateNotActed;
    }
    return kSwarmSandboxGateNotGranted;
}

} // namespace modelnet
