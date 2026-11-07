// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/record.h>

#include <modelnet/swarm_sandboxgate/blank.h>
#include <modelnet/swarm_sandboxgate/capability.h>
#include <modelnet/swarm_sandboxgate/clock.h>
#include <modelnet/swarm_sandboxgate/prefix.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

SwarmSandboxGateGrant SwarmSandboxGateMakeGrant(const std::string& worker,
                                                const std::string& path_prefix,
                                                const std::vector<std::string>& capabilities,
                                                bool network,
                                                int64_t until_ms)
{
    SwarmSandboxGateGrant grant;
    grant.worker = worker;
    grant.path_prefix = path_prefix;
    grant.capabilities = capabilities;
    grant.network = network;
    grant.until_ms = until_ms;
    return grant;
}

SwarmSandboxGateAction SwarmSandboxGateMakeAction(const std::string& worker,
                                                  const std::string& path,
                                                  const std::string& capability,
                                                  int64_t now_ms)
{
    SwarmSandboxGateAction action;
    action.worker = worker;
    action.path = path;
    action.capability = capability;
    action.now_ms = now_ms;
    return action;
}

bool SwarmSandboxGateGrantUsable(const SwarmSandboxGateGrant& grant)
{
    if (SwarmSandboxGateBlank(grant.worker)) return false;
    if (SwarmSandboxGateBlank(grant.path_prefix)) return false;
    if (SwarmSandboxGateUntilRejected(grant.until_ms)) return false;
    if (SwarmSandboxGateCapabilitiesEmpty(grant.capabilities)) return false;
    return true;
}

bool SwarmSandboxGateActionUsable(const SwarmSandboxGateAction& action)
{
    if (SwarmSandboxGateBlank(action.worker)) return false;
    if (SwarmSandboxGateBlank(action.path)) return false;
    if (SwarmSandboxGateCapabilityBlank(action.capability)) return false;
    if (SwarmSandboxGatePrivatePath(action.path)) return false;
    return true;
}

} // namespace modelnet
