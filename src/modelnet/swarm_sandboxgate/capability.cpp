// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/capability.h>

#include <modelnet/swarm_sandboxgate/blank.h>

#include <string>
#include <vector>

namespace modelnet {

bool SwarmSandboxGateCapabilitiesEmpty(const std::vector<std::string>& capabilities)
{
    return capabilities.empty();
}

bool SwarmSandboxGateCapabilityBlank(const std::string& capability)
{
    return SwarmSandboxGateBlank(capability);
}

bool SwarmSandboxGateCapabilityListed(const std::vector<std::string>& capabilities,
                                      const std::string& capability)
{
    if (SwarmSandboxGateCapabilityBlank(capability)) return false;
    for (const std::string& name : capabilities) {
        if (name == capability) return true;
    }
    return false;
}

} // namespace modelnet
