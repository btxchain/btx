// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/prefix.h>

#include <modelnet/swarm_sandboxgate/limits.h>

#include <cstddef>
#include <string>

namespace modelnet {

bool SwarmSandboxGateStrictPrefix(const std::string& prefix, const std::string& path)
{
    if (prefix.empty()) return false;
    if (path.size() <= prefix.size()) return false;
    return path.compare(0, prefix.size(), prefix) == 0;
}

bool SwarmSandboxGatePrivatePath(const std::string& path)
{
    constexpr std::size_t prefix_len = sizeof(kSwarmSandboxGatePrivatePrefix) - 1;
    if (path.size() < prefix_len) return false;
    return path.compare(0, prefix_len, kSwarmSandboxGatePrivatePrefix) == 0;
}

} // namespace modelnet
