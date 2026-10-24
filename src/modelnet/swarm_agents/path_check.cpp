// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/path_check.h>

#include <string>

namespace modelnet {

bool SwarmAgentPathInside(const std::string& sandbox_root, const std::string& path)
{
    if (sandbox_root.empty() || sandbox_root.back() != '/') {
        return false;
    }
    if (path.empty()) {
        return false;
    }
    if (path.find("..") != std::string::npos) {
        return false;
    }
    if (path.compare(0, sandbox_root.size(), sandbox_root) != 0) {
        return false;
    }
    return true;
}

} // namespace modelnet
