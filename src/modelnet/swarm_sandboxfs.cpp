// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxfs.h>

namespace modelnet {

bool SwarmSandboxFs::Allow(const std::string& sandbox_root, const std::string& path, std::string& err)
{
    if (sandbox_root.empty() || path.empty()) {
        err = "PATH";
        return false;
    }
    if (path.find("..") != std::string::npos) {
        err = "ESCAPE";
        return false;
    }
    if (path.compare(0, sandbox_root.size(), sandbox_root) != 0) {
        err = "ESCAPE";
        return false;
    }
    if (m_paths.find(path) != m_paths.end()) {
        err = "REPLAY";
        return false;
    }
    m_paths.insert(path);
    err.clear();
    return true;
}

bool SwarmSandboxFs::allowed(const std::string& path) const
{
    return m_paths.find(path) != m_paths.end();
}

bool SwarmSandboxFs::launched() const
{
    return false;
}

} // namespace modelnet
