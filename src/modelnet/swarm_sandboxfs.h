// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SANDBOXFS_H
#define BTX_MODELNET_SWARM_SANDBOXFS_H

#include <set>
#include <string>

namespace modelnet {

/** Path allow-list for a sandbox root. Does not exec a child. */
class SwarmSandboxFs {
public:
    bool Allow(const std::string& sandbox_root, const std::string& path, std::string& err);
    bool allowed(const std::string& path) const;
    bool launched() const;

private:
    std::set<std::string> m_paths;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SANDBOXFS_H
