// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifestok.h>
#include <modelnet/swarm_cycle.h>

namespace modelnet {

bool SwarmManifestOk::Bind(const std::string& root_id, const std::vector<std::string>& children, const std::vector<std::string>& verified, std::string& err)
{
    if (root_id.empty()) {
        err = "MANIFEST";
        return false;
    }
    if (m_roots.find(root_id) != m_roots.end()) {
        err = "REPLAY";
        return false;
    }

    SwarmManifestRoot root;
    root.children.reserve(children.size());
    for (const std::string& digest : children) {
        SwarmChildManifest child;
        child.digest = digest;
        root.children.push_back(child);
    }
    if (!SwarmBindManifestRoot(root, verified, err)) {
        return false;
    }
    m_roots.insert(root_id);
    err.clear();
    return true;
}

bool SwarmManifestOk::usable(const std::string& root_id) const
{
    return m_roots.find(root_id) != m_roots.end();
}

bool SwarmManifestOk::bytes_streamed() const
{
    return false;
}

} // namespace modelnet
