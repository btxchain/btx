// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_peerpath.h>

#include <string>

namespace modelnet {

SwarmPeerPathResult SwarmNotePeerPath(const SwarmPeerPath& path, std::string& err)
{
    SwarmPeerPathResult result;
    result.opened = false;
    if (path.peer_id.empty() || path.relative_path.empty()) {
        result.code = "PATH";
        result.opened = false;
        err = "PATH";
        return result;
    }
    // PEER_PATH wins even when want_open is true.
    if (path.relative_path.find('/') != std::string::npos ||
        path.relative_path.find('\\') != std::string::npos ||
        path.relative_path.find("..") != std::string::npos) {
        result.code = "PEER_PATH";
        result.opened = false;
        err = "PEER_PATH";
        return result;
    }
    // This note does not open a path.
    if (path.want_open) {
        result.code = "HELD";
        result.opened = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
