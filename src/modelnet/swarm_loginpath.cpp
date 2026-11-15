// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginpath.h>

namespace modelnet {

SwarmLoginPathResult SwarmNoteLoginPath(const SwarmLoginPath& node, std::string& err)
{
    SwarmLoginPathResult result;
    result.logged_in = false;
    // A Windows login request is held and does not log in.
    if (node.node_id.empty()) {
        result.code = "NODE";
        result.logged_in = false;
        err = "NODE";
        return result;
    }
    if (node.want_login) {
        result.code = "HELD";
        result.logged_in = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.logged_in = false;
    err.clear();
    return result;
}

} // namespace modelnet
