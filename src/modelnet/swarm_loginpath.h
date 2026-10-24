// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LOGINPATH_H
#define BTX_MODELNET_SWARM_LOGINPATH_H

#include <string>

namespace modelnet {

struct SwarmLoginPath {
    std::string node_id;
    bool want_login;
};

struct SwarmLoginPathResult {
    std::string code;
    bool logged_in;
};

SwarmLoginPathResult SwarmNoteLoginPath(const SwarmLoginPath& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LOGINPATH_H
