// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINTEGER82_H
#define BTX_MODELNET_SWARM_NOTNOINTEGER82_H

#include <string>

namespace modelnet {

struct SwarmNotNoInteger82 {
    std::string pair_id;
    bool want_add{false};
};

struct SwarmNotNoInteger82Result {
    std::string code;
    bool added{false};
};

SwarmNotNoInteger82Result SwarmNoteNotNoInteger82(const SwarmNotNoInteger82& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINTEGER82_H
