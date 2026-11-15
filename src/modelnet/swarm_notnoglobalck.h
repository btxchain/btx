// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGLOBALCK_H
#define BTX_MODELNET_SWARM_NOTNOGLOBALCK_H

#include <string>

namespace modelnet {

struct SwarmNotNoGlobalCk {
    std::string island_id;
    bool want_checkpoint{false};
};

struct SwarmNotNoGlobalCkResult {
    std::string code;
    bool saved{false};
    bool bytes_moved{false};
};

// An island note builds no global checkpoint.
SwarmNotNoGlobalCkResult SwarmNoteNotNoGlobalCk(const SwarmNotNoGlobalCk& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGLOBALCK_H
