// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGLOBAL_H
#define BTX_MODELNET_SWARM_NOTNOGLOBAL_H

#include <string>

namespace modelnet {

struct SwarmNotNoGlobal {
    std::string island_id;
    bool want_build{false};
};

struct SwarmNotNoGlobalResult {
    std::string code;
    bool built{false};
    bool bytes_moved{false};
};

// Island admission does not build a global checkpoint.
SwarmNotNoGlobalResult SwarmNoteNotNoGlobal(const SwarmNotNoGlobal& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGLOBAL_H
