// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGLOBALCKPT_H
#define BTX_MODELNET_SWARM_NOTNOGLOBALCKPT_H

#include <string>

namespace modelnet {

struct SwarmNotNoGlobalCkpt {
    std::string island_id;
    bool want_build{false};
};

struct SwarmNotNoGlobalCkptResult {
    std::string code;
    bool built{false};
    bool bytes_moved{false};
};

// An island note builds no global checkpoint and moves no bytes.
SwarmNotNoGlobalCkptResult SwarmNoteNotNoGlobalCkpt(const SwarmNotNoGlobalCkpt& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGLOBALCKPT_H
