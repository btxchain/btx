// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTROLLOUT_H
#define BITCOIN_MODELNET_SWARM_NOTROLLOUT_H

#include <string>

namespace modelnet {

struct SwarmNotRollout {
    std::string agent_id;
    bool want_generate{false};
};

struct SwarmNotRolloutResult {
    std::string code;
    bool generated{false};
    bool recorded{false};
};

SwarmNotRolloutResult SwarmNoteNotRollout(const SwarmNotRollout& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTROLLOUT_H
