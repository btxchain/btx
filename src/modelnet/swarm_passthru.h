// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PASSTHRU_H
#define BITCOIN_MODELNET_SWARM_PASSTHRU_H

#include <string>

namespace modelnet {

struct SwarmPassthru {
    std::string node_id;
    bool want_start;
};

struct SwarmPassthruResult {
    std::string code;
    bool started;
};

SwarmPassthruResult SwarmNotePassthru(const SwarmPassthru& node, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PASSTHRU_H
