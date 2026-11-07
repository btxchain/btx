// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPCOVER_H
#define BITCOIN_MODELNET_SWARM_CAPCOVER_H

#include <string>

namespace modelnet {

struct SwarmCapCover {
    std::string capability_id;
    bool covered;
    bool want_act;
};

struct SwarmCapCoverResult {
    std::string code;
    bool acted;
};

SwarmCapCoverResult SwarmNoteCapability(const SwarmCapCover& cap, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPCOVER_H
