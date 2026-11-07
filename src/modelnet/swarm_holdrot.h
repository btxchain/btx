// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_H

#include <string>

namespace modelnet {

struct SwarmHoldRot {
    std::string split_id;
    bool fixed_holdout;
    bool want_rotate;
};

struct SwarmHoldRotResult {
    std::string code;
    bool rotated;
};

SwarmHoldRotResult SwarmNoteHoldRot(const SwarmHoldRot& split, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_H
