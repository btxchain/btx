// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTNOMULTIPLIER2_H
#define BITCOIN_MODELNET_SWARM_NOTNOMULTIPLIER2_H

#include <string>

namespace modelnet {

struct SwarmNotNoMultiplier2 {
    std::string sample_id;
    bool want_publish{false};
};

struct SwarmNotNoMultiplier2Result {
    std::string code;
    bool published{false};
};

SwarmNotNoMultiplier2Result SwarmNoteNotNoMultiplier2(const SwarmNotNoMultiplier2& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTNOMULTIPLIER2_H
