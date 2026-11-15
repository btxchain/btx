// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTNOPRIVATEOFF2_H
#define BITCOIN_MODELNET_SWARM_NOTNOPRIVATEOFF2_H

#include <string>

namespace modelnet {

struct SwarmNotNoPrivateOff2 {
    std::string node_id;
    bool no_device{false};
    bool want_enable{false};
};

struct SwarmNotNoPrivateOff2Result {
    std::string code;
    bool enabled{false};
};

SwarmNotNoPrivateOff2Result SwarmNoteNotNoPrivateOff2(const SwarmNotNoPrivateOff2& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTNOPRIVATEOFF2_H
