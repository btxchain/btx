// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHSTATE_H
#define BITCOIN_MODELNET_SWARM_WATCHSTATE_H

#include <string>

namespace modelnet {

struct SwarmWatchState {
    std::string channel_id;
    bool stale;
    bool want_penalty;
    bool want_broadcast;
};

struct SwarmWatchStateResult {
    std::string code;
    bool penalized;
    bool broadcast;
    bool secp_penalty;
};

SwarmWatchStateResult SwarmWatchChannel(const SwarmWatchState& watch, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHSTATE_H
