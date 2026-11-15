// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTSUBSCRIBE_H
#define BITCOIN_MODELNET_SWARM_NOTSUBSCRIBE_H

#include <string>

namespace modelnet {

struct SwarmNotSubscribe {
    std::string model_id;
    bool want_subscribe{false};
};

struct SwarmNotSubscribeResult {
    std::string code;
    bool subscribed{false};
    bool adopted{false};
};

/** Record a note only. This note does not subscribe and does not adopt. */
SwarmNotSubscribeResult SwarmNoteNotSubscribe(const SwarmNotSubscribe& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTSUBSCRIBE_H
