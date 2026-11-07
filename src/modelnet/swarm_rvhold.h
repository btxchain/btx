// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RVHOLD_H
#define BTX_MODELNET_SWARM_RVHOLD_H

#include <string>

namespace modelnet {

/**
 * A public-rendezvous record. node_id names the node. public_rv marks a
 * public rendezvous. want_open asks this record to open.
 * A public rendezvous opens no socket and publishes no address.
 */
struct SwarmRvHold {
    std::string node_id;
    bool public_rv{false};
    bool want_open{false};
};

/**
 * Outcome of holding a rendezvous. opened and published stay false on
 * every path. A public rendezvous opens no socket.
 */
struct SwarmRvHoldResult {
    std::string code;
    bool opened{false};
    bool published{false};
};

/**
 * Hold a rendezvous without opening a socket or publishing an address.
 * Order, first match wins: an empty node_id is NODE. public_rv is HELD
 * even when want_open is false. want_open is HELD. Otherwise the record
 * is NOTED and err is cleared. opened and published stay false on every
 * path. A public rendezvous opens no socket.
 */
SwarmRvHoldResult SwarmHoldRendezvous(const SwarmRvHold& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RVHOLD_H
