// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEIGH2_H
#define BTX_MODELNET_SWARM_NOTNONEIGH2_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. peer_id names the peer.
 * outside_set says the peer is outside the neighborhood.
 * want_connect asks this note to connect.
 *
 * A neighborhood of four lowest-RTT peers plus two new trust domains
 * does not connect a peer outside that set. connected and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoNeigh2 {
    std::string peer_id;
    bool outside_set{false};
    bool want_connect{false};
};

/**
 * Outcome of noting a peer. connected and bytes_moved stay false on
 * every path. A neighborhood of four lowest-RTT peers plus two new
 * trust domains does not connect a peer outside that set.
 */
struct SwarmNotNoNeigh2Result {
    std::string code;
    bool connected{false};
    bool bytes_moved{false};
};

/**
 * Note a peer without connecting it.
 * Order, first match wins: an empty peer_id is PEER.
 * outside_set true is NOT_CONNECTED even when want_connect is false.
 * want_connect is HELD. Otherwise the note is NOTED and err is cleared.
 * connected and bytes_moved stay false on every path.
 * A neighborhood of four lowest-RTT peers plus two new trust domains
 * does not connect a peer outside that set.
 */
SwarmNotNoNeigh2Result SwarmNoteNotNoNeigh2(const SwarmNotNoNeigh2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEIGH2_H
