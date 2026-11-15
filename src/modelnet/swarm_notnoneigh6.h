// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEIGH6_H
#define BTX_MODELNET_SWARM_NOTNONEIGH6_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. peer_id names the peer.
 * count is the neighborhood size. want_add asks this note to add.
 *
 * The neighborhood cap is 4 lowest-RTT plus 2 new trust domains. This note adds no peer.
 * added and bytes_moved stay false on every path.
 */
struct SwarmNotNoNeigh6 {
    std::string peer_id;
    int count{0};
    bool want_add{false};
};

/**
 * Outcome of noting a peer. added and bytes_moved stay false on
 * every path. The neighborhood cap is 4 lowest-RTT plus 2 new trust
 * domains. This note adds no peer.
 */
struct SwarmNotNoNeigh6Result {
    std::string code;
    bool added{false};
    bool bytes_moved{false};
};

/**
 * Note a peer without adding it. Order, first match wins: an empty
 * peer_id is PEER. A count greater than 6 is NOT_ADDED even when
 * want_add is false. want_add is HELD. Otherwise the note is NOTED
 * and err is cleared. added and bytes_moved stay false on every path.
 * The neighborhood cap is 4 lowest-RTT plus 2 new trust domains. This
 * note adds no peer.
 */
SwarmNotNoNeigh6Result SwarmNoteNotNoNeigh6(const SwarmNotNoNeigh6& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEIGH6_H
