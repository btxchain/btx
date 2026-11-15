// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT19_H
#define BTX_MODELNET_SWARM_FAULT19_H

#include <string>

namespace modelnet {

/**
 * Live fault 19: a discovery peer advertises false compatibility.
 * Local note only. shared, bytes_moved, and connected stay false.
 * This does not open a socket.
 */
struct SwarmFault19 {
    std::string peer_id;
    bool advertised_compatible{false};
    bool actually_compatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting a false-compatibility advertisement.
 * shared, bytes_moved, and connected stay false on every path.
 */
struct SwarmFault19Result {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
    bool connected{false};
};

/**
 * Note a discovery peer that advertises false compatibility.
 * Order, first match wins:
 * 1. An empty peer_id is PEER. Every result bool stays false and err is PEER.
 * 2. advertised_compatible and not actually_compatible is FAMILY_NOT_COMPAT.
 *    shared and bytes_moved stay false. err is FAMILY_NOT_COMPAT even if
 *    want_share.
 * 3. want_share is HELD. shared and bytes_moved stay false. err is cleared.
 * 4. Otherwise the note is NOTED. shared and bytes_moved stay false.
 *    err is cleared.
 * shared, bytes_moved, and connected stay false on every path.
 * This does not open a socket, connect, share, or move bytes.
 */
SwarmFault19Result SwarmRecoverFault19(const SwarmFault19& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT19_H
