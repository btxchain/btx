// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG02_H
#define BTX_MODELNET_SWARM_FLAG02_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 2 join against the local family catalog.
 * manual_config asks for a manual configuration and is refused.
 * want_connect asks to open a socket. want_pass asks to treat the stage
 * as passed.
 *
 * joined, connected, traversed, passed, and bytes_moved stay false on
 * every path. This note does not open a socket or traverse NAT.
 */
struct SwarmFlag02 {
    std::string family_id;
    std::string peer_id;
    bool manual_config{false};
    bool want_connect{false};
    bool want_pass{false};
};

/**
 * Outcome of a flagship stage 2 join note. joined, connected, traversed,
 * passed, and bytes_moved stay false on every path.
 */
struct SwarmFlag02Result {
    std::string code;
    bool joined{false};
    bool connected{false};
    bool traversed{false};
    bool passed{false};
    bool bytes_moved{false};
};

/**
 * Note a flagship stage 2 join against the local family catalog.
 * Order, first match wins: an empty family_id or peer_id is FAMILY.
 * manual_config is MANUAL and is refused. want_connect is NO_SOCKET and
 * opens no socket. want_pass is UNQUALIFIED. Otherwise the note is NOTED
 * and err is clear.
 * joined, connected, traversed, passed, and bytes_moved stay false on
 * every path. This note does not open a socket or traverse NAT.
 */
SwarmFlag02Result SwarmStageJoin(const SwarmFlag02& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG02_H
