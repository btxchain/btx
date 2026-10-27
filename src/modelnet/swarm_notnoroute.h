// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOROUTE_H
#define BTX_MODELNET_SWARM_NOTNOROUTE_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_reach asks this note to treat a
 * missing route as qualification of a remote host.
 *
 * A missing route does not qualify a remote host. This note opens no
 * connection and names no address. reached and qualified stay false
 * on every path.
 */
struct SwarmNotNoRoute {
    std::string peer_id;
    bool want_reach{false};
};

/**
 * Outcome of noting a missing route. reached and qualified stay false
 * on every path: a missing route does not qualify a remote host. This
 * note opens no connection and names no address.
 */
struct SwarmNotNoRouteResult {
    std::string code;
    bool reached{false};
    bool qualified{false};
};

/**
 * Note a missing route without qualifying a remote host.
 * Order, first match wins: an empty peer_id is PEER.
 * want_reach is UNQUALIFIED.
 * Otherwise the note is NOTED and err is clear.
 * reached and qualified stay false on every path. A missing route
 * does not qualify a remote host. This note opens no connection and
 * names no address.
 */
SwarmNotNoRouteResult SwarmNoteNotNoRoute(const SwarmNotNoRoute& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOROUTE_H
