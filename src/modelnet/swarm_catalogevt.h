// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CATALOGEVT_H
#define BTX_MODELNET_SWARM_CATALOGEVT_H

#include <string>

namespace modelnet {

/**
 * A local catalog note about one candidate. Opening a socket, adopting
 * the candidate, and subscribing to a network are not provided.
 */
struct SwarmCatalogEvent {
    std::string event_id;
    std::string candidate_id;
    bool qualified{false};
    bool want_socket{false};
    bool want_adopt{false};
};

/**
 * A local catalog note. adopted and socket_opened stay false: this
 * function does not adopt a candidate and does not open a socket.
 */
struct SwarmCatalogEventResult {
    bool noted{false};
    bool adopted{false};
    bool socket_opened{false};
    std::string code;
};

/**
 * Order, first match wins: an empty event_id or candidate_id is CATALOG.
 * A request that wants a socket is NO_SOCKET. A request that wants to
 * adopt an unqualified candidate is NOT_ADOPTED. Otherwise the event is
 * NOTED and err is clear. noted is true only for NOTED. adopted and
 * socket_opened stay false. This records a local catalog note. It does
 * not open a socket, does not adopt a candidate, and does not subscribe
 * to a network.
 */
SwarmCatalogEventResult SwarmNoteCatalogEvent(const SwarmCatalogEvent& event, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CATALOGEVT_H
