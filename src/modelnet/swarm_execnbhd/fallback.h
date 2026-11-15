// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_FALLBACK_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_FALLBACK_H

#include <string>

namespace modelnet {

/**
 * Refuse a fallback peer. An empty id is PEER.
 * Any other id is NOT_CONNECTED.
 * This function has no book and no seating, so it cannot store or seat.
 * It does not connect and does not open a socket.
 */
bool SwarmExecNbhdFallback(const std::string& peer, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_FALLBACK_H
