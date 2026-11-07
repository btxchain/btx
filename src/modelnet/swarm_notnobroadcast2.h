// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBROADCAST2_H
#define BTX_MODELNET_SWARM_NOTNOBROADCAST2_H

#include <string>

namespace modelnet {

/**
 * A local note about one transaction. want_broadcast asks this note to
 * broadcast.
 *
 * Nothing is broadcast to mainnet. broadcast stays false on every path.
 */
struct SwarmNotNoBroadcast2 {
    std::string tx_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a transaction. broadcast stays false on every path.
 * Nothing is broadcast to mainnet.
 */
struct SwarmNotNoBroadcast2Result {
    std::string code;
    bool broadcast{false};
};

/**
 * Note a transaction without broadcasting.
 * Order, first match wins: an empty tx_id is TX. want_broadcast is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * broadcast stays false on every path. Nothing is broadcast to mainnet.
 */
SwarmNotNoBroadcast2Result SwarmNoteNotNoBroadcast2(const SwarmNotNoBroadcast2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBROADCAST2_H
