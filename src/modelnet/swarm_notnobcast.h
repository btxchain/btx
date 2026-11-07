// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBCAST_H
#define BTX_MODELNET_SWARM_NOTNOBCAST_H

#include <string>

namespace modelnet {

/**
 * A local note about one transaction. want_mainnet asks this note to
 * broadcast to mainnet.
 *
 * This note does not broadcast to mainnet. broadcast and mined stay false
 * on every path.
 */
struct SwarmNotNoBcast {
    std::string tx_id;
    bool want_mainnet{false};
};

/**
 * Outcome of noting a transaction. broadcast and mined stay false on
 * every path: this note does not broadcast to mainnet.
 */
struct SwarmNotNoBcastResult {
    std::string code;
    bool broadcast{false};
    bool mined{false};
};

/**
 * Note a transaction without broadcasting to mainnet.
 * Order, first match wins: an empty tx_id is TX. want_mainnet is MAINNET.
 * Otherwise the note is NOTED and err is clear.
 * broadcast and mined stay false on every path. This note does not
 * broadcast to mainnet.
 */
SwarmNotNoBcastResult SwarmNoteNotNoBcast(const SwarmNotNoBcast& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBCAST_H
