// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_MINE_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_MINE_H

#include <string>

namespace modelnet {

/**
 * Refuse to mine.
 * The result is always HELD. blocks() stays 0.
 * There is no broadcast and no byte is moved.
 */
bool SwarmCursorFenceMine(std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_MINE_H
