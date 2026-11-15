// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_ROW_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_ROW_H

#include <string>

namespace modelnet {

/**
 * One reservation. The outpoint is the table key, not a field here.
 * No atom count is stored: reserving an outpoint does not move atoms.
 * The same outpoint is never both escrow and collateral.
 */
struct SwarmCollatRow {
    std::string pool;
    std::string bucket;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_ROW_H
