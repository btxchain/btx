// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_HASH_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_HASH_H

#include <string>

namespace modelnet {

/** How a new result hash relates to the hash already stored for a task. */
enum class LeaseWorkHashKind {
    Store,
    Replay,
    Conflict,
};

/**
 * When nothing is stored yet, the next hash can be stored.
 * The same hash is a replay. A different hash is a conflict.
 * The stored hash is not changed by this classification.
 */
LeaseWorkHashKind LeaseWorkClassifyHash(bool have_hash, const std::string& stored, const std::string& next);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_HASH_H
