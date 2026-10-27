// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_HASH_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_HASH_H

#include <string>

namespace modelnet {

/** How a commit hash relates to the hash already stored for that step. */
enum class SwarmCursorFenceHashKind {
    Store,
    Replay,
    Conflict,
};

/** True when hash is empty. An empty hash is not stored. */
bool SwarmCursorFenceHashEmpty(const std::string& hash);

/**
 * When nothing is stored yet, the next hash can be stored.
 * The same hash is a replay. A different hash is a conflict.
 * The stored hash is not changed by this classification.
 */
SwarmCursorFenceHashKind SwarmCursorFenceClassifyHash(bool have_hash, const std::string& stored, const std::string& next);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_HASH_H
