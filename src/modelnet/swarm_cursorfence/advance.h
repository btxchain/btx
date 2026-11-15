// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_ADVANCE_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_ADVANCE_H

#include <modelnet/swarm_cursorfence/cursor.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Advance the cursor by exactly 1.
 * next below 0 is RANGE and the cursor stays.
 * next at or below the cursor is STALE and the cursor stays.
 * next above cursor + 1 is GAP and the cursor stays.
 * next equal to cursor + 1 sets the cursor to next.
 * This function does not mine and does not store a hash.
 */
bool SwarmCursorFenceAdvance(SwarmCursorFenceCursor& cursor, int64_t next, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_ADVANCE_H
