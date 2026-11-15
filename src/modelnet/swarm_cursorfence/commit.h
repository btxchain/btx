// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_COMMIT_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_COMMIT_H

#include <modelnet/swarm_cursorfence/cursor.h>
#include <modelnet/swarm_cursorfence/ledger.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Store the first hash for the current cursor step.
 * An empty hash is HASH and stores nothing.
 * A step other than the current cursor is GAP and stores nothing.
 * The first hash for that step wins.
 * The same hash again is REPLAY.
 * A different hash is CONFLICT and the first hash stays.
 * This function does not advance the cursor and does not mine.
 */
bool SwarmCursorFenceCommit(const SwarmCursorFenceCursor& cursor, SwarmCursorFenceLedger& ledger, int64_t step, const std::string& hash, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_COMMIT_H
