// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/commit.h>

#include <modelnet/swarm_cursorfence/codes.h>
#include <modelnet/swarm_cursorfence/hash.h>

namespace modelnet {

bool SwarmCursorFenceCommit(const SwarmCursorFenceCursor& cursor, SwarmCursorFenceLedger& ledger, int64_t step, const std::string& hash, std::string& err)
{
    if (SwarmCursorFenceHashEmpty(hash)) {
        err = kSwarmCursorFenceHash;
        return false;
    }
    if (step != cursor.cursor()) {
        err = kSwarmCursorFenceGap;
        return false;
    }
    const SwarmCursorFenceHashKind kind = SwarmCursorFenceClassifyHash(ledger.stored(step), ledger.hash_at(step), hash);
    if (kind == SwarmCursorFenceHashKind::Replay) {
        err = kSwarmCursorFenceReplay;
        return false;
    }
    if (kind == SwarmCursorFenceHashKind::Conflict) {
        err = kSwarmCursorFenceConflict;
        return false;
    }
    if (!ledger.StoreFirst(step, hash)) {
        err = ledger.stored(step) ? kSwarmCursorFenceConflict : kSwarmCursorFenceHash;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
