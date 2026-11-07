// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/advance.h>

#include <modelnet/swarm_cursorfence/codes.h>
#include <modelnet/swarm_cursorfence/span.h>

namespace modelnet {

bool SwarmCursorFenceAdvance(SwarmCursorFenceCursor& cursor, int64_t next, std::string& err)
{
    switch (SwarmCursorFenceClassify(cursor.cursor(), next)) {
    case SwarmCursorFenceMove::Range:
        err = kSwarmCursorFenceRange;
        return false;
    case SwarmCursorFenceMove::Stale:
        err = kSwarmCursorFenceStale;
        return false;
    case SwarmCursorFenceMove::Gap:
        err = kSwarmCursorFenceGap;
        return false;
    case SwarmCursorFenceMove::Exact:
        break;
    }
    if (!cursor.Advance(next)) {
        err = kSwarmCursorFenceGap;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
