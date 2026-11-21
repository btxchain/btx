// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <compat/wide128.h>
#include <modelnet/swarm_cursorfence/span.h>

#include <modelnet/swarm_cursorfence/limits.h>

namespace modelnet {

SwarmCursorFenceMove SwarmCursorFenceClassify(int64_t cursor, int64_t next)
{
    if (next < 0) return SwarmCursorFenceMove::Range;
    if (next <= cursor) return SwarmCursorFenceMove::Stale;
    const btx::I128 delta = static_cast<btx::I128>(next) - static_cast<btx::I128>(cursor);
    if (delta == static_cast<btx::I128>(kSwarmCursorFenceStep)) return SwarmCursorFenceMove::Exact;
    return SwarmCursorFenceMove::Gap;
}

} // namespace modelnet
