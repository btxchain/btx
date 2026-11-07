// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/cursor.h>

#include <modelnet/swarm_cursorfence/span.h>

namespace modelnet {

int64_t SwarmCursorFenceCursor::cursor() const
{
    return m_cursor;
}

bool SwarmCursorFenceCursor::Advance(int64_t next)
{
    if (SwarmCursorFenceClassify(m_cursor, next) != SwarmCursorFenceMove::Exact) return false;
    m_cursor = next;
    return true;
}

} // namespace modelnet
