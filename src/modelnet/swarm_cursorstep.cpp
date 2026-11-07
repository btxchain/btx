// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorstep.h>

namespace modelnet {

bool SwarmCursorStep::Advance(uint64_t next, std::string& err)
{
    if (next <= m_cursor) {
        err = "STALE";
        return false;
    }
    // next is strictly ahead, so next - 1 does not wrap. A step other
    // than exactly one is a gap and leaves the cursor.
    if (next - 1 != m_cursor) {
        err = "GAP";
        return false;
    }
    m_cursor = next;
    err.clear();
    return true;
}

uint64_t SwarmCursorStep::cursor() const
{
    return m_cursor;
}

} // namespace modelnet
