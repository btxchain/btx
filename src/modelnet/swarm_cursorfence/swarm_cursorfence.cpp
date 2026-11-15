// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/swarm_cursorfence.h>

#include <modelnet/swarm_cursorfence/advance.h>
#include <modelnet/swarm_cursorfence/commit.h>
#include <modelnet/swarm_cursorfence/mine.h>

namespace modelnet {

bool SwarmCursorFence::Advance(int64_t next, std::string& err)
{
    return SwarmCursorFenceAdvance(m_cursor, next, err);
}

bool SwarmCursorFence::Commit(int64_t step, const std::string& hash, std::string& err)
{
    return SwarmCursorFenceCommit(m_cursor, m_ledger, step, hash, err);
}

bool SwarmCursorFence::Mine(std::string& err)
{
    return SwarmCursorFenceMine(err);
}

int64_t SwarmCursorFence::cursor() const
{
    return m_cursor.cursor();
}

bool SwarmCursorFence::committed(int64_t step) const
{
    return m_ledger.stored(step);
}

std::string SwarmCursorFence::hash_at(int64_t step) const
{
    return m_ledger.hash_at(step);
}

int64_t SwarmCursorFence::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmCursorFence::mined() const
{
    return m_quiet.mined();
}

int64_t SwarmCursorFence::blocks() const
{
    return m_quiet.blocks();
}

} // namespace modelnet
