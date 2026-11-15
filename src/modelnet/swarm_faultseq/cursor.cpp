// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/cursor.h>

#include <modelnet/swarm_faultseq/limits.h>

namespace modelnet {

void SwarmFaultSeqCursor::Reset()
{
    m_next = kSwarmFaultSeqFirst;
    m_last = 0;
    m_took_last = false;
}

bool SwarmFaultSeqCursor::past_end() const
{
    return m_next > kSwarmFaultSeqLast;
}

bool SwarmFaultSeqCursor::took_last() const
{
    return m_took_last;
}

int SwarmFaultSeqCursor::next() const
{
    return m_next;
}

int SwarmFaultSeqCursor::last() const
{
    return m_last;
}

int SwarmFaultSeqCursor::Take()
{
    if (past_end()) return 0;
    const int fault = m_next;
    ++m_next;
    m_last = fault;
    if (fault == kSwarmFaultSeqLast) m_took_last = true;
    return fault;
}

} // namespace modelnet
