// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/refusal.h>

namespace modelnet {

void SwarmFaultSeqRefusal::Clear()
{
    m_latched = false;
    m_last_applied = false;
}

void SwarmFaultSeqRefusal::NoteApplied()
{
    m_last_applied = true;
}

void SwarmFaultSeqRefusal::NoteRefused()
{
    m_latched = true;
    m_last_applied = false;
}

void SwarmFaultSeqRefusal::NoteDone()
{
    m_last_applied = false;
}

bool SwarmFaultSeqRefusal::latched() const
{
    return m_latched;
}

bool SwarmFaultSeqRefusal::last_applied() const
{
    return m_last_applied;
}

} // namespace modelnet
