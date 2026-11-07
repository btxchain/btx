// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/swarm_faultseq.h>

#include <modelnet/swarm_faultseq/apply.h>
#include <modelnet/swarm_faultseq/arm.h>
#include <modelnet/swarm_faultseq/continue_work.h>
#include <modelnet/swarm_faultseq/limits.h>
#include <modelnet/swarm_faultseq/restart.h>

namespace modelnet {

void SwarmFaultSequence::Begin(int64_t earned)
{
    m_earned = earned;
    SwarmFaultSeqArmJournal(m_journal, m_earned);
    m_record.Clear();
    m_cursor.Reset();
    m_refusal.Clear();
    m_hold = SwarmFaultSeqHold::Idle();
    m_begun = true;
}

SwarmFaultSeqStep SwarmFaultSequence::Step(std::string& err)
{
    if (!m_begun) {
        err = "BEGIN";
        return SwarmFaultSeqStep::Failed;
    }
    if (m_cursor.past_end()) {
        err = kSwarmFaultSeqDone;
        m_refusal.NoteDone();
        return SwarmFaultSeqStep::Done;
    }

    const int fault = m_cursor.Take();
    const SwarmFaultSeqApplyResult applied = SwarmFaultSeqApply(m_journal, fault);
    m_record.Add(applied.code);
    if (applied.status != SwarmFaultSeqStep::Applied) {
        m_refusal.NoteRefused();
        err = applied.err;
        return SwarmFaultSeqStep::Failed;
    }
    m_refusal.NoteApplied();
    err = applied.code;
    return SwarmFaultSeqStep::Applied;
}

bool SwarmFaultSequence::ContinueWork() const
{
    return SwarmFaultSeqMayContinue(m_begun,
                                    m_refusal.latched(),
                                    m_refusal.last_applied(),
                                    m_hold.allows_work(),
                                    m_journal.earned_atoms(),
                                    m_earned,
                                    m_journal.bytes_moved());
}

bool SwarmFaultSequence::Restart()
{
    if (!m_begun) return false;
    if (!SwarmFaultSeqCanRestart(m_cursor.took_last(), m_refusal.latched())) return false;
    const int64_t earned = m_earned;
    SwarmFaultSeqArmJournal(m_journal, earned);
    m_record.Clear();
    m_cursor.Reset();
    m_refusal.Clear();
    m_hold = SwarmFaultSeqHold::Idle();
    return true;
}

} // namespace modelnet
