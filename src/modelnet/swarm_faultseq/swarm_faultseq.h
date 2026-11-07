// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_H
#define BTX_MODELNET_SWARM_FAULTSEQ_H

#include <modelnet/swarm_faultjournal.h>
#include <modelnet/swarm_faultseq/cursor.h>
#include <modelnet/swarm_faultseq/hold.h>
#include <modelnet/swarm_faultseq/record.h>
#include <modelnet/swarm_faultseq/refusal.h>
#include <modelnet/swarm_faultseq/status.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Drives SwarmFaultJournal through faults 1 through 20.
 *
 * Begin stores earned and arms checkpoint, payment plane, and durable.
 * Step calls Apply for the next in-range fault and records the journal code.
 * After a successful Apply, earned atoms stay at the armed value and bytes
 * moved stay 0. Step past 20 returns Done and does not call Apply.
 * When Apply returns false, Step returns Failed, err is the journal code,
 * earned is not changed, and ContinueWork stays false until Restart.
 * ContinueWork does not mine, spend, or broadcast. Restart keeps the same
 * earned value and runs only after fault 20 or after a refusal.
 *
 * This is not a live GPU injection and does not claim one.
 */
class SwarmFaultSequence {
public:
    void Begin(int64_t earned);
    SwarmFaultSeqStep Step(std::string& err);
    bool ContinueWork() const;
    bool Restart();

    int64_t earned_atoms() const { return m_journal.earned_atoms(); }
    int64_t armed_earned() const { return m_earned; }
    int64_t bytes_moved() const { return m_journal.bytes_moved(); }
    const std::string& code() const { return m_record.last(); }
    const std::vector<std::string>& codes() const { return m_record.codes(); }
    int next_fault() const { return m_cursor.next(); }
    int last_fault() const { return m_cursor.last(); }
    bool refused() const { return m_refusal.latched(); }
    bool finished() const { return m_cursor.took_last(); }
    bool begun() const { return m_begun; }
    const SwarmFaultJournal& journal() const { return m_journal; }

    bool live_gpu_injection() const { return m_hold.live_gpu; }
    bool mined() const { return m_hold.mined; }
    bool spent() const { return m_hold.spent; }
    bool broadcast() const { return m_hold.broadcast; }

private:
    SwarmFaultJournal m_journal;
    SwarmFaultSeqCursor m_cursor;
    SwarmFaultSeqRefusal m_refusal;
    SwarmFaultSeqRecord m_record;
    SwarmFaultSeqHold m_hold{SwarmFaultSeqHold::Idle()};
    int64_t m_earned{0};
    bool m_begun{false};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_H
