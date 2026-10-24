// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_REFUSAL_H
#define BTX_MODELNET_SWARM_FAULTSEQ_REFUSAL_H

namespace modelnet {

/**
 * A failed Apply latches continuation off. A later successful Apply does not
 * clear the latch. Clear runs from Begin and from Restart.
 */
class SwarmFaultSeqRefusal {
public:
    void Clear();
    void NoteApplied();
    void NoteRefused();
    void NoteDone();
    bool latched() const;
    bool last_applied() const;

private:
    bool m_latched{false};
    bool m_last_applied{false};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_REFUSAL_H
