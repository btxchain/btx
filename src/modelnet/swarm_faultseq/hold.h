// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_HOLD_H
#define BTX_MODELNET_SWARM_FAULTSEQ_HOLD_H

namespace modelnet {

/**
 * Work the sequence is not allowed to perform.
 * Continuation never mines, spends, broadcasts, or claims a live GPU injection.
 */
struct SwarmFaultSeqHold {
    bool mined{false};
    bool spent{false};
    bool broadcast{false};
    bool live_gpu{false};

    static SwarmFaultSeqHold Idle();
    bool allows_work() const;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_HOLD_H
