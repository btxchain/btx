// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_STATUS_H
#define BTX_MODELNET_SWARM_FAULTSEQ_STATUS_H

namespace modelnet {

/**
 * Result of one SwarmFaultSequence::Step.
 * Failed: Apply returned false. Done: fault 20 is already done, Apply was not called.
 * Applied: Apply returned true.
 */
enum class SwarmFaultSeqStep {
    Failed,
    Applied,
    Done,
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_STATUS_H
