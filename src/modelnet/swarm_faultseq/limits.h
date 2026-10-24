// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_LIMITS_H
#define BTX_MODELNET_SWARM_FAULTSEQ_LIMITS_H

namespace modelnet {

/** Journal faults are numbered 1 through 20. Zero and 21 are not applied. */
inline constexpr int kSwarmFaultSeqFirst = 1;
inline constexpr int kSwarmFaultSeqLast = 20;

/** Step past the last fault reports this and does not call Apply. */
inline constexpr char kSwarmFaultSeqDone[] = "DONE";

inline bool SwarmFaultSeqInRange(int fault)
{
    return fault >= kSwarmFaultSeqFirst && fault <= kSwarmFaultSeqLast;
}

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_LIMITS_H
