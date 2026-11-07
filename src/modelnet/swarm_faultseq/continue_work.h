// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_CONTINUE_WORK_H
#define BTX_MODELNET_SWARM_FAULTSEQ_CONTINUE_WORK_H

#include <cstdint>

namespace modelnet {

/**
 * True only after a successful step that has not been refused, when the hold
 * is idle, bytes_moved is 0, and earned still equals the armed value.
 * The predicate does not mine, spend, or broadcast.
 */
bool SwarmFaultSeqMayContinue(bool begun,
                              bool latched,
                              bool last_applied,
                              bool hold_idle,
                              int64_t observed_earned,
                              int64_t armed_earned,
                              int64_t bytes_moved);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_CONTINUE_WORK_H
