// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/continue_work.h>

namespace modelnet {

bool SwarmFaultSeqMayContinue(bool begun,
                              bool latched,
                              bool last_applied,
                              bool hold_idle,
                              int64_t observed_earned,
                              int64_t armed_earned,
                              int64_t bytes_moved)
{
    if (!begun || latched || !last_applied || !hold_idle) return false;
    return observed_earned == armed_earned && bytes_moved == 0;
}

} // namespace modelnet
