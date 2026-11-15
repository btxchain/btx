// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/arm.h>

namespace modelnet {

void SwarmFaultSeqArmJournal(SwarmFaultJournal& journal, int64_t earned)
{
    journal.Arm(earned, true, true, true);
}

} // namespace modelnet
