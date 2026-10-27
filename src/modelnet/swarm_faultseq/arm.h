// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_ARM_H
#define BTX_MODELNET_SWARM_FAULTSEQ_ARM_H

#include <modelnet/swarm_faultjournal.h>

#include <cstdint>

namespace modelnet {

/**
 * Arms the journal with checkpoint, payment plane, and durable all true.
 * Stores earned. Does not apply a fault and does not inject a live GPU fault.
 */
void SwarmFaultSeqArmJournal(SwarmFaultJournal& journal, int64_t earned);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_ARM_H
