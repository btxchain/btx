// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_APPLY_H
#define BTX_MODELNET_SWARM_FAULTSEQ_APPLY_H

#include <modelnet/swarm_faultjournal.h>
#include <modelnet/swarm_faultseq/status.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One journal Apply. Faults outside 1..20 do not call Apply.
 * This does not reimplement the twenty faults and does not inject a live GPU fault.
 */
struct SwarmFaultSeqApplyResult {
    SwarmFaultSeqStep status{SwarmFaultSeqStep::Failed};
    bool called{false};
    bool held{false};
    int64_t earned{0};
    int64_t bytes{0};
    std::string code;
    std::string err;
};

SwarmFaultSeqApplyResult SwarmFaultSeqApply(SwarmFaultJournal& journal, int fault);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_APPLY_H
