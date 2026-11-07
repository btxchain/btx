// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfsdp.h>

#include <string>

namespace modelnet {

SwarmNotFsdpResult SwarmNoteNotFsdp(const SwarmNotFsdp& note, std::string& err)
{
    SwarmNotFsdpResult result;
    result.distributed = false;
    // One local step is not FSDP and is not distributed training.
    if (note.node_id.empty()) {
        result.code = "TRAIN";
        result.distributed = false;
        err = "TRAIN";
        return result;
    }
    if (note.want_fsdp) {
        result.code = "NOT_DISTRIBUTED";
        result.distributed = false;
        err = "NOT_DISTRIBUTED";
        return result;
    }
    result.code = "NOTED";
    result.distributed = false;
    err.clear();
    return result;
}

} // namespace modelnet
