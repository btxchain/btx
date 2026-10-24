// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notschedwit.h>

#include <string>

namespace modelnet {

SwarmNotSchedWitResult SwarmNoteNotSchedWit(const SwarmNotSchedWit& note, std::string& err)
{
    SwarmNotSchedWitResult result;
    result.signed_witness = false;
    result.broadcast = false;
    // The scheduler does not sign a funding witness.
    if (note.scheduler_id.empty()) {
        result.code = "SCHEDULER";
        result.signed_witness = false;
        result.broadcast = false;
        err = "SCHEDULER";
        return result;
    }
    if (note.want_sign) {
        result.code = "NO_WITNESS";
        result.signed_witness = false;
        result.broadcast = false;
        err = "NO_WITNESS";
        return result;
    }
    result.code = "NOTED";
    result.signed_witness = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
