// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlivefault.h>

#include <string>

namespace modelnet {

SwarmNotLiveFaultResult SwarmNoteNotLiveFault(const SwarmNotLiveFault& note, std::string& err)
{
    SwarmNotLiveFaultResult result;
    result.injected = false;
    // A code label is not a live fault injection.
    if (note.fault_id.empty()) {
        result.code = "FAULT";
        result.injected = false;
        err = "FAULT";
        return result;
    }
    if (note.want_inject) {
        result.code = "NOT_INJECTED";
        result.injected = false;
        err = "NOT_INJECTED";
        return result;
    }
    result.code = "NOTED";
    result.injected = false;
    err.clear();
    return result;
}

} // namespace modelnet
