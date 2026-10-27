// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlease.h>

#include <string>

namespace modelnet {

SwarmNotLeaseResult SwarmNoteNotLease(const SwarmNotLease& note, std::string& err)
{
    SwarmNotLeaseResult result;
    result.replaced = false;
    // A replacement coordinator starting during lease expiry has not been injected.
    if (note.lease_id.empty()) {
        result.code = "LEASE";
        result.replaced = false;
        err = "LEASE";
        return result;
    }
    if (note.want_replace) {
        result.code = "NOT_INJECTED";
        result.replaced = false;
        err = "NOT_INJECTED";
        return result;
    }
    result.code = "NOTED";
    result.replaced = false;
    err.clear();
    return result;
}

} // namespace modelnet
