// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolease.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoLeaseResult SwarmNoteNotNoLease(const SwarmNotNoLease& note, std::string& err)
{
    SwarmNotNoLeaseResult result;
    result.spent = false;
    result.atoms = 0;
    // Lease expiry does not spend.
    if (note.lease_id.empty()) {
        result.code = "LEASE";
        result.spent = false;
        result.atoms = 0;
        err = "LEASE";
        return result;
    }
    if (note.expired) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
