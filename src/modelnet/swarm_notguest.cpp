// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notguest.h>

#include <string>

namespace modelnet {

SwarmNotGuestResult SwarmNoteNotGuest(const SwarmNotGuest& note, std::string& err)
{
    SwarmNotGuestResult result;
    result.passed = false;
    if (note.guest_id.empty()) {
        result.code = "GUEST";
        result.passed = false;
        err = "GUEST";
        return result;
    }
    // A Windows guest with no login path that leaves the signer alone is not a pass.
    if (note.want_pass) {
        result.code = "UNQUALIFIED";
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
