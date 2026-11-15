// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowear.h>

#include <string>

namespace modelnet {

SwarmNotNoWearResult SwarmNoteNotNoWear(const SwarmNotNoWear& note, std::string& err)
{
    SwarmNotNoWearResult result;
    result.claimed = false;
    result.hours = 0;
    // This note publishes no wear hours.
    if (note.device_id.empty()) {
        result.code = "DEVICE";
        result.claimed = false;
        result.hours = 0;
        err = "DEVICE";
        return result;
    }
    if (note.want_claim) {
        result.code = "UNMEASURED";
        result.claimed = false;
        result.hours = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.claimed = false;
    result.hours = 0;
    err.clear();
    return result;
}

} // namespace modelnet
