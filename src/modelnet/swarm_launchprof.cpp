// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof.h>

namespace modelnet {

SwarmLaunchProfResult SwarmNoteLaunchProf(const SwarmLaunchProf& note, std::string& err)
{
    SwarmLaunchProfResult result;
    result.changed = false;
    if (note.profile.empty()) {
        result.code = "PROFILE";
        result.changed = false;
        err = "PROFILE";
        return result;
    }
    // The only accepted profile is fixed. Do not launch training.
    if (note.profile != "BTX035-LAUNCH-DECODER-2x64") {
        result.code = "FIXED";
        result.changed = false;
        err = "FIXED";
        return result;
    }
    if (note.want_change) {
        result.code = "HELD";
        result.changed = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.changed = false;
    err.clear();
    return result;
}

} // namespace modelnet
