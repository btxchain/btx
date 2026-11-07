// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprofile.h>

#include <string>

namespace modelnet {

SwarmNotProfileResult SwarmNoteNotProfile(const SwarmNotProfile& note, std::string& err)
{
    SwarmNotProfileResult result;
    result.changed = false;
    // The launch profile stays BTX035-LAUNCH-DECODER-2x64.
    if (note.profile_id.empty()) {
        result.code = "PROFILE";
        result.changed = false;
        err = "PROFILE";
        return result;
    }
    if (note.profile_id != "BTX035-LAUNCH-DECODER-2x64") {
        result.code = "FIXED";
        result.changed = false;
        err = "FIXED";
        return result;
    }
    if (note.want_change) {
        result.code = "FIXED";
        result.changed = false;
        err = "FIXED";
        return result;
    }
    result.code = "NOTED";
    result.changed = false;
    err.clear();
    return result;
}

} // namespace modelnet
