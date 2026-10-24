// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprof.h>

#include <string>

namespace modelnet {

SwarmNotNoProfResult SwarmNoteNotNoProf(const SwarmNotNoProf& note, std::string& err)
{
    SwarmNotNoProfResult result;
    result.changed = false;
    result.launched = false;
    // The launch profile stays fixed.
    if (note.profile_id.empty()) {
        result.code = "PROFILE";
        result.changed = false;
        result.launched = false;
        err = "PROFILE";
        return result;
    }
    if (note.profile_id != "BTX035-LAUNCH-DECODER-2x64") {
        result.code = "FIXED";
        result.changed = false;
        result.launched = false;
        err = "FIXED";
        return result;
    }
    if (note.want_change) {
        result.code = "FIXED";
        result.changed = false;
        result.launched = false;
        err = "FIXED";
        return result;
    }
    result.code = "NOTED";
    result.changed = false;
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
