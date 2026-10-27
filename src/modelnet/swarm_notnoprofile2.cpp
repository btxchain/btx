// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprofile2.h>

#include <string>

namespace modelnet {

SwarmNotNoProfile2Result SwarmNoteNotNoProfile2(const SwarmNotNoProfile2& note, std::string& err)
{
    SwarmNotNoProfile2Result result;
    result.changed = false;
    // The launch profile stays BTX035-LAUNCH-DECODER-2x64.
    if (note.profile_id.empty()) {
        result.code = "PROFILE";
        result.changed = false;
        err = "PROFILE";
        return result;
    }
    if (note.want_change) {
        result.code = "HELD";
        result.changed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.changed = false;
    err.clear();
    return result;
}

} // namespace modelnet
