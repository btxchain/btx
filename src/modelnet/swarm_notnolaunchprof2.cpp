// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolaunchprof2.h>

#include <string>

namespace modelnet {

SwarmNotNoLaunchProf2Result SwarmNoteNotNoLaunchProf2(const SwarmNotNoLaunchProf2& note, std::string& err)
{
    SwarmNotNoLaunchProf2Result result;
    result.renamed = false;
    // The launch profile stays BTX035-LAUNCH-DECODER-2x64.
    if (note.profile_id.empty()) {
        result.code = "PROFILE";
        result.renamed = false;
        err = "PROFILE";
        return result;
    }
    if (note.want_rename) {
        result.code = "HELD";
        result.renamed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.renamed = false;
    err.clear();
    return result;
}

} // namespace modelnet
