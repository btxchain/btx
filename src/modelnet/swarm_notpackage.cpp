// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpackage.h>

namespace modelnet {

SwarmNotPackageResult SwarmNoteNotPackage(const SwarmNotPackage& note, std::string& err)
{
    SwarmNotPackageResult result;
    result.omitted = false;
    result.packaged = false;
    if (note.target_id.empty()) {
        result.code = "TARGET";
        result.omitted = false;
        result.packaged = false;
        err = "TARGET";
        return result;
    }
    // The default package must not silently omit the swarm lifecycle.
    if (note.want_omit) {
        result.code = "PRESENT";
        result.omitted = false;
        result.packaged = false;
        err = "PRESENT";
        return result;
    }
    result.code = "NOTED";
    result.omitted = false;
    result.packaged = false;
    err.clear();
    return result;
}

} // namespace modelnet
