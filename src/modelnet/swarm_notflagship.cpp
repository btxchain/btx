// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notflagship.h>

#include <string>

namespace modelnet {

SwarmNotFlagshipResult SwarmNoteNotFlagship(const SwarmNotFlagship& note, std::string& err)
{
    SwarmNotFlagshipResult result;
    result.passed = false;
    if (note.stage_id.empty()) {
        result.code = "STAGE";
        result.passed = false;
        err = "STAGE";
        return result;
    }
    // A unit note is not a passed 13-stage flagship demo.
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
