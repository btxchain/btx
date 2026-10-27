// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocanaryreg.h>

#include <string>

namespace modelnet {

SwarmNotNoCanaryRegResult SwarmNoteNotNoCanaryReg(const SwarmNotNoCanaryReg& note, std::string& err)
{
    SwarmNotNoCanaryRegResult result;
    result.published = false;
    result.admitted = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.admitted = false;
        err = "RUN";
        return result;
    }
    // A canary regression is not published and is not admitted.
    if (note.regression) {
        result.code = "CANARY";
        result.published = false;
        result.admitted = false;
        err = "CANARY";
        return result;
    }
    if (note.want_publish) {
        result.code = "BLOCK";
        result.published = false;
        result.admitted = false;
        err = "BLOCK";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
