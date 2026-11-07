// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notacquire.h>

#include <string>

namespace modelnet {

SwarmNotAcquireResult SwarmNoteNotAcquire(const SwarmNotAcquire& note, std::string& err)
{
    SwarmNotAcquireResult result;
    result.verified = false;
    if (note.artifact_id.empty()) {
        result.code = "ARTIFACT";
        result.verified = false;
        err = "ARTIFACT";
        return result;
    }
    // No node has verified an openly licensed model artifact from this note.
    if (note.want_verify) {
        result.code = "UNVERIFIED";
        result.verified = false;
        err = "UNVERIFIED";
        return result;
    }
    result.code = "NOTED";
    result.verified = false;
    err.clear();
    return result;
}

} // namespace modelnet
