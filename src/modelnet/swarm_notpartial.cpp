// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpartial.h>

#include <string>

namespace modelnet {

SwarmNotPartialResult SwarmNoteNotPartial(const SwarmNotPartial& note, std::string& err)
{
    SwarmNotPartialResult result;
    result.accepted = false;
    result.bytes_moved = false;
    if (note.artifact_id.empty()) {
        result.code = "ARTIFACT";
        result.accepted = false;
        result.bytes_moved = false;
        err = "ARTIFACT";
        return result;
    }
    // A partially transferred model artifact has not been shown.
    if (note.want_accept) {
        result.code = "NOT_SHOWN";
        result.accepted = false;
        result.bytes_moved = false;
        err = "NOT_SHOWN";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
