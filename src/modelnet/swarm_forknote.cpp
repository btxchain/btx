// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forknote.h>

namespace modelnet {

SwarmForkNoteResult SwarmNoteFork(const SwarmForkNote& note, std::string& err)
{
    SwarmForkNoteResult result;
    result.averaged = false;
    if (note.left_id.empty() || note.right_id.empty() || note.left_digest.empty() || note.right_digest.empty()) {
        result.code = "FORK";
        err = "FORK";
        return result;
    }
    if (note.want_average) {
        result.code = "AVERAGE_REFUSED";
        err = "AVERAGE_REFUSED";
        return result;
    }
    if (note.left_digest != note.right_digest) {
        result.code = "DIVERGED";
        err.clear();
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
