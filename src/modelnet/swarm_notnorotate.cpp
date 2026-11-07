// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorotate.h>

#include <string>

namespace modelnet {

SwarmNotNoRotateResult SwarmNoteNotNoRotate(const SwarmNotNoRotate& note, std::string& err)
{
    SwarmNotNoRotateResult result;
    result.rotated = false;
    result.broadcast = false;
    // This note rotates no key and broadcasts nothing.
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.rotated = false;
        result.broadcast = false;
        err = "KEY";
        return result;
    }
    if (note.want_rotate) {
        result.code = "REFUSED";
        result.rotated = false;
        result.broadcast = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.rotated = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
