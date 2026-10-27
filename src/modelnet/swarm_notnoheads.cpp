// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoheads.h>

#include <string>

namespace modelnet {

SwarmNotNoHeadsResult SwarmNoteNotNoHeads(const SwarmNotNoHeads& note, std::string& err)
{
    SwarmNotNoHeadsResult result;
    result.hidden = false;
    result.bytes_moved = false;
    // Several heads stay visible. This note hides nothing and moves no bytes.
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        result.hidden = false;
        result.bytes_moved = false;
        err = "CHAIN";
        return result;
    }
    if (note.several) {
        result.code = "VISIBLE";
        result.hidden = false;
        result.bytes_moved = false;
        err = "VISIBLE";
        return result;
    }
    if (note.want_hide) {
        result.code = "HELD";
        result.hidden = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.hidden = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
