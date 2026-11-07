// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmoonabs.h>

#include <string>

namespace modelnet {

SwarmNotMoonAbsResult SwarmNoteNotMoonAbs(const SwarmNotMoonAbs& note, std::string& err)
{
    SwarmNotMoonAbsResult result;
    result.moved = false;
    result.bytes_moved = false;
    // Missing Mooncake moves no bytes.
    if (note.adapter_id.empty()) {
        result.code = "ADAPTER";
        result.moved = false;
        result.bytes_moved = false;
        err = "ADAPTER";
        return result;
    }
    if (note.want_move) {
        result.code = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
