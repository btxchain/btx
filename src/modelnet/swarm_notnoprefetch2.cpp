// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprefetch2.h>

#include <string>

namespace modelnet {

SwarmNotNoPrefetch2Result SwarmNoteNotNoPrefetch2(const SwarmNotNoPrefetch2& note, std::string& err)
{
    SwarmNotNoPrefetch2Result result;
    result.moved = false;
    result.bytes_moved = false;
    // A prefetch note moves no bytes.
    if (note.transfer_id.empty()) {
        result.code = "TRANSFER";
        result.moved = false;
        result.bytes_moved = false;
        err = "TRANSFER";
        return result;
    }
    if (note.want_prefetch) {
        result.code = "HELD";
        result.moved = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
