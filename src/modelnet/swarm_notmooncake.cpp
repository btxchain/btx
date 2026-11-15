// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmooncake.h>

#include <string>

namespace modelnet {

SwarmNotMooncakeResult SwarmNoteNotMooncake(const SwarmNotMooncake& note, std::string& err)
{
    SwarmNotMooncakeResult result;
    result.bytes_moved = false;
    // Mooncake is not installed, so this note does not transfer.
    if (note.page_id.empty()) {
        result.code = "MOONCAKE";
        result.bytes_moved = false;
        err = "MOONCAKE";
        return result;
    }
    // Absent Mooncake refuses the note even when the caller asked to transfer.
    if (!note.mooncake_present) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    // Present Mooncake still moves no bytes from this note.
    if (note.want_transfer) {
        result.code = "HELD";
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
