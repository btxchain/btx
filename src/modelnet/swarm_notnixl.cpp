// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnixl.h>

#include <string>

namespace modelnet {

SwarmNotNixlResult SwarmNoteNotNixl(const SwarmNotNixl& note, std::string& err)
{
    SwarmNotNixlResult result;
    result.bytes_moved = false;
    // NIXL is not installed, so this note does not transfer.
    if (note.page_id.empty()) {
        result.code = "NIXL";
        result.bytes_moved = false;
        err = "NIXL";
        return result;
    }
    if (!note.nixl_present) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
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
