// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospecial.h>

#include <string>

namespace modelnet {

SwarmNotNoSpecialResult SwarmNoteNotNoSpecial(const SwarmNotNoSpecial& note, std::string& err)
{
    SwarmNotNoSpecialResult result;
    result.replaced = false;
    result.bytes_moved = false;
    // A specialist store leaves general/stable in place and moves no bytes.
    if (note.store_id.empty()) {
        result.code = "STORE";
        result.replaced = false;
        result.bytes_moved = false;
        err = "STORE";
        return result;
    }
    if (note.want_replace) {
        result.code = "KEPT";
        result.replaced = false;
        result.bytes_moved = false;
        err = "KEPT";
        return result;
    }
    result.code = "NOTED";
    result.replaced = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
