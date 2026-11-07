// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnetbytes.h>

namespace modelnet {

SwarmNotNetBytesResult SwarmNoteNotNetBytes(const SwarmNotNetBytes& note, std::string& err)
{
    SwarmNotNetBytesResult result;
    result.published = false;
    result.bytes_moved = false;
    result.nbytes = 0;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.published = false;
        result.bytes_moved = false;
        result.nbytes = 0;
        err = "PEER";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.bytes_moved = false;
        result.nbytes = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    result.nbytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
