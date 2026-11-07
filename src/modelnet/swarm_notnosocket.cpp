// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosocket.h>

#include <string>

namespace modelnet {

SwarmNotNoSocketResult SwarmNoteNotNoSocket(const SwarmNotNoSocket& note, std::string& err)
{
    // A public rendezvous opens no socket and moves no bytes.
    SwarmNotNoSocketResult result;
    result.opened = false;
    result.bytes_moved = false;
    if (note.rendezvous_id.empty()) {
        result.code = "RENDEZVOUS";
        result.opened = false;
        result.bytes_moved = false;
        err = "RENDEZVOUS";
        return result;
    }
    if (note.want_open) {
        result.code = "NO_SOCKET";
        result.opened = false;
        result.bytes_moved = false;
        err = "NO_SOCKET";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
