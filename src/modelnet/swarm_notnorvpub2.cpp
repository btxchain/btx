// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorvpub2.h>

#include <string>

namespace modelnet {

SwarmNotNoRvPub2Result SwarmNoteNotNoRvPub2(const SwarmNotNoRvPub2& note, std::string& err)
{
    SwarmNotNoRvPub2Result result;
    result.opened = false;
    // A public rendezvous opens no socket.
    if (note.rendezvous_id.empty()) {
        result.code = "RENDEZVOUS";
        result.opened = false;
        err = "RENDEZVOUS";
        return result;
    }
    if (note.want_open) {
        result.code = "HELD";
        result.opened = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
