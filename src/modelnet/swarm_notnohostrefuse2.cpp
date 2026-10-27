// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohostrefuse2.h>

#include <string>

namespace modelnet {

SwarmNotNoHostRefuse2Result SwarmNoteNotNoHostRefuse2(const SwarmNotNoHostRefuse2& note, std::string& err)
{
    SwarmNotNoHostRefuse2Result result;
    result.accepted = false;
    // A note that names an operator host is refused.
    if (note.note_id.empty()) {
        result.code = "NOTE";
        result.accepted = false;
        err = "NOTE";
        return result;
    }
    if (note.names_host) {
        result.code = "REFUSED";
        result.accepted = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
