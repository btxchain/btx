// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohostname.h>

#include <string>

namespace modelnet {

SwarmNotNoHostnameResult SwarmNoteNotNoHostname(const SwarmNotNoHostname& note, std::string& err)
{
    SwarmNotNoHostnameResult result;
    result.published = false;
    result.bytes_moved = false;
    // A note that names an operator host is refused.
    if (note.note_id.empty()) {
        result.code = "NOTE";
        result.published = false;
        result.bytes_moved = false;
        err = "NOTE";
        return result;
    }
    if (note.names_host) {
        result.code = "REFUSED";
        result.published = false;
        result.bytes_moved = false;
        err = "REFUSED";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
