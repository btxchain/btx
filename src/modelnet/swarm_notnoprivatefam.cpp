// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivatefam.h>

#include <string>

namespace modelnet {

SwarmNotNoPrivateFamResult SwarmNoteNotNoPrivateFam(const SwarmNotNoPrivateFam& note, std::string& err)
{
    SwarmNotNoPrivateFamResult result;
    result.published = false;
    result.bytes_moved = false;
    // Discovery does not publish a private family and moves no bytes.
    if (note.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        result.bytes_moved = false;
        err = "FAMILY";
        return result;
    }
    if (note.private_family) {
        result.code = "REFUSED";
        result.published = false;
        result.bytes_moved = false;
        err = "REFUSED";
        return result;
    }
    if (note.want_publish) {
        result.code = "REFUSED";
        result.published = false;
        result.bytes_moved = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
