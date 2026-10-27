// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopinpub.h>

#include <string>

namespace modelnet {

SwarmNotNoPinPubResult SwarmNoteNotNoPinPub(const SwarmNotNoPinPub& note, std::string& err)
{
    SwarmNotNoPinPubResult result;
    result.published = false;
    result.authority = false;
    // Pin membership is not a public seed authority.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.published = false;
        result.authority = false;
        err = "NODE";
        return result;
    }
    if (note.pin_member) {
        result.code = "NOT_AUTHORITY";
        result.published = false;
        result.authority = false;
        err = "NOT_AUTHORITY";
        return result;
    }
    if (note.want_publish) {
        result.code = "NOT_AUTHORITY";
        result.published = false;
        result.authority = false;
        err = "NOT_AUTHORITY";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.authority = false;
    err.clear();
    return result;
}

} // namespace modelnet
