// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonatpub2.h>

#include <string>

namespace modelnet {

SwarmNotNoNatPub2Result SwarmNoteNotNoNatPub2(const SwarmNotNoNatPub2& note, std::string& err)
{
    SwarmNotNoNatPub2Result result;
    result.published = false;
    // NAT traversal publishes no address.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.published = false;
        err = "NODE";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
