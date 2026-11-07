// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_community.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmCommunityResult SwarmNoteCommunity(const SwarmCommunity& community, std::string& err)
{
    SwarmCommunityResult result;

    if (community.pool_id.empty() || community.other_active < 0) {
        result.continues = false;
        result.stopped = false;
        result.code = "POOL";
        err = "POOL";
        return result;
    }

    // A stop request holds the note. It does not stop the community.
    if (community.want_stop) {
        result.continues = community.other_active > 0;
        result.stopped = false;
        result.code = "HELD";
        err.clear();
        return result;
    }

    if (community.other_active == 0) {
        result.continues = false;
        result.stopped = false;
        result.code = "ALONE";
        err = "ALONE";
        return result;
    }

    result.continues = true;
    result.stopped = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
