// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminheight.h>

#include <string>

namespace modelnet {

SwarmAdminHeightResult SwarmNoteAdminHeight(const SwarmAdminHeight& height, std::string& err)
{
    SwarmAdminHeightResult result;
    result.moved = false;
    result.height = 0;
    // An admin does not move the sponsor refund height.
    if (!height.channel_id.empty() && height.height >= 0) {
        result.height = height.height;
    }
    if (height.channel_id.empty()) {
        result.code = "CHANNEL";
        result.moved = false;
        result.height = 0;
        err = "CHANNEL";
        return result;
    }
    if (height.height < 0) {
        result.code = "RANGE";
        result.moved = false;
        result.height = 0;
        err = "RANGE";
        return result;
    }
    if (height.admin) {
        result.code = "HELD";
        result.moved = false;
        err = "HELD";
        return result;
    }
    if (height.want_move) {
        result.code = "HELD";
        result.moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
