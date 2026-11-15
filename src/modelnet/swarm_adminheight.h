// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHEIGHT_H
#define BITCOIN_MODELNET_SWARM_ADMINHEIGHT_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmAdminHeight {
    std::string channel_id;
    int64_t height;
    bool admin;
    bool want_move;
};

struct SwarmAdminHeightResult {
    std::string code;
    bool moved;
    int64_t height;
};

SwarmAdminHeightResult SwarmNoteAdminHeight(const SwarmAdminHeight& height, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHEIGHT_H
