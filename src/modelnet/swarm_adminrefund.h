// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINREFUND_H
#define BITCOIN_MODELNET_SWARM_ADMINREFUND_H

#include <string>

namespace modelnet {

struct SwarmAdminRefund {
    std::string channel_id;
    bool admin;
    bool want_move;
};

struct SwarmAdminRefundResult {
    std::string code;
    bool moved;
};

SwarmAdminRefundResult SwarmNoteAdminRefund(const SwarmAdminRefund& channel, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINREFUND_H
