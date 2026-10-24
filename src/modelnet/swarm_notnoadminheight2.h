// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTNOADMINHEIGHT2_H
#define BITCOIN_MODELNET_SWARM_NOTNOADMINHEIGHT2_H

#include <string>

namespace modelnet {

struct SwarmNotNoAdminHeight2 {
    std::string admin_id;
    bool want_move{false};
};

struct SwarmNotNoAdminHeight2Result {
    std::string code;
    bool moved{false};
};

SwarmNotNoAdminHeight2Result SwarmNoteNotNoAdminHeight2(const SwarmNotNoAdminHeight2& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTNOADMINHEIGHT2_H
