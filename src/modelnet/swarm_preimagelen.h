// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PREIMAGELEN_H
#define BITCOIN_MODELNET_SWARM_PREIMAGELEN_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmPreimageLen {
    std::string claim_id;
    int64_t length;
    bool want_claim;
};

struct SwarmPreimageLenResult {
    std::string code;
    bool claimed;
    int64_t atoms;
};

SwarmPreimageLenResult SwarmNotePreimageLength(const SwarmPreimageLen& claim, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PREIMAGELEN_H
