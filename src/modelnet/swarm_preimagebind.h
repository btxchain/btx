// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PREIMAGEBIND_H
#define BITCOIN_MODELNET_SWARM_PREIMAGEBIND_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmPreimageBind {
    std::string claim_id;
    int64_t length;
    bool signer;
    bool want_claim;
};

struct SwarmPreimageBindResult {
    std::string code;
    bool claimed;
    int64_t atoms;
};

SwarmPreimageBindResult SwarmBindPreimageLocal(const SwarmPreimageBind& bind, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PREIMAGEBIND_H
