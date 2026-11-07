// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NONSIGNER_H
#define BITCOIN_MODELNET_SWARM_NONSIGNER_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmNonSigner {
    std::string claim_id;
    bool signer;
    bool want_claim;
};

struct SwarmNonSignerResult {
    std::string code;
    bool claimed;
    int64_t atoms;
};

SwarmNonSignerResult SwarmNoteNonSigner(const SwarmNonSigner& claim, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NONSIGNER_H
