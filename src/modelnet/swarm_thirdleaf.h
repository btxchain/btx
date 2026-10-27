// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_THIRDLEAF_H
#define BITCOIN_MODELNET_SWARM_THIRDLEAF_H

#include <string>

namespace modelnet {

struct SwarmThirdLeaf {
    std::string tx_id;
    bool want_build{false};
};

struct SwarmThirdLeafResult {
    std::string code;
    bool built{false};
};

SwarmThirdLeafResult SwarmNoteThirdLeaf(const SwarmThirdLeaf& tx, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_THIRDLEAF_H
