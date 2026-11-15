// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTNOTHIRDLEAF2_H
#define BITCOIN_MODELNET_SWARM_NOTNOTHIRDLEAF2_H

#include <string>

namespace modelnet {

struct SwarmNotNoThirdLeaf2 {
    std::string tx_id;
    bool want_build{false};
};

struct SwarmNotNoThirdLeaf2Result {
    std::string code;
    bool built{false};
};

SwarmNotNoThirdLeaf2Result SwarmNoteNotNoThirdLeaf2(const SwarmNotNoThirdLeaf2& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTNOTHIRDLEAF2_H
