// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SCHEDWIT_H
#define BTX_MODELNET_SWARM_SCHEDWIT_H

#include <string>

namespace modelnet {

struct SwarmSchedWit {
    std::string witness_id;
    bool scheduler{false};
    bool want_sign{false};
};

struct SwarmSchedWitResult {
    std::string code;
    bool signed_ok{false};
};

SwarmSchedWitResult SwarmNoteSchedWitness(const SwarmSchedWit& witness, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SCHEDWIT_H
