// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESEP_H
#define BITCOIN_MODELNET_SWARM_NICHESEP_H

#include <string>

namespace modelnet {

struct SwarmNicheSep {
    std::string niche_id;
    std::string other_id;
    bool want_merge;
};

struct SwarmNicheSepResult {
    std::string code;
    bool merged;
};

SwarmNicheSepResult SwarmKeepNiches(const SwarmNicheSep& niche, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESEP_H
