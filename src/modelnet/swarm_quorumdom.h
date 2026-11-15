// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUORUMDOM_H
#define BITCOIN_MODELNET_SWARM_QUORUMDOM_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmQuorumDom {
    std::string vote_id;
    int64_t evaluators;
    int64_t domains;
    bool same_domain;
    bool want_count;
};

struct SwarmQuorumDomResult {
    std::string code;
    bool counted;
};

SwarmQuorumDomResult SwarmNoteQuorumDomain(const SwarmQuorumDom& vote, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUORUMDOM_H
