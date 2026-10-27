// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NATPUB_H
#define BTX_MODELNET_SWARM_NATPUB_H

#include <string>

namespace modelnet {

struct SwarmNatPub {
    std::string node_id;
    bool want_publish;
};

struct SwarmNatPubResult {
    std::string code;
    bool published;
};

SwarmNatPubResult SwarmNoteNatPub(const SwarmNatPub& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NATPUB_H
