// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORVPUB2_H
#define BTX_MODELNET_SWARM_NOTNORVPUB2_H

#include <string>

namespace modelnet {

struct SwarmNotNoRvPub2 {
    std::string rendezvous_id;
    bool want_open{false};
};

struct SwarmNotNoRvPub2Result {
    std::string code;
    bool opened{false};
};

SwarmNotNoRvPub2Result SwarmNoteNotNoRvPub2(const SwarmNotNoRvPub2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORVPUB2_H
