// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FIRSTCLTV_H
#define BTX_MODELNET_SWARM_FIRSTCLTV_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmFirstCltv {
    std::string edge_id;
    bool first_edge{false};
    bool want_add{false};
};

struct SwarmFirstCltvResult {
    std::string code;
    bool added{false};
    int64_t delay{0};
};

// The sender's first edge adds no CLTV.
SwarmFirstCltvResult SwarmNoteFirstCltv(const SwarmFirstCltv& edge, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FIRSTCLTV_H
