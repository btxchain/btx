// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEIGHBOR_H
#define BTX_MODELNET_SWARM_NOTNONEIGHBOR_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmNotNoNeighbor {
    std::string node_id;
    int64_t low_rtt{0};
    int64_t new_domains{0};
    bool want_expand{false};
};

struct SwarmNotNoNeighborResult {
    std::string code;
    bool expanded{false};
    bool connected{false};
};

// The neighborhood cap is 4 lowest-RTT peers plus 2 new trust domains.
// This note connects none. expanded and connected stay false on every path.
// Order: empty node_id is NODE. A low_rtt other than 4 or a new_domains other
// than 2 is CAPPED, even when want_expand is false. want_expand is CAPPED.
// Otherwise the note is NOTED and err is cleared.
SwarmNotNoNeighborResult SwarmNoteNotNoNeighbor(const SwarmNotNoNeighbor& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEIGHBOR_H
