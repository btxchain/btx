// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_neighbor.h>

namespace modelnet {

SwarmNeighborResult SwarmCapNeighborhood(const SwarmNeighbor& neighbor, std::string& err)
{
    // A neighborhood record stays within 4 lowest-RTT peers and 2 new trust domains. It connects nothing.
    if (neighbor.node_id.empty()) {
        err = "NODE";
        return SwarmNeighborResult{"NODE", false, 0, 0};
    }
    if (neighbor.lowest_rtt < 0 || neighbor.new_domains < 0) {
        err = "RANGE";
        return SwarmNeighborResult{"RANGE", false, 0, 0};
    }
    if (neighbor.lowest_rtt > 4 || neighbor.new_domains > 2) {
        err = "CAPPED";
        const int64_t kept_rtt = neighbor.lowest_rtt < 0 ? 0 : (neighbor.lowest_rtt > 4 ? 4 : neighbor.lowest_rtt);
        const int64_t kept_domains = neighbor.new_domains < 0 ? 0 : (neighbor.new_domains > 2 ? 2 : neighbor.new_domains);
        return SwarmNeighborResult{"CAPPED", false, kept_rtt, kept_domains};
    }
    if (neighbor.want_connect) {
        err = "HELD";
        return SwarmNeighborResult{"HELD", false, neighbor.lowest_rtt, neighbor.new_domains};
    }
    err.clear();
    return SwarmNeighborResult{"NOTED", false, neighbor.lowest_rtt, neighbor.new_domains};
}

} // namespace modelnet
