// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nbhd.h>

#include <cstdint>

namespace modelnet {

SwarmNeighborhoodResult SwarmNoteNeighborhood(const SwarmNeighborhood& neighborhood, std::string& err)
{
    SwarmNeighborhoodResult result;
    result.connected = false;
    result.socket_opened = false;
    if (neighborhood.node_id.empty() || neighborhood.lowest_rtt < 0 || neighborhood.new_domains < 0) {
        result.code = "PEER";
        result.connected = false;
        result.socket_opened = false;
        err = "PEER";
        return result;
    }
    // RTT_CAP wins even when want_connect is true. The cap is 4
    // lowest-RTT authorized peers. This note does not open a socket.
    if (neighborhood.lowest_rtt > 4) {
        result.code = "RTT_CAP";
        result.connected = false;
        result.socket_opened = false;
        err = "RTT_CAP";
        return result;
    }
    // DOMAIN_CAP wins even when want_connect is true. The cap is 2
    // peers from new trust domains. This note does not open a socket.
    if (neighborhood.new_domains > 2) {
        result.code = "DOMAIN_CAP";
        result.connected = false;
        result.socket_opened = false;
        err = "DOMAIN_CAP";
        return result;
    }
    // This note does not open a socket.
    if (neighborhood.want_connect) {
        result.code = "HELD";
        result.connected = false;
        result.socket_opened = false;
        err.clear();
        return result;
    }
    // lowest_rtt 4 and new_domains 2 is NOTED when want_connect is false.
    result.code = "NOTED";
    result.connected = false;
    result.socket_opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
