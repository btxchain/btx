// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dnsempty.h>

#include <cstdint>

namespace modelnet {

SwarmDnsSeedsResult SwarmNoteDnsSeeds(const SwarmDnsSeeds& seeds, std::string& err)
{
    SwarmDnsSeedsResult result;
    result.seed_count = 0;
    result.published = false;
    result.socket_opened = false;
    if (seeds.node_id.empty() || seeds.requested_seeds < 0) {
        result.code = "DNS";
        result.seed_count = 0;
        result.published = false;
        result.socket_opened = false;
        err = "DNS";
        return result;
    }
    // Model DNS seeds stay empty. This wins even when want_publish is true.
    // This note does not publish a hostname or an address and does not open a socket.
    if (seeds.want_publish || seeds.requested_seeds > 0) {
        result.code = "EMPTY";
        result.seed_count = 0;
        result.published = false;
        result.socket_opened = false;
        err = "EMPTY";
        return result;
    }
    // requested_seeds 0 and want_publish false is NOTED.
    result.code = "NOTED";
    result.seed_count = 0;
    result.published = false;
    result.socket_opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
