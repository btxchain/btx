// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NBHD_H
#define BTX_MODELNET_SWARM_NBHD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one neighborhood of authorized peers. node_id is an
 * opaque id. lowest_rtt is the count of lowest-RTT authorized peers in
 * the note. new_domains is the count of peers from new trust domains.
 * want_connect asks this note to connect.
 *
 * The cap is 4 lowest-RTT authorized peers plus 2 from new trust domains.
 * This note does not connect and does not open a socket. connected and
 * socket_opened stay false on every path. No hostnames or IPs are used.
 */
struct SwarmNeighborhood {
    std::string node_id;
    int64_t lowest_rtt{0};
    int64_t new_domains{0};
    bool want_connect{false};
};

/**
 * Outcome of noting a neighborhood. connected and socket_opened stay
 * false: this note does not connect and does not open a socket.
 */
struct SwarmNeighborhoodResult {
    bool connected{false};
    bool socket_opened{false};
    std::string code;
};

/**
 * Note a neighborhood without connecting or opening a socket.
 * Order, first match wins: an empty node_id, lowest_rtt below 0, or
 * new_domains below 0 is PEER. lowest_rtt above 4 is RTT_CAP. That wins
 * even when want_connect is true. new_domains above 2 is DOMAIN_CAP.
 * That wins even when want_connect is true. want_connect is HELD and err
 * is cleared. This note does not open a socket. Otherwise the note is
 * NOTED and err is cleared. lowest_rtt 4 and new_domains 2 is NOTED when
 * want_connect is false.
 * connected and socket_opened stay false on every path. No hostnames or
 * IPs are used.
 */
SwarmNeighborhoodResult SwarmNoteNeighborhood(const SwarmNeighborhood& neighborhood, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NBHD_H
