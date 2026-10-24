// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DNSEMPTY_H
#define BTX_MODELNET_SWARM_DNSEMPTY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that model DNS seeds stay empty. node_id names the note.
 * requested_seeds is the count of seeds the caller asked to record.
 * want_publish asks this note to publish a hostname or an address.
 *
 * This note does not publish a hostname or an address and does not open
 * a socket. seed_count stays 0. published and socket_opened stay false
 * on every path. No hostnames or IPs are used.
 */
struct SwarmDnsSeeds {
    std::string node_id;
    int64_t requested_seeds{0};
    bool want_publish{false};
};

/**
 * Outcome of noting empty model DNS seeds. seed_count stays 0.
 * published and socket_opened stay false: this note does not publish a
 * hostname or an address and does not open a socket.
 */
struct SwarmDnsSeedsResult {
    int64_t seed_count{0};
    bool published{false};
    bool socket_opened{false};
    std::string code;
};

/**
 * Note that model DNS seeds stay empty. This note does not publish a
 * hostname or an address and does not open a socket.
 * Order, first match wins: an empty node_id or requested_seeds below 0
 * is DNS. want_publish, or requested_seeds above 0, is EMPTY. Model DNS
 * seeds stay empty. This wins even when want_publish is true. Otherwise
 * the note is NOTED and err is cleared. requested_seeds 0 with
 * want_publish false is NOTED.
 * seed_count stays 0. published and socket_opened stay false on every
 * path. No hostnames or IPs are used.
 */
SwarmDnsSeedsResult SwarmNoteDnsSeeds(const SwarmDnsSeeds& seeds, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DNSEMPTY_H
