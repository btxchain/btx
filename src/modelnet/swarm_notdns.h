// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDNS_H
#define BTX_MODELNET_SWARM_NOTDNS_H

#include <string>

namespace modelnet {

/**
 * A local note about one seed. want_publish asks this note to publish it.
 *
 * This note publishes no seed and no address. ModelDNSSeeds stays empty.
 * published stays false and seed_count stays 0 on every path.
 */
struct SwarmNotDns {
    std::string seed_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a seed. published stays false and seed_count stays 0
 * on every path. ModelDNSSeeds stays empty.
 */
struct SwarmNotDnsResult {
    std::string code;
    bool published{false};
    int seed_count{0};
};

/**
 * Note a seed without publishing a seed or an address.
 * Order, first match wins: an empty seed_id is SEED.
 * want_publish is EMPTY.
 * Otherwise the note is NOTED and err is clear.
 * published stays false and seed_count stays 0 on every path.
 * ModelDNSSeeds stays empty. This note publishes no seed and no address.
 */
SwarmNotDnsResult SwarmNoteNotDns(const SwarmNotDns& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDNS_H
