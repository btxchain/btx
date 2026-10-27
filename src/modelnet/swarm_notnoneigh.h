// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEIGH_H
#define BTX_MODELNET_SWARM_NOTNONEIGH_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one neighborhood. node_id names the node.
 * lowest_rtt is the count of lowest-RTT peers. new_domains is the count
 * of new trust domains. want_connect asks this note to connect.
 *
 * A neighborhood is at most 4 lowest-RTT peers plus 2 new trust domains,
 * and this note connects nothing. connected stays false and applied stays
 * 0 on every path.
 */
struct SwarmNotNoNeigh {
    std::string node_id;
    int64_t lowest_rtt{0};
    int64_t new_domains{0};
    bool want_connect{false};
};

/**
 * Outcome of noting a neighborhood. connected stays false and applied
 * stays 0 on every path. A neighborhood is at most 4 lowest-RTT peers
 * plus 2 new trust domains, and this note connects nothing.
 */
struct SwarmNotNoNeighResult {
    std::string code;
    bool connected{false};
    int64_t applied{0};
};

/**
 * Note a neighborhood without connecting it.
 * Order, first match wins: an empty node_id is NODE.
 * lowest_rtt greater than 4 or new_domains greater than 2 is CAPPED,
 * even when want_connect is false.
 * want_connect is CAPPED.
 * Otherwise the note is NOTED and err is cleared.
 * connected stays false and applied stays 0 on every path.
 * A neighborhood is at most 4 lowest-RTT peers plus 2 new trust domains,
 * and this note connects nothing.
 */
SwarmNotNoNeighResult SwarmNoteNotNoNeigh(const SwarmNotNoNeigh& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEIGH_H
