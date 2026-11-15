// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEIGHCAP2_H
#define BTX_MODELNET_SWARM_NOTNONEIGHCAP2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one neighborhood. node_id names the node.
 * low_rtt is the count of lowest-RTT peers. extra_domains is the count
 * of new trust domains. want_raise asks this note to raise the cap.
 *
 * A neighborhood stays four lowest-RTT peers plus two new trust domains
 * and this note raises nothing. raised stays false on every path.
 */
struct SwarmNotNoNeighCap2 {
    std::string node_id;
    uint32_t low_rtt{0};
    uint32_t extra_domains{0};
    bool want_raise{false};
};

/**
 * Outcome of noting a neighborhood. raised stays false on every path.
 * A neighborhood stays four lowest-RTT peers plus two new trust domains
 * and this note raises nothing.
 */
struct SwarmNotNoNeighCap2Result {
    std::string code;
    bool raised{false};
};

/**
 * Note a neighborhood without raising it.
 * Order, first match wins: an empty node_id is NODE.
 * low_rtt greater than 4 or extra_domains greater than 2 is CAPPED,
 * even when want_raise is false.
 * want_raise is CAPPED.
 * Otherwise the note is NOTED and err is cleared.
 * raised stays false on every path.
 * A neighborhood stays four lowest-RTT peers plus two new trust domains
 * and this note raises nothing.
 */
SwarmNotNoNeighCap2Result SwarmNoteNotNoNeighCap2(const SwarmNotNoNeighCap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEIGHCAP2_H
