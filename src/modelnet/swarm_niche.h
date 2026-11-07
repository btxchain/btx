// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NICHE_H
#define BTX_MODELNET_SWARM_NICHE_H

#include <string>

namespace modelnet {

/**
 * A comparison request between two niches. left_niche and right_niche name
 * the niches. want_compare asks to rank them against each other.
 *
 * Different niches are not ranked against each other. No hostnames or IPs
 * are used.
 */
struct SwarmNicheCompare {
    std::string left_niche;
    std::string right_niche;
    bool want_compare{false};
};

/**
 * Outcome of noting a niche comparison. compared stays false on every path:
 * different niches are not ranked against each other.
 */
struct SwarmNicheResult {
    bool compared{false};
    std::string code;
};

/**
 * Note two niches without ranking them against each other.
 * Order, first match wins: an empty left_niche or right_niche is NICHE.
 * Unequal niches are SEPARATE, including when want_compare is true.
 * A request to compare equal niches is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * compared stays false on every path. Different niches are not ranked
 * against each other. No hostnames or IPs are used.
 */
SwarmNicheResult SwarmNoteNiche(const SwarmNicheCompare& compare, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NICHE_H
