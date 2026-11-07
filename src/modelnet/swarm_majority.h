// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MAJORITY_H
#define BTX_MODELNET_SWARM_MAJORITY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a majority vote. candidate_id names the candidate.
 * yes_ppm is the yes share in parts per million, from 0 through 1000000.
 * want_graduate asks this note to graduate the candidate.
 *
 * A majority vote does not graduate a candidate. No hostnames or IPs
 * are used.
 */
struct SwarmMajorityVote {
    std::string candidate_id;
    int64_t yes_ppm{0};
    bool want_graduate{false};
};

/**
 * Outcome of noting a majority vote. graduated stays false on every
 * path: a majority vote does not graduate a candidate.
 */
struct SwarmMajorityResult {
    bool graduated{false};
    std::string code;
};

/**
 * Note a majority vote without graduating the candidate.
 * Order, first match wins: an empty candidate_id, yes_ppm < 0, or
 * yes_ppm > 1000000 is VOTE. want_graduate is GRADUATE_REFUSED, including
 * when yes_ppm is 510000 or 1000000. Otherwise the note is NOTED and err
 * is clear.
 * graduated stays false. A majority vote does not graduate a candidate.
 * No hostnames or IPs are used.
 */
SwarmMajorityResult SwarmNoteMajority(const SwarmMajorityVote& vote, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MAJORITY_H
