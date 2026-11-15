// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PARETO_H
#define BTX_MODELNET_SWARM_PARETO_H

#include <string>

namespace modelnet {

/**
 * A ranking request for one candidate. candidate_id names the candidate.
 * niche and other_niche name the niches being considered. want_rank asks
 * to rank inside a niche.
 *
 * Different niches are not ranked against each other. This note does not
 * rank inside one niche either. Nothing is scored. No hostnames or IPs
 * are used.
 */
struct SwarmPareto {
    std::string candidate_id;
    std::string niche;
    std::string other_niche;
    bool want_rank{false};
};

/**
 * Outcome of noting a Pareto request. ranked stays false on every path:
 * nothing is scored.
 */
struct SwarmParetoResult {
    bool ranked{false};
    std::string code;
};

/**
 * Note a Pareto request without ranking.
 * Order, first match wins: an empty candidate_id or niche is PARETO.
 * Unequal niches are SEPARATE, including when want_rank is true.
 * Different niches are not ranked against each other.
 * A request to rank inside one niche is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * ranked stays false on every path. Nothing is scored. No hostnames or
 * IPs are used.
 */
SwarmParetoResult SwarmNotePareto(const SwarmPareto& pareto, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PARETO_H
