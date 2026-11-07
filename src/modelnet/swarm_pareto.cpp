// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_pareto.h>

namespace modelnet {

SwarmParetoResult SwarmNotePareto(const SwarmPareto& pareto, std::string& err)
{
    SwarmParetoResult result;
    result.ranked = false;
    if (pareto.candidate_id.empty() || pareto.niche.empty()) {
        result.code = "PARETO";
        err = "PARETO";
        return result;
    }
    // Different niches are not ranked against each other.
    // SEPARATE wins even when want_rank is true.
    if (pareto.niche != pareto.other_niche) {
        result.code = "SEPARATE";
        err = "SEPARATE";
        return result;
    }
    if (pareto.want_rank) {
        result.code = "HELD";
        result.ranked = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.ranked = false;
    err.clear();
    return result;
}

} // namespace modelnet
