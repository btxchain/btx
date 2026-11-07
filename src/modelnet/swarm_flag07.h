// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG07_H
#define BTX_MODELNET_SWARM_FLAG07_H

#include <string>

namespace modelnet {

/**
 * A local note about flagship stage 7 evolve: multiple candidate
 * descendants, including one different strategy. parent_id names the
 * parent. candidate_a and candidate_b name the candidates.
 * different_strategy asks this note to treat the pair as a strategy
 * change. from_real_run asks this note to treat the pair as evolved
 * from a real run. want_pass asks this note to treat the pair as a
 * produced, passed descendant.
 *
 * Distinct names are not a real descendant. produced, passed, and
 * bytes_moved stay false on every path.
 */
struct SwarmFlag07 {
    std::string parent_id;
    std::string candidate_a;
    std::string candidate_b;
    bool different_strategy{false};
    bool from_real_run{false};
    bool want_pass{false};
};

/**
 * Outcome of noting flagship stage 7 evolve. produced, passed, and
 * bytes_moved stay false: distinct names are not a real descendant.
 */
struct SwarmFlag07Result {
    std::string code;
    bool produced{false};
    bool passed{false};
    bool bytes_moved{false};
};

/**
 * Note flagship stage 7 evolve. Distinct names are not a real descendant.
 * Order, first match wins: an empty parent_id, candidate_a, or
 * candidate_b is PARENT. Equal candidate_a and candidate_b is
 * SAME_CANDIDATE. different_strategy false is SAME_STRATEGY.
 * from_real_run false is NOT_EVOLVED, even when want_pass is true.
 * want_pass is UNQUALIFIED. Otherwise the note is NOTED and err is
 * cleared.
 * produced, passed, and bytes_moved stay false on every path.
 */
SwarmFlag07Result SwarmStageEvolve(const SwarmFlag07& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG07_H
