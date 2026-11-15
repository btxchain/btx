// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPROMO_H
#define BTX_MODELNET_SWARM_NOTPROMO_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. want_promote asks this note to promote
 * that candidate.
 *
 * An interrupted candidate promotion has not been shown.
 * promoted stays false on every path.
 */
struct SwarmNotPromo {
    std::string candidate_id;
    bool want_promote{false};
};

/**
 * Outcome of noting a promotion request. promoted stays false on every path:
 * an interrupted candidate promotion has not been shown.
 */
struct SwarmNotPromoResult {
    std::string code;
    bool promoted{false};
};

/**
 * Note a promotion request without promoting the candidate.
 * Order, first match wins: an empty candidate_id is CANDIDATE. want_promote
 * is NOT_PROMOTED. Otherwise the note is NOTED and err is clear.
 * promoted stays false on every path.
 */
SwarmNotPromoResult SwarmNoteNotPromo(const SwarmNotPromo& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPROMO_H
