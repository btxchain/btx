// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PROMOHALT_H
#define BTX_MODELNET_SWARM_PROMOHALT_H

#include <string>

namespace modelnet {

/**
 * Local inputs for a promotion halt note.
 * started false means the attempt never began. interrupted is ignored
 * until the attempt has started.
 */
struct SwarmPromotionAttempt {
    std::string candidate_id;
    bool started{false};
    bool interrupted{false};
};

/**
 * Local halt note. graduated stays false. This note is not a promotion
 * certificate and does not graduate the candidate.
 */
struct SwarmPromotionHalt {
    bool graduated{false};
    std::string code;
};

/**
 * Record a local halt note for a promotion attempt.
 * graduated stays false on every return. A local halt note is not a
 * promotion certificate and does not graduate. This function does not
 * broadcast.
 *
 * An empty candidate_id is PROMOTION.
 * An attempt that has not started is NOT_STARTED, even when interrupted
 * is true.
 * An interrupted attempt that has started is INTERRUPTED.
 * Otherwise the note is HELD and err is cleared.
 */
SwarmPromotionHalt SwarmHaltPromotion(const SwarmPromotionAttempt& attempt, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PROMOHALT_H
