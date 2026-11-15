// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCANARY_H
#define BTX_MODELNET_SWARM_NOTCANARY_H

#include <string>

namespace modelnet {

/**
 * A local note about one regression attachment. want_roll asks this note
 * to treat the attachment as a live canary rollout.
 *
 * A regression attachment is not a live canary rollout, so rolled stays
 * false on every path.
 */
struct SwarmNotCanary {
    std::string candidate_id;
    bool want_roll{false};
};

/**
 * Outcome of noting a regression attachment. rolled stays false on every
 * path: a regression attachment is not a live canary rollout.
 */
struct SwarmNotCanaryResult {
    std::string code;
    bool rolled{false};
};

/**
 * Note a regression attachment without rolling it as a live canary.
 * Order, first match wins: an empty candidate_id is CANDIDATE.
 * want_roll is NOT_CANARY.
 * Otherwise the note is NOTED and err is clear.
 * rolled stays false on every path. A regression attachment is not a live
 * canary rollout.
 */
SwarmNotCanaryResult SwarmNoteNotCanary(const SwarmNotCanary& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCANARY_H
