// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT11_H
#define BTX_MODELNET_SWARM_FAULT11_H

#include <string>

namespace modelnet {

/**
 * Local note for live fault 11: a canary rollout regresses.
 *
 * This note does not roll, promote, or broadcast a candidate.
 * rolled, promoted, and broadcast stay false on every path.
 */
struct SwarmFault11 {
    std::string candidate_id;
    bool regressed{false};
    bool want_roll{false};
};

/**
 * Outcome of a regressed canary note. rolled, promoted, and broadcast
 * stay false on every path.
 */
struct SwarmFault11Result {
    std::string code;
    bool rolled{false};
    bool promoted{false};
    bool broadcast{false};
};

/**
 * Note a regressed canary without rolling, promoting, or broadcasting.
 * Order, first match wins:
 * 1. An empty candidate_id is CANDIDATE. Every bool stays false.
 *    err is CANDIDATE.
 * 2. regressed is REGRESSION. rolled and promoted stay false.
 *    err is REGRESSION even if want_roll.
 * 3. want_roll is HELD. rolled and promoted stay false. err is cleared.
 * 4. Otherwise the note is NOTED. rolled and promoted stay false.
 *    err is cleared.
 * rolled, promoted, and broadcast stay false on every path.
 */
SwarmFault11Result SwarmRecoverFault11(const SwarmFault11& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT11_H
