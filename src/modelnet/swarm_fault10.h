// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT10_H
#define BTX_MODELNET_SWARM_FAULT10_H

#include <string>

namespace modelnet {

/**
 * Live fault 10: candidate promotion is interrupted.
 * want_promote asks to promote. This function does not promote.
 * promoted, committed, and broadcast stay false on every path.
 */
struct SwarmFault10 {
    std::string candidate_id;
    bool interrupted{false};
    bool durable{false};
    bool want_promote{false};
};

/**
 * Outcome of recovering live fault 10. promoted, committed, and broadcast
 * stay false: candidate promotion is interrupted and nothing is published.
 */
struct SwarmFault10Result {
    std::string code;
    bool promoted{false};
    bool recovered{false};
    bool committed{false};
    bool broadcast{false};
};

/**
 * Recover live fault 10 without promoting, committing, or broadcasting.
 * Order, first match wins:
 * empty candidate_id is CANDIDATE and sets err.
 * interrupted is GATE and sets err, even if want_promote.
 * want_promote is HELD and clears err.
 * durable is DURABLE, sets recovered, and clears err.
 * otherwise NOTED and clears err.
 * promoted, committed, and broadcast stay false on every path.
 */
SwarmFault10Result SwarmRecoverFault10(const SwarmFault10& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT10_H
