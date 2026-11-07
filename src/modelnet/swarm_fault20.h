// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT20_H
#define BTX_MODELNET_SWARM_FAULT20_H

#include <string>

namespace modelnet {

/**
 * Live fault 20: the original coordinator permanently disappears and a
 * survivor continues only from a durable commitment.
 * committed, broadcast, and bytes_moved stay false on every path.
 * continued is true only on the durable survivor path.
 * This does not kill a process.
 */
struct SwarmFault20 {
    std::string coord_id;
    std::string survivor_id;
    bool durable{false};
    bool payment_claim{false};
    bool want_continue{false};
};

/**
 * Outcome of continuing from a durable commitment after the original
 * coordinator permanently disappears.
 * committed, broadcast, and bytes_moved stay false on every path.
 * continued is true only on the durable survivor path.
 */
struct SwarmFault20Result {
    std::string code;
    bool continued{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool committed{false};
    bool broadcast{false};
    bool bytes_moved{false};
};

/**
 * Continue from a durable commitment after the original coordinator
 * permanently disappears. This does not kill a process.
 * Order, first match wins:
 * 1. An empty coord_id is COORD. Every result bool stays false and err
 *    is COORD.
 * 2. An empty survivor_id is NO_SURVIVOR. continued and recovered stay
 *    false. payment_preserved equals payment_claim. err is NO_SURVIVOR.
 * 3. Not durable is LOST. continued and recovered stay false.
 *    payment_preserved equals payment_claim. err is LOST.
 * 4. want_continue is DURABLE. continued and recovered are true.
 *    committed stays false. payment_preserved equals payment_claim.
 *    err is cleared. This is the only path where continued is true.
 * 5. Otherwise NOTED. continued stays false and recovered is true.
 *    payment_preserved equals payment_claim. err is cleared. Durable
 *    state is retained, but continuation was not requested.
 * committed, broadcast, and bytes_moved stay false on every path.
 */
SwarmFault20Result SwarmRecoverFault20(const SwarmFault20& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT20_H
