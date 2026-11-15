// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG12_H
#define BTX_MODELNET_SWARM_FLAG12_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 12 recover: a survivor retains durable commitments after
 * the coordinator is gone. continued is true only when durable, a survivor
 * id is present, and continuation is requested.
 * committed, broadcast, passed, and bytes_moved stay false.
 * This does not kill a process.
 */
struct SwarmFlag12 {
    std::string survivor_id;
    std::string work_id;
    bool durable{false};
    bool payment_claim{false};
    bool want_continue{false};
    bool want_pass{false};
};

/**
 * Outcome of retaining durable commitments after the coordinator is gone.
 * committed, broadcast, passed, and bytes_moved stay false on every path.
 */
struct SwarmFlag12Result {
    std::string code;
    bool continued{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool committed{false};
    bool broadcast{false};
    bool passed{false};
    bool bytes_moved{false};
};

/**
 * Classify a survivor that retains durable commitments after the coordinator
 * is gone. Order, first match wins:
 * 1. An empty survivor_id or work_id is NODE. Every result bool stays false
 *    and err is NODE.
 * 2. want_pass is UNQUALIFIED. continued and passed stay false.
 *    payment_preserved equals payment_claim. err is UNQUALIFIED.
 * 3. A claim that is not durable is LOST. continued and recovered stay
 *    false. payment_preserved equals payment_claim. err is LOST.
 * 4. want_continue is DURABLE. continued and recovered are set.
 *    committed stays false. payment_preserved equals payment_claim.
 *    err is cleared.
 * 5. Otherwise NOTED. continued stays false. recovered is set.
 *    payment_preserved equals payment_claim. err is cleared.
 * continued is true only when durable, a survivor id is present, and
 * continuation is requested. committed, broadcast, passed, and bytes_moved
 * stay false on every path. This does not kill a process.
 */
SwarmFlag12Result SwarmStageRecover(const SwarmFlag12& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG12_H
