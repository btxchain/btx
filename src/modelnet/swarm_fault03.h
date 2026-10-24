// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT03_H
#define BTX_MODELNET_SWARM_FAULT03_H

#include <string>

namespace modelnet {

/**
 * Live fault 3: an old coordinator resumes with a stale epoch.
 * Local recovery only. committed, bytes_moved, and broadcast stay false.
 * A stale resume commits nothing.
 */
struct SwarmFault03 {
    std::string epoch_id;
    std::string current_epoch;
    bool durable{false};
    bool payment_claim{false};
    bool want_commit{false};
};

/**
 * Outcome of a stale-epoch resume. committed, bytes_moved, and broadcast
 * stay false on every path.
 */
struct SwarmFault03Result {
    std::string code;
    bool committed{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Classify a stale-epoch resume. Order, first match wins:
 * 1. An empty epoch_id or current_epoch is EPOCH. Every result bool stays
 *    false and err is EPOCH.
 * 2. epoch_id not equal to current_epoch, or want_commit, is STALE.
 *    committed and recovered stay false. payment_preserved equals
 *    payment_claim. err is STALE.
 * 3. durable is DURABLE. recovered is set. committed stays false.
 *    payment_preserved equals payment_claim. err is cleared.
 * 4. Otherwise NOTED. recovered and committed stay false.
 *    payment_preserved equals payment_claim. err is cleared.
 * committed, bytes_moved, and broadcast stay false on every path.
 * This is local recovery only. It does not move bytes or broadcast.
 */
SwarmFault03Result SwarmRecoverFault03(const SwarmFault03& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT03_H
