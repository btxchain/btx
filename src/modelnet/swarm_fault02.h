// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT02_H
#define BTX_MODELNET_SWARM_FAULT02_H

#include <string>

namespace modelnet {

/**
 * Live fault 2: a replacement coordinator starts during the old lease expiry.
 * Local recovery only. committed, bytes_moved, and broadcast stay false.
 */
struct SwarmFault02 {
    std::string lease_id;
    std::string old_epoch;
    std::string new_epoch;
    bool lease_expired{false};
    bool durable{false};
    bool payment_claim{false};
    bool want_commit{false};
};

/**
 * Outcome of a local replacement during old-lease expiry.
 * committed, bytes_moved, and broadcast stay false on every path.
 */
struct SwarmFault02Result {
    std::string code;
    bool committed{false};
    bool replaced{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Classify a local replacement during old-lease expiry.
 * Order, first match wins:
 * 1. An empty lease_id, old_epoch, or new_epoch is LEASE. Every result
 *    bool stays false and err is LEASE.
 * 2. want_commit is STALE. committed, replaced, and recovered stay false.
 *    payment_preserved equals payment_claim. err is STALE.
 * 3. A lease that has not expired is HELD. replaced and recovered stay
 *    false. payment_preserved equals payment_claim. err is cleared.
 * 4. new_epoch equal to old_epoch is SAME_EPOCH. replaced and recovered
 *    stay false. payment_preserved equals payment_claim. err is SAME_EPOCH.
 * 5. A durable claim is REPLACED. replaced and recovered are set.
 *    committed stays false. payment_preserved equals payment_claim.
 *    err is cleared.
 * 6. Otherwise LOST. replaced and recovered stay false.
 *    payment_preserved equals payment_claim. err is LOST.
 * committed, bytes_moved, and broadcast stay false on every path.
 * This is local recovery only. It does not move bytes or broadcast.
 */
SwarmFault02Result SwarmRecoverFault02(const SwarmFault02& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT02_H
