// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT06_H
#define BTX_MODELNET_SWARM_FAULT06_H

#include <string>

namespace modelnet {

/**
 * Live fault 6: a duplicate work receipt arrives after reconnection.
 * Local recovery only. accepted, committed, bytes_moved, and broadcast
 * stay false.
 */
struct SwarmFault06 {
    std::string receipt_id;
    bool seen_before{false};
    bool durable{false};
    bool payment_claim{false};
    bool want_accept{false};
};

/**
 * Outcome of a duplicate work receipt after reconnection.
 * accepted, committed, bytes_moved, and broadcast stay false on every path.
 */
struct SwarmFault06Result {
    std::string code;
    bool accepted{false};
    bool committed{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Classify a duplicate work receipt after reconnection.
 * Order, first match wins:
 * 1. An empty receipt_id is RECEIPT. Every result bool stays false and
 *    err is RECEIPT.
 * 2. seen_before is REPLAY. accepted stays false. recovered equals
 *    durable. payment_preserved equals payment_claim. err is REPLAY.
 * 3. want_accept is HELD. accepted and recovered stay false.
 *    payment_preserved equals payment_claim. err is cleared.
 * 4. durable is DURABLE. recovered is set. accepted stays false.
 *    payment_preserved equals payment_claim. err is cleared.
 * 5. Otherwise NOTED. accepted stays false. recovered stays false.
 *    payment_preserved equals payment_claim. err is cleared.
 * accepted, committed, bytes_moved, and broadcast stay false on every
 * path. This is local recovery only. It does not accept, commit, move
 * bytes, or broadcast.
 */
SwarmFault06Result SwarmRecoverFault06(const SwarmFault06& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT06_H
