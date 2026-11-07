// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT13_H
#define BTX_MODELNET_SWARM_FAULT13_H

#include <string>

namespace modelnet {

/**
 * Live fault 13: the payment service crashes after earning and before
 * settlement. The payment claim is preserved separately from volatile
 * execution. This note does not settle, broadcast, or commit.
 * settled, broadcast, and committed stay false on every path.
 */
struct SwarmFault13 {
    std::string earn_id;
    bool earned{false};
    bool durable{false};
    bool payment_claim{false};
    bool want_settle{false};
};

/**
 * Outcome of recovering live fault 13. settled, broadcast, and committed
 * stay false: a crash after earning and before settlement settles nothing.
 * payment_preserved is the claim kept apart from volatile execution.
 */
struct SwarmFault13Result {
    std::string code;
    bool settled{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool broadcast{false};
    bool committed{false};
};

/**
 * Recover live fault 13 without settling, broadcasting, or committing.
 * Order, first match wins:
 * 1. An empty earn_id is EARN. Every result bool stays false. err is EARN.
 * 2. want_settle is HELD. settled, broadcast, and recovered stay false.
 *    payment_preserved equals payment_claim. err is cleared.
 * 3. earned and not durable is LOST. recovered stays false.
 *    payment_preserved equals payment_claim. settled stays false.
 *    err is LOST.
 * 4. earned and durable is EARNED. recovered is true.
 *    payment_preserved is true even when payment_claim is false, because
 *    the durable earn itself is the preserved claim. settled and broadcast
 *    stay false. err is cleared.
 * 5. Otherwise the note is NOTED. recovered stays false.
 *    payment_preserved equals payment_claim. settled stays false.
 *    err is cleared.
 * settled, broadcast, and committed stay false on every path.
 */
SwarmFault13Result SwarmRecoverFault13(const SwarmFault13& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT13_H
