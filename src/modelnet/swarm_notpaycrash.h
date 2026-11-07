// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPAYCRASH_H
#define BTX_MODELNET_SWARM_NOTPAYCRASH_H

#include <string>

namespace modelnet {

/**
 * A local note about one earning. want_settle asks this note to settle and
 * broadcast the result.
 *
 * A payment service crash after earning and before settlement broadcasts
 * nothing. settled and broadcast stay false on every path.
 */
struct SwarmNotPayCrash {
    std::string earn_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a crash between earning and settlement. settled and
 * broadcast stay false on every path: a payment service crash after earning
 * and before settlement broadcasts nothing.
 */
struct SwarmNotPayCrashResult {
    std::string code;
    bool settled{false};
    bool broadcast{false};
};

/**
 * Note a payment-service crash after earning and before settlement.
 * Order, first match wins: an empty earn_id is EARN. want_settle is
 * NOT_SETTLED. Otherwise the note is NOTED and err is clear.
 * settled and broadcast stay false on every path. Nothing is broadcast.
 */
SwarmNotPayCrashResult SwarmNoteNotPayCrash(const SwarmNotPayCrash& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPAYCRASH_H
