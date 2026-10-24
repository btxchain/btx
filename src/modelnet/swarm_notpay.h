// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPAY_H
#define BTX_MODELNET_SWARM_NOTPAY_H

#include <string>

namespace modelnet {

/**
 * A local note about one invoice. want_settle asks this note to settle on
 * isolated regtest and broadcast the result.
 *
 * Isolated regtest settlement is not done, and nothing is broadcast.
 * settled and broadcast stay false on every path.
 */
struct SwarmNotPay {
    std::string invoice_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a settlement request. settled and broadcast stay false
 * on every path: isolated regtest settlement is not done, and nothing is
 * broadcast.
 */
struct SwarmNotPayResult {
    std::string code;
    bool settled{false};
    bool broadcast{false};
};

/**
 * Note a settlement request without settling or broadcasting.
 * Order, first match wins: an empty invoice_id is INVOICE. want_settle is
 * NOT_SETTLED. Otherwise the note is NOTED and err is clear.
 * settled and broadcast stay false on every path.
 */
SwarmNotPayResult SwarmNoteNotPay(const SwarmNotPay& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPAY_H
