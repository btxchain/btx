// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG11_H
#define BTX_MODELNET_SWARM_FLAG11_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 11 pay for one invoice.
 * Isolated regtest settlement stays unbroadcast. settled, broadcast, mined,
 * and passed stay false on every path. This stage does not mine and does
 * not store a txid.
 */
struct SwarmFlag11 {
    std::string invoice_id;
    bool regtest{false};
    bool want_settle{false};
    bool want_mine{false};
    bool want_pass{false};
};

/**
 * Outcome of a flagship stage 11 pay note. settled, broadcast, mined, and
 * passed stay false, and txid stays empty, on every path.
 */
struct SwarmFlag11Result {
    std::string code;
    bool settled{false};
    bool broadcast{false};
    bool mined{false};
    bool passed{false};
    std::string txid;
};

/**
 * Note a flagship stage 11 pay without settling, broadcasting, mining, or
 * storing a txid.
 * Order, first match wins: an empty invoice_id is INVOICE. A note that is
 * not regtest is MAINNET. want_mine is NOT_MINED. want_settle is
 * NOT_SETTLED and err is clear. want_pass is UNQUALIFIED. Otherwise the
 * note is NOTED and err is clear.
 * settled, broadcast, mined, and passed stay false. txid stays empty.
 */
SwarmFlag11Result SwarmStagePay(const SwarmFlag11& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG11_H
