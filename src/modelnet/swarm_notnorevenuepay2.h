// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREVENUEPAY2_H
#define BTX_MODELNET_SWARM_NOTNOREVENUEPAY2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one revenue ledger. ledger_id names the ledger.
 * want_pay asks this note to pay.
 *
 * A revenue illustration records 7000, 2000, and 1000 and pays nothing.
 * paid stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoRevenuePay2 {
    std::string ledger_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a revenue ledger. paid stays false and atoms stays 0
 * on every path. A revenue illustration records 7000, 2000, and 1000
 * and pays nothing.
 */
struct SwarmNotNoRevenuePay2Result {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a revenue ledger without paying.
 * Order, first match wins: an empty ledger_id is LEDGER. want_pay is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path. A revenue
 * illustration records 7000, 2000, and 1000 and pays nothing.
 */
SwarmNotNoRevenuePay2Result SwarmNoteNotNoRevenuePay2(const SwarmNotNoRevenuePay2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREVENUEPAY2_H
