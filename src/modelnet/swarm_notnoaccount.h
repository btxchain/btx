// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOACCOUNT_H
#define BTX_MODELNET_SWARM_NOTNOACCOUNT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one ledger. want_pay asks this note to pay.
 * real_money marks a real-money channel.
 *
 * Paynet stays accounting only. A real-money channel pays nothing, so
 * paid stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoAccount {
    std::string ledger_id;
    bool real_money{false};
    bool want_pay{false};
};

/**
 * Outcome of noting a ledger. paid stays false and atoms stays 0 on
 * every path. Paynet stays accounting only. A real-money channel pays
 * nothing.
 */
struct SwarmNotNoAccountResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a ledger without paying a real-money channel.
 * Order, first match wins: an empty ledger_id is LEDGER. real_money is
 * REAL_MONEY even when want_pay is false. want_pay is ACCOUNTING_ONLY.
 * Otherwise the note is NOTED and err is cleared. paid stays false and
 * atoms stays 0 on every path. Paynet stays accounting only. A
 * real-money channel pays nothing.
 */
SwarmNotNoAccountResult SwarmNoteNotNoAccount(const SwarmNotNoAccount& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOACCOUNT_H
