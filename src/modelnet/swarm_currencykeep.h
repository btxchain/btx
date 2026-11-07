// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CURRENCYKEEP_H
#define BTX_MODELNET_SWARM_CURRENCYKEEP_H

#include <string>

namespace modelnet {

/**
 * A local note that a ledger keeps its currency.
 * The currency stays BTX. A rename request is refused.
 */
struct SwarmCurrencyKeep {
    std::string ledger_id;
    bool want_rename{false};
};

/**
 * Outcome of keeping the currency. renamed stays false and currency
 * stays BTX on every path.
 */
struct SwarmCurrencyKeepResult {
    std::string code;
    bool renamed{false};
    std::string currency;
};

/**
 * Keep the ledger currency. Empty ledger_id is LEDGER. A rename request
 * is HELD. Otherwise the note is NOTED and err is clear. renamed stays
 * false and currency stays BTX on every path.
 */
SwarmCurrencyKeepResult SwarmKeepCurrency(const SwarmCurrencyKeep& ledger, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CURRENCYKEEP_H
