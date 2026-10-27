// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_currencykeep.h>

namespace modelnet {

SwarmCurrencyKeepResult SwarmKeepCurrency(const SwarmCurrencyKeep& ledger, std::string& err)
{
    // The currency stays BTX.
    SwarmCurrencyKeepResult result;
    result.renamed = false;
    result.currency = "BTX";
    if (ledger.ledger_id.empty()) {
        result.code = "LEDGER";
        result.renamed = false;
        result.currency = "BTX";
        err = "LEDGER";
        return result;
    }
    if (ledger.want_rename) {
        result.code = "HELD";
        result.renamed = false;
        result.currency = "BTX";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.renamed = false;
    result.currency = "BTX";
    err.clear();
    return result;
}

} // namespace modelnet
