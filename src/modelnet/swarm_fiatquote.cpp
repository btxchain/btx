// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fiatquote.h>

#include <cstdint>

namespace modelnet {

SwarmFiatQuoteResult SwarmNoteFiatQuote(const SwarmFiatQuoteRequest& quote, std::string& err)
{
    SwarmFiatQuoteResult result;
    result.balance_credited = false;
    if (quote.quote_id.empty() || quote.currency.empty() || quote.atoms < 0) {
        result.code = "QUOTE";
        result.balance_credited = false;
        err = "QUOTE";
        return result;
    }
    // A fiat quote is not a BTX balance. Nothing is credited and nothing
    // is broadcast.
    if (quote.currency != "BTX") {
        result.code = "NOT_BTX";
        result.balance_credited = false;
        err = "NOT_BTX";
        return result;
    }
    if (quote.want_balance) {
        result.code = "HELD";
        result.balance_credited = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.balance_credited = false;
    err.clear();
    return result;
}

} // namespace modelnet
