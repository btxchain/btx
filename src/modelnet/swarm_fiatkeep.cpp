// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fiatkeep.h>

namespace modelnet {

// A fiat quote is not a BTX balance.
SwarmFiatKeepResult SwarmNoteFiatQuote(const SwarmFiatKeep& quote, std::string& err)
{
    SwarmFiatKeepResult out;
    out.booked = false;
    out.atoms = 0;

    if (quote.quote_id.empty()) {
        out.code = "QUOTE";
        err = "QUOTE";
        return out;
    }
    if (quote.fiat) {
        out.code = "NOT_BALANCE";
        err = "NOT_BALANCE";
        return out;
    }
    if (quote.want_book) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }

    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
