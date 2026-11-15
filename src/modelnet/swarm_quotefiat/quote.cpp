// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/quote.h>

#include <modelnet/swarm_quotefiat/codes.h>
#include <modelnet/swarm_quotefiat/gate.h>

namespace modelnet {

bool SwarmQuoteFiatQuote::Apply(SwarmQuoteFiatBook& book, const std::string& usd, std::string& err) const
{
    const SwarmQuoteFiatDecision decision = SwarmQuoteFiatDecide(book, usd);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(usd) || !book.contains(usd)) {
        if (book.contains(usd)) {
            err = kSwarmQuoteFiatReplay;
        } else {
            err = kSwarmQuoteFiatQuote;
        }
        return false;
    }
    // The quote is kept. It is not a BTX balance, so Quote returns false.
    err = kSwarmQuoteFiatNotBalance;
    return false;
}

} // namespace modelnet
