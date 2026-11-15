// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/fiat_quote.h>

namespace modelnet {

bool SwarmPayFiatQuote(std::string& err)
{
    // A fiat quote is not a BTX balance. Nothing is stored.
    err = "NOT_BALANCE";
    return false;
}

} // namespace modelnet
