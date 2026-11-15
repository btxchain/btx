// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/fiat_quote.h>

#include <modelnet/swarm_workpay/codes.h>

namespace modelnet {

bool SwarmWorkFiatQuote(const std::string& fiat, std::string& err)
{
    // A fiat quote is not a balance. The quote text is not stored.
    static_cast<void>(fiat);
    err = SWARM_WORK_NOT_BALANCE;
    return false;
}

} // namespace modelnet
