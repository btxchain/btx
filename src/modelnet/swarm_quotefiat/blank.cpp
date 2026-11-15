// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/blank.h>

#include <modelnet/swarm_quotefiat/codes.h>

namespace modelnet {

bool SwarmQuoteFiatBlank::accept(const std::string& usd, std::string& err) const
{
    if (usd.empty()) {
        err = kSwarmQuoteFiatQuote;
        return false;
    }
    return true;
}

} // namespace modelnet
