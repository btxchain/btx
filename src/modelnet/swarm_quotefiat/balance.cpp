// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/balance.h>

#include <modelnet/swarm_quotefiat/limits.h>

namespace modelnet {

bool SwarmQuoteFiatBalance::is_balance() const
{
    return kSwarmQuoteFiatUsdIsBalance;
}

} // namespace modelnet
