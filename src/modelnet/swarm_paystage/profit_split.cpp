// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/profit_split.h>

namespace modelnet {

bool SwarmPayProfitSplit(std::string& err)
{
    // Profit-share is refused. Nothing is moved.
    err = "REFUSED";
    return false;
}

} // namespace modelnet
