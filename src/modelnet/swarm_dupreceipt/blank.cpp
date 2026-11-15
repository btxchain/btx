// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/blank.h>

#include <modelnet/swarm_dupreceipt/codes.h>

namespace modelnet {

bool SwarmDupBlank::accept(const std::string& receipt, std::string& err) const
{
    if (receipt.empty()) {
        err = kSwarmDupReceipt;
        return false;
    }
    return true;
}

} // namespace modelnet
