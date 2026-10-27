// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/bind.h>

#include <modelnet/swarm_dupreceipt/codes.h>
#include <modelnet/swarm_dupreceipt/gate.h>

namespace modelnet {

bool SwarmDupBind::Apply(SwarmDupReceiptBook& book, const std::string& receipt, std::string& err) const
{
    const std::string refusal = SwarmDupBindRefusal(book, receipt);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.store(receipt)) {
        if (receipt.empty()) {
            err = kSwarmDupReceipt;
        } else {
            err = kSwarmDupReplay;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
