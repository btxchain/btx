// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/replay.h>

namespace modelnet {

bool SwarmDupBindIsReplay(const SwarmDupReceiptBook& book, const std::string& receipt)
{
    if (receipt.empty()) {
        return false;
    }
    return book.contains(receipt);
}

bool SwarmDupPayIsReplay(const SwarmDupReceiptBook& book, const std::string& receipt)
{
    if (receipt.empty()) {
        return false;
    }
    return book.paid(receipt);
}

} // namespace modelnet
