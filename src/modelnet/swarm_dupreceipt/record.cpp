// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/record.h>

namespace modelnet {

SwarmDupReceiptRow SwarmDupMakeRow(const std::string& receipt)
{
    SwarmDupReceiptRow row;
    row.receipt = receipt;
    row.paid = false;
    row.atoms = 0;
    return row;
}

bool SwarmDupRowBound(const SwarmDupReceiptRow& row)
{
    return !row.receipt.empty() && !row.paid && row.atoms == 0;
}

} // namespace modelnet
