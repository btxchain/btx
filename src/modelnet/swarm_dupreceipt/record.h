// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_RECORD_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One bound receipt.
 * atoms is the amount from the first successful Pay, and 0 until then.
 * A second Pay does not replace atoms. A second Bind does not replace the row.
 */
struct SwarmDupReceiptRow {
    std::string receipt;
    bool paid{false};
    int64_t atoms{0};
};

/** An unpaid row for receipt. atoms stays 0 until the first Pay. */
SwarmDupReceiptRow SwarmDupMakeRow(const std::string& receipt);

/** The receipt id is non-empty and the row has not been paid. */
bool SwarmDupRowBound(const SwarmDupReceiptRow& row);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_RECORD_H
