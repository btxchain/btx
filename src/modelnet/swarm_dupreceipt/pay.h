// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_PAY_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_PAY_H

#include <modelnet/swarm_dupreceipt/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Pays one bound receipt once.
 * An unknown receipt is RECEIPT and adds nothing.
 * atoms below 1 is ATOMS and adds nothing.
 * A second Pay is REPLAY and leaves earned unchanged.
 * A research key or a scheduler is NOT_SIGNED and leaves the receipt unpaid.
 * A sum that would pass int64 max is ATOMS and leaves the receipt unpaid.
 * Those checks run in that order.
 */
class SwarmDupPay {
public:
    bool Apply(SwarmDupReceiptBook& book,
               const std::string& receipt,
               int64_t atoms,
               bool research_key,
               bool scheduler,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_PAY_H
