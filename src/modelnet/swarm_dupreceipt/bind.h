// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_BIND_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_BIND_H

#include <modelnet/swarm_dupreceipt/book.h>

#include <string>

namespace modelnet {

/**
 * Binds one receipt.
 * An empty receipt is RECEIPT and the book stays as it was.
 * A second Bind of the same receipt is REPLAY and leaves the first row.
 * Those checks run in that order. A successful Bind adds no atoms.
 */
class SwarmDupBind {
public:
    bool Apply(SwarmDupReceiptBook& book, const std::string& receipt, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_BIND_H
