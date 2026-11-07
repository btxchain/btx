// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_REPLAY_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_REPLAY_H

#include <modelnet/swarm_dupreceipt/book.h>

#include <string>

namespace modelnet {

/** True when receipt is already stored. An empty receipt is never a replay. */
bool SwarmDupBindIsReplay(const SwarmDupReceiptBook& book, const std::string& receipt);

/** True when receipt was already paid. An unpaid or unknown receipt is not a replay. */
bool SwarmDupPayIsReplay(const SwarmDupReceiptBook& book, const std::string& receipt);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_REPLAY_H
