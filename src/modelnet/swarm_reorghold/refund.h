// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_REFUND_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_REFUND_H

#include <modelnet/swarm_reorghold/book.h>

#include <string>

namespace modelnet {

/**
 * Refuse to refund a channel.
 * An unknown id is CHANNEL. A frozen channel is FROZEN and builds no transaction.
 * Before Reorg the refund is HELD and nothing is broadcast.
 */
bool ReorgHoldRefund(ReorgHoldBook& book, const std::string& channel, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_REFUND_H
