// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_OPEN_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_OPEN_H

#include <modelnet/swarm_reorghold/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Open one channel.
 * An empty id is CHANNEL. earned below 0 is ATOMS. A frozen plane is FROZEN
 * and adds nothing. A duplicate id is REPLAY and adds nothing.
 * Success stores the channel unfrozen and adds earned once.
 */
bool ReorgHoldOpen(ReorgHoldBook& book, const std::string& channel, int64_t earned, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_OPEN_H
