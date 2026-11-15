// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_EXIT_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_EXIT_H

#include <modelnet/swarm_reorghold/book.h>

#include <string>

namespace modelnet {

/**
 * Refuse to exit a channel.
 * An unknown id is CHANNEL. A frozen channel is FROZEN and is not removed or paid.
 * A channel that is still open is OPEN and is not paid.
 */
bool ReorgHoldExit(ReorgHoldBook& book, const std::string& channel, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_EXIT_H
