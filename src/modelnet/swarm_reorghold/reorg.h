// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_REORG_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_REORG_H

#include <modelnet/swarm_reorghold/book.h>

#include <string>

namespace modelnet {

/**
 * Freeze every open channel.
 * Calls SwarmReorgExit and freezes only when that result stays frozen with the
 * same earned atoms. A second call is REPLAY and leaves the freeze in place.
 * Earned atoms are not moved.
 */
bool ReorgHoldReorg(ReorgHoldBook& book, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_REORG_H
