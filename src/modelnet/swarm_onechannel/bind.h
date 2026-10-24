// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_BIND_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_BIND_H

#include <string>

namespace modelnet {

/**
 * Decide whether pool may be bound to the single reserved channel.
 * An empty pool sets err to POOL and stores nothing.
 * A missing reservation sets err to CHANNEL and stores nothing.
 * A pool that is already bound sets err to REPLAY and keeps the first bind.
 * Otherwise err is cleared and the function returns true.
 * The new pool binds to the same channel as every other pool. No second channel is opened.
 */
bool SwarmOneChannelDecideBind(bool channel_reserved, bool already_bound, const std::string& pool, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_BIND_H
