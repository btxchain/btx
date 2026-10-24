// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBROADCAST_H
#define BTX_MODELNET_SWARM_NOTNOBROADCAST_H

#include <string>

namespace modelnet {

/**
 * A local note about one chain. mainnet marks the note as mainnet.
 * want_broadcast asks this note to broadcast.
 *
 * Nothing is broadcast on mainnet. broadcast stays false and l1_txs
 * stays 0 on every path.
 */
struct SwarmNotNoBroadcast {
    std::string chain_id;
    bool mainnet{false};
    bool want_broadcast{false};
};

/**
 * Outcome of noting a chain. broadcast stays false and l1_txs stays 0
 * on every path. Nothing is broadcast on mainnet.
 */
struct SwarmNotNoBroadcastResult {
    std::string code;
    bool broadcast{false};
    int l1_txs{0};
};

/**
 * Note a chain without broadcasting.
 * Order, first match wins: an empty chain_id is CHAIN. mainnet is
 * NOT_BROADCAST even when want_broadcast is false. want_broadcast is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * broadcast stays false and l1_txs stays 0 on every path. Nothing is
 * broadcast on mainnet.
 */
SwarmNotNoBroadcastResult SwarmNoteNotNoBroadcast(const SwarmNotNoBroadcast& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBROADCAST_H
