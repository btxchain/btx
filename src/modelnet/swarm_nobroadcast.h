// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOBROADCAST_H
#define BTX_MODELNET_SWARM_NOBROADCAST_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_mainnet asks this note to
 * broadcast on mainnet.
 *
 * Nothing is broadcast on mainnet. broadcast stays false on every path.
 */
struct SwarmNoBroadcast {
    std::string channel_id;
    bool want_mainnet{false};
};

/**
 * Outcome of noting a channel. broadcast stays false on every path:
 * a note is recorded and nothing is broadcast on mainnet.
 */
struct SwarmNoBroadcastResult {
    std::string code;
    bool broadcast{false};
};

/**
 * Note a channel without broadcasting.
 * Order, first match wins: an empty channel_id is BROADCAST.
 * want_mainnet is MAINNET. Otherwise the note is NOTED and err is clear.
 * broadcast stays false on every path. Nothing is broadcast on mainnet.
 */
SwarmNoBroadcastResult SwarmNoteNoBroadcast(const SwarmNoBroadcast& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOBROADCAST_H
