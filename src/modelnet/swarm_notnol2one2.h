// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOL2ONE2_H
#define BTX_MODELNET_SWARM_NOTNOL2ONE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one high-speed channel. channel_id names the channel.
 * many_pools says many pools share it. want_split asks this note to split it.
 *
 * High-speed L2 stays one channel for many pools. split stays false on
 * every path.
 */
struct SwarmNotNoL2One2 {
    std::string channel_id;
    bool many_pools{false};
    bool want_split{false};
};

/**
 * Outcome of noting one high-speed channel. split stays false on every path.
 * High-speed L2 stays one channel for many pools.
 */
struct SwarmNotNoL2One2Result {
    std::string code;
    bool split{false};
};

/**
 * Note one high-speed channel without splitting it.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * many_pools is STAYS, even when want_split is false.
 * want_split is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * split stays false on every path.
 * High-speed L2 stays one channel for many pools.
 */
SwarmNotNoL2One2Result SwarmNoteNotNoL2One2(const SwarmNotNoL2One2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOL2ONE2_H
