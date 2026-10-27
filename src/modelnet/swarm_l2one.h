// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_L2ONE_H
#define BTX_MODELNET_SWARM_L2ONE_H

#include <string>

namespace modelnet {

/**
 * A high-speed channel record. channel_id names the channel.
 * second_channel asks to open a second channel. want_open asks to
 * open this channel. One channel serves many pools.
 *
 * A second high-speed channel is not opened.
 */
struct SwarmL2One {
    std::string channel_id;
    bool second_channel{false};
    bool want_open{false};
};

/**
 * Outcome of keeping one channel. opened stays false: a second
 * high-speed channel is not opened.
 */
struct SwarmL2OneResult {
    std::string code;
    bool opened{false};
};

/**
 * Keep one high-speed channel. A second channel is not opened.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * second_channel is NOT_OPENED, even when want_open is false.
 * want_open is HELD. Otherwise the note is NOTED and err is clear.
 * opened stays false on every path.
 * A second high-speed channel is not opened.
 */
SwarmL2OneResult SwarmKeepOneChannel(const SwarmL2One& channel, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_L2ONE_H
