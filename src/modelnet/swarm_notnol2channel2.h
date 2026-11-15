// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOL2CHANNEL2_H
#define BTX_MODELNET_SWARM_NOTNOL2CHANNEL2_H

#include <string>

namespace modelnet {

/**
 * A local note about one high-speed channel. channel_id names the channel.
 * second_channel asks for a second channel. want_open asks this note to open it.
 *
 * High-speed L2 stays one channel. opened stays false on every path.
 */
struct SwarmNotNoL2Channel2 {
    std::string channel_id;
    bool second_channel{false};
    bool want_open{false};
};

/**
 * Outcome of noting one high-speed channel. opened stays false on every path.
 * High-speed L2 stays one channel.
 */
struct SwarmNotNoL2Channel2Result {
    std::string code;
    bool opened{false};
};

/**
 * Note one high-speed channel without opening a second one.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * second_channel is NOT_OPENED, even when want_open is false.
 * want_open is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * opened stays false on every path.
 * High-speed L2 stays one channel.
 */
SwarmNotNoL2Channel2Result SwarmNoteNotNoL2Channel2(const SwarmNotNoL2Channel2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOL2CHANNEL2_H
