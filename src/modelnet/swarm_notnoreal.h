// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREAL_H
#define BTX_MODELNET_SWARM_NOTNOREAL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_open asks this note to open a
 * real-money channel.
 *
 * A real-money channel is not opened. opened stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotNoReal {
    std::string channel_id;
    bool want_open{false};
};

/**
 * Outcome of noting a channel request. opened stays false and atoms stays
 * 0 on every path. A real-money channel is not opened.
 */
struct SwarmNotNoRealResult {
    std::string code;
    bool opened{false};
    int64_t atoms{0};
};

/**
 * Note a channel request without opening a real-money channel.
 * Order, first match wins: an empty channel_id is CHANNEL. want_open is
 * REAL_MONEY. Otherwise the note is NOTED and err is clear. opened stays
 * false and atoms stays 0 on every path. A real-money channel is not opened.
 */
SwarmNotNoRealResult SwarmNoteNotNoReal(const SwarmNotNoReal& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREAL_H
