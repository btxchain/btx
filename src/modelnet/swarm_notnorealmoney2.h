// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREALMONEY2_H
#define BTX_MODELNET_SWARM_NOTNOREALMONEY2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * real_money marks a real-money channel. want_open asks this note to
 * open it.
 *
 * No real-money channel is opened. opened stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotNoRealMoney2 {
    std::string channel_id;
    bool real_money{false};
    bool want_open{false};
};

/**
 * Outcome of noting a channel. opened stays false and atoms stays 0 on
 * every path. No real-money channel is opened.
 */
struct SwarmNotNoRealMoney2Result {
    std::string code;
    bool opened{false};
    int64_t atoms{0};
};

/**
 * Note a channel without opening a real-money channel.
 * Order, first match wins: an empty channel_id is CHANNEL. real_money
 * is NOT_OPENED even when want_open is false. want_open is HELD.
 * Otherwise the note is NOTED and err is cleared. opened stays false
 * and atoms stays 0 on every path. No real-money channel is opened.
 */
SwarmNotNoRealMoney2Result SwarmNoteNotNoRealMoney2(const SwarmNotNoRealMoney2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREALMONEY2_H
