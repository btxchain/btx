// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REALMONEY_H
#define BTX_MODELNET_SWARM_REALMONEY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * real_money marks a real-money channel. want_open asks this note to
 * open it.
 *
 * A real-money channel is not opened. It spends nothing. Currency
 * stays BTX. opened stays false and atoms stays 0 on every path.
 */
struct SwarmRealMoney {
    std::string channel_id;
    bool real_money{false};
    bool want_open{false};
};

/**
 * Outcome of noting a channel. opened stays false and atoms stays 0 on
 * every path. A real-money channel is not opened.
 */
struct SwarmRealMoneyResult {
    std::string code;
    bool opened{false};
    int64_t atoms{0};
};

/**
 * Note a channel without opening a real-money channel.
 * Order, first match wins: an empty channel_id is CHANNEL. real_money
 * is NOT_OPENED even when want_open is false. want_open is HELD.
 * Otherwise the note is NOTED and err is cleared. opened stays false
 * and atoms stays 0 on every path. A real-money channel is not opened.
 */
SwarmRealMoneyResult SwarmNoteRealMoney(const SwarmRealMoney& channel, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REALMONEY_H
