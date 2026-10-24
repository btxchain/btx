// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOREALMONEY_H
#define BTX_MODELNET_SWARM_NOREALMONEY_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_real_money asks this note to
 * open a real-money channel.
 *
 * There are no real-money channels. opened and broadcast stay false
 * on every path.
 */
struct SwarmNoRealMoney {
    std::string channel_id;
    bool want_real_money{false};
};

/**
 * Outcome of noting a channel. opened and broadcast stay false on
 * every path: a note is recorded and no real-money channel is opened
 * or broadcast.
 */
struct SwarmNoRealMoneyResult {
    std::string code;
    bool opened{false};
    bool broadcast{false};
};

/**
 * Note a channel without opening or broadcasting a real-money channel.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * want_real_money is REAL_MONEY. Otherwise the note is NOTED and err
 * is clear. opened and broadcast stay false on every path. There are
 * no real-money channels.
 */
SwarmNoRealMoneyResult SwarmNoteNoRealMoney(const SwarmNoRealMoney& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOREALMONEY_H
