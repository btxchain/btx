// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREALMONEY_H
#define BTX_MODELNET_SWARM_NOTREALMONEY_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_open asks this note to open a
 * real-money channel.
 *
 * Currency stays BTX. This note opens no real-money channel. opened and
 * funded stay false on every path.
 */
struct SwarmNotRealMoney {
    std::string channel_id;
    bool want_open{false};
};

/**
 * Outcome of noting a channel request. opened and funded stay false on
 * every path. Currency stays BTX. This note opens no real-money channel.
 */
struct SwarmNotRealMoneyResult {
    std::string code;
    bool opened{false};
    bool funded{false};
};

/**
 * Note a channel request without opening or funding a real-money channel.
 * Order, first match wins: an empty channel_id is CHANNEL. want_open is
 * REAL_MONEY. Otherwise the note is NOTED and err is clear. opened and
 * funded stay false on every path. Currency stays BTX. This note opens
 * no real-money channel.
 */
SwarmNotRealMoneyResult SwarmNoteNotRealMoney(const SwarmNotRealMoney& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREALMONEY_H
