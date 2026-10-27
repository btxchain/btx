// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO14400_H
#define BTX_MODELNET_SWARM_NOTNO14400_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * want_close asks this note to close.
 *
 * 160 blocks at 90 seconds is 14400 seconds and is not a wall-clock
 * close. closed stays false, and l1_txs stays 0, on every path.
 */
struct SwarmNotNo14400 {
    std::string channel_id;
    bool want_close{false};
};

/**
 * Outcome of noting a channel. closed stays false, and l1_txs stays 0,
 * on every path. 160 blocks at 90 seconds is 14400 seconds and is not
 * a wall-clock close.
 */
struct SwarmNotNo14400Result {
    std::string code;
    bool closed{false};
    int l1_txs{0};
};

/**
 * Note a channel without closing it. Order, first match wins: an empty
 * channel_id is CHANNEL. want_close is NOT_WALLCLOCK. Otherwise the note
 * is NOTED and err is clear. closed stays false, and l1_txs stays 0, on
 * every path. 160 blocks at 90 seconds is 14400 seconds and is not a
 * wall-clock close.
 */
SwarmNotNo14400Result SwarmNoteNotNo14400(const SwarmNotNo14400& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO14400_H
