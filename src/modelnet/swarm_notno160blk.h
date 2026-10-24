// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO160BLK_H
#define BTX_MODELNET_SWARM_NOTNO160BLK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * want_close asks this note to close.
 *
 * A 160-block close margin is not a wall-clock guarantee and this note
 * closes nothing. closed stays false, and l1_txs stays 0, on every path.
 */
struct SwarmNotNo160Blk {
    std::string channel_id;
    bool want_close{false};
};

/**
 * Outcome of noting a channel. closed stays false, and l1_txs stays 0,
 * on every path. A 160-block close margin is not a wall-clock guarantee
 * and this note closes nothing.
 */
struct SwarmNotNo160BlkResult {
    std::string code;
    bool closed{false};
    int64_t l1_txs{0};
};

/**
 * Note a channel without closing it. Order, first match wins: an empty
 * channel_id is CHANNEL. want_close is NOT_WALLCLOCK. Otherwise the note
 * is NOTED and err is clear. closed stays false, and l1_txs stays 0, on
 * every path. A 160-block close margin is not a wall-clock guarantee and
 * this note closes nothing.
 */
SwarmNotNo160BlkResult SwarmNoteNotNo160Blk(const SwarmNotNo160Blk& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO160BLK_H
