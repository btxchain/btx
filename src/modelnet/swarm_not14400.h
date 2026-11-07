// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOT14400_H
#define BTX_MODELNET_SWARM_NOT14400_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel counted in blocks. channel_id names the
 * channel. blocks is the block count. want_guarantee asks this note to
 * treat the count as a wall-clock guarantee.
 *
 * 160 blocks is not a wall-clock 14400 seconds. guaranteed stays false,
 * and seconds stays 0, on every path.
 */
struct SwarmNot14400 {
    std::string channel_id;
    int blocks{0};
    bool want_guarantee{false};
};

/**
 * Outcome of noting a block channel. guaranteed stays false, and seconds
 * stays 0, on every path. 160 blocks is not a wall-clock 14400 seconds.
 */
struct SwarmNot14400Result {
    std::string code;
    bool guaranteed{false};
    int seconds{0};
};

/**
 * Note a block channel without treating it as a wall-clock 14400 seconds.
 * Order, first match wins: an empty channel_id is CHANNEL. A block count
 * that is not exactly 160 is NOT_GUARANTEE, even when want_guarantee is
 * false. want_guarantee is NOT_GUARANTEE. Otherwise the note is NOTED and
 * err is clear. 160 blocks is not a wall-clock 14400 seconds. guaranteed
 * stays false, and seconds stays 0, on every path.
 */
SwarmNot14400Result SwarmNoteNot14400(const SwarmNot14400& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOT14400_H
