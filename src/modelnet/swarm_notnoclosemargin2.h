// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLOSEMARGIN2_H
#define BTX_MODELNET_SWARM_NOTNOCLOSEMARGIN2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * want_shrink asks this note to shrink the close margin.
 *
 * The close margin stays 160 blocks. This note shrinks nothing.
 * shrunk stays false and blocks stays 160 on every path.
 */
struct SwarmNotNoCloseMargin2 {
    std::string channel_id;
    bool want_shrink{false};
};

/**
 * Outcome of noting a channel. shrunk stays false and blocks stays 160
 * on every path. The close margin stays 160 blocks.
 */
struct SwarmNotNoCloseMargin2Result {
    std::string code;
    bool shrunk{false};
    int64_t blocks{160};
};

/**
 * Note a channel without shrinking its close margin.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * want_shrink is HELD. Otherwise the note is NOTED and err is cleared.
 * shrunk stays false and blocks stays 160 on every path.
 * The close margin stays 160 blocks.
 */
SwarmNotNoCloseMargin2Result SwarmNoteNotNoCloseMargin2(const SwarmNotNoCloseMargin2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLOSEMARGIN2_H
