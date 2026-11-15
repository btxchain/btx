// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLOSE160_H
#define BTX_MODELNET_SWARM_NOTNOCLOSE160_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * want_close asks this note to close.
 *
 * The close margin stays 160 blocks. This note closes nothing.
 * closed stays false and height stays 0 on every path.
 */
struct SwarmNotNoClose160 {
    std::string channel_id;
    bool want_close{false};
};

/**
 * Outcome of noting a channel. closed stays false and height stays 0
 * on every path. The close margin stays 160 blocks. This note closes
 * nothing.
 */
struct SwarmNotNoClose160Result {
    std::string code;
    bool closed{false};
    int64_t height{0};
};

/**
 * Note a channel without closing it. Order, first match wins: an empty
 * channel_id is CHANNEL. want_close is HELD. Otherwise the note is NOTED
 * and err is clear. closed stays false and height stays 0 on every path.
 * The close margin stays 160 blocks. This note closes nothing.
 */
SwarmNotNoClose160Result SwarmNoteNotNoClose160(const SwarmNotNoClose160& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLOSE160_H
