// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLOSE1602_H
#define BTX_MODELNET_SWARM_NOTNOCLOSE1602_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * margin_blocks is the close margin in blocks. want_close asks this
 * note to close.
 *
 * A close margin stays 160 blocks and this note closes nothing.
 * closed stays false on every path.
 */
struct SwarmNotNoClose1602 {
    std::string channel_id;
    int32_t margin_blocks{0};
    bool want_close{false};
};

/**
 * Outcome of noting a channel. closed stays false on every path.
 * A close margin stays 160 blocks and this note closes nothing.
 */
struct SwarmNotNoClose1602Result {
    std::string code;
    bool closed{false};
};

/**
 * Note a channel without closing it.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * margin_blocks other than 160 is CAPPED even when want_close is false.
 * want_close is CAPPED. Otherwise the note is NOTED and err is cleared.
 * closed stays false on every path. A close margin stays 160 blocks and
 * this note closes nothing.
 */
SwarmNotNoClose1602Result SwarmNoteNotNoClose1602(const SwarmNotNoClose1602& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLOSE1602_H
