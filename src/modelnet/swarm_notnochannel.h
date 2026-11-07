// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHANNEL_H
#define BTX_MODELNET_SWARM_NOTNOCHANNEL_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one channel. channel_id names the channel.
 * want_open_second asks this note to open a second channel.
 *
 * High-speed L2 stays one channel for many pools, and this note opens
 * no second channel. opened stays false and channels stays 0 on every
 * path.
 */
struct SwarmNotNoChannel {
    std::string channel_id;
    bool want_open_second{false};
};

/**
 * Outcome of noting a channel. opened stays false and channels stays 0
 * on every path. High-speed L2 stays one channel for many pools, and
 * this note opens no second channel.
 */
struct SwarmNotNoChannelResult {
    std::string code;
    bool opened{false};
    int64_t channels{0};
};

/**
 * Note a channel without opening a second one.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * want_open_second is ONE_CHANNEL.
 * Otherwise the note is NOTED and err is cleared.
 * opened stays false and channels stays 0 on every path.
 * High-speed L2 stays one channel for many pools, and this note opens
 * no second channel.
 */
SwarmNotNoChannelResult SwarmNoteNotNoChannel(const SwarmNotNoChannel& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHANNEL_H
