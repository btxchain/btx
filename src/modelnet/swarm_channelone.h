// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CHANNELONE_H
#define BTX_MODELNET_SWARM_CHANNELONE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One payment channel. Open stores the channel name and its capacity.
 * A second channel is not opened; the first channel stays in place.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmChannelOne {
public:
    /**
     * An empty channel is CHANNEL and stores nothing.
     * capacity below 1 is CAPACITY and stores nothing.
     * When a channel is already open, the call returns false, sets err
     * to NOT_OPENED, and leaves the first channel and its capacity.
     * Otherwise the call stores the channel and capacity, clears err,
     * and returns true.
     */
    bool Open(const std::string& channel, int64_t capacity, std::string& err);

    /** The stored channel name, or empty when none is open. */
    const std::string& open_channel() const;

    /** The stored capacity, or 0 when none is open. */
    int64_t capacity() const;

private:
    std::string m_channel;
    int64_t m_capacity{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CHANNELONE_H
