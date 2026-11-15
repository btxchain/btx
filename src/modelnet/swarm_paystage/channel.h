// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_CHANNEL_H
#define BTX_MODELNET_SWARM_PAYSTAGE_CHANNEL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One payment channel. The first Open stores the name and capacity.
 * A second Open is refused and the first channel stays in place.
 * Debit subtracts from that channel's remaining atoms.
 */
class SwarmPayChannel {
public:
    /**
     * An empty name is CHANNEL and stores nothing.
     * capacity below 1 is CAPACITY and stores nothing.
     * When a channel is already open, the call is NOT_OPENED and leaves
     * the first name, capacity, and remaining atoms.
     */
    bool Open(const std::string& name, int64_t capacity, std::string& err);

    /**
     * No open channel is CHANNEL and subtracts nothing.
     * atoms below 1 is ATOMS and remaining stays.
     * atoms greater than remaining is SHORT and remaining stays.
     * Otherwise remaining decreases by atoms.
     */
    bool Debit(int64_t atoms, std::string& err);

    /**
     * Remaining atoms of the open channel when name is that channel.
     * An unknown channel, including when none is open, is -1.
     */
    int64_t Remaining(const std::string& name) const;

    /** The stored channel name, or empty when none is open. */
    const std::string& open_channel() const;

    /** The stored capacity, or 0 when none is open. */
    int64_t capacity() const;

private:
    bool m_open{false};
    std::string m_name;
    int64_t m_capacity{0};
    int64_t m_remaining{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_CHANNEL_H
