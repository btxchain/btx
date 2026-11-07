// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_BOOK_H

#include <modelnet/swarm_reorghold/channel.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Open channels and the plane-wide earned counter.
 * Insert stores one unfrozen channel and adds its earned atoms once.
 * FreezeAll marks every open channel frozen and does not change earned().
 * There is no remove. paid(), exited(), and refund_built() stay false.
 */
class ReorgHoldBook {
public:
    bool reorged() const;
    bool contains(const std::string& channel) const;
    bool channel_frozen(const std::string& channel) const;
    int64_t channel_earned(const std::string& channel) const;
    bool paid(const std::string& channel) const;
    bool exited(const std::string& channel) const;
    bool refund_built() const;
    int64_t earned() const;
    std::size_t size() const;

    /** Sum of earned atoms stored on open channels. False if that sum would wrap. */
    bool Sum(int64_t& total) const;

    /**
     * Store channel unfrozen and add earned into the plane counter.
     * Refuses an empty id, a negative earned, a duplicate, a frozen plane,
     * or a sum that would wrap. On refusal the book is unchanged.
     */
    bool Insert(const std::string& channel, int64_t earned);

    /** Mark every open channel frozen. Earned atoms stay where they are. */
    void FreezeAll();

    /**
     * Keep the plane counter when earned_atoms is the sum already recorded.
     * A different value is refused and the counter stays.
     */
    bool AcceptEarned(int64_t earned_atoms);

private:
    std::map<std::string, ReorgHoldChannel> m_channels;
    int64_t m_earned{0};
    bool m_reorged{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_BOOK_H
