// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_BOOK_H

#include <modelnet/swarm_adminhold/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Channels stored by a successful Open, keyed by channel id.
 * store refuses an empty channel, a height below 1, a key whose size
 * is other than 1312, and a channel already present.
 * A refused store leaves the first height and key in place.
 * There is no method that writes a new height or a new key.
 */
class SwarmAdminHoldBook {
public:
    bool contains(const std::string& channel) const;
    int64_t height_of(const std::string& channel) const;
    std::vector<unsigned char> key_of(const std::string& channel) const;
    std::size_t size() const;

    /**
     * Store channel with its refund height and sponsor key.
     * Refuses an unusable record and a duplicate channel. On refusal
     * the book is unchanged.
     */
    bool store(const std::string& channel, int64_t refund_height, const std::vector<unsigned char>& sponsor_key);

private:
    std::map<std::string, SwarmAdminHoldRecord> m_channels;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_BOOK_H
