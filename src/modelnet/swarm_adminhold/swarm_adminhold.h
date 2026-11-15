// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_H

#include <modelnet/swarm_adminhold/book.h>
#include <modelnet/swarm_adminhold/quiet.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Admin-hold plane.
 * An admin cannot move the sponsor refund key or the refund height.
 *
 * Open stores a channel, its refund height, and its sponsor key.
 * An empty channel is CHANNEL and stores nothing.
 * refund_height below 1 is HEIGHT and stores nothing.
 * A sponsor_key whose size is other than 1312 is KEY and stores nothing.
 * A second Open of the same channel is REPLAY and keeps the first
 * height and key. CHANNEL, HEIGHT, and KEY are decided before REPLAY.
 *
 * MoveHeight returns HELD and leaves the stored height unchanged.
 * MoveKey returns HELD and leaves the stored key unchanged.
 * An unknown channel on either move is CHANNEL.
 *
 * broadcast() stays false. mined() stays false.
 * bytes_moved() stays 0. automatic_spend() stays "0".
 */
class SwarmAdminHold {
public:
    bool Open(const std::string& channel,
              int64_t refund_height,
              const std::vector<unsigned char>& sponsor_key,
              std::string& err);
    bool MoveHeight(const std::string& channel, int64_t next_height, std::string& err) const;
    bool MoveKey(const std::string& channel,
                 const std::vector<unsigned char>& next_key,
                 std::string& err) const;

    bool opened(const std::string& channel) const;
    int64_t refund_height(const std::string& channel) const;
    std::vector<unsigned char> sponsor_key(const std::string& channel) const;
    std::size_t channel_count() const;

    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;

private:
    SwarmAdminHoldBook m_book;
    SwarmAdminHoldQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_H
