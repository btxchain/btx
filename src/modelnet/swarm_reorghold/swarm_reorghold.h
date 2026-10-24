// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_H

#include <modelnet/swarm_reorghold/book.h>
#include <modelnet/swarm_reorghold/silence.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Reorganization-exit plane.
 * Several channel ids can be open. A reorganization freezes every open channel.
 * Nothing is broadcast. Earned atoms do not move.
 *
 * Open stores one unfrozen channel and adds earned into the plane counter once.
 * An empty channel is CHANNEL. earned below 0 is ATOMS. A duplicate is REPLAY.
 * Open while frozen is FROZEN and adds nothing.
 *
 * Reorg calls SwarmReorgExit and marks every open channel frozen when that
 * result is frozen and earned_atoms is unchanged. A second Reorg is REPLAY
 * and stays frozen. broadcast(), mined(), and bytes_moved() stay clear.
 * earned() stays the sum recorded at Open.
 *
 * Exit while frozen is FROZEN and does not remove the channel or pay it.
 * Exit of an unknown channel is CHANNEL. Exit before any Reorg is OPEN and
 * does not pay.
 *
 * Refund while frozen is FROZEN and does not build a transaction.
 * Refund before Reorg is HELD and does not broadcast.
 */
class SwarmReorgHold {
public:
    bool Open(const std::string& channel, int64_t earned, std::string& err);
    bool Reorg(std::string& err);
    bool Exit(const std::string& channel, std::string& err);
    bool Refund(const std::string& channel, std::string& err);

    int64_t earned() const;
    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;

    bool frozen() const;
    bool has(const std::string& channel) const;
    bool channel_frozen(const std::string& channel) const;
    int64_t channel_earned(const std::string& channel) const;
    bool paid(const std::string& channel) const;
    bool exited(const std::string& channel) const;
    bool refund_built() const;
    std::size_t channels() const;

private:
    ReorgHoldBook m_book;
    ReorgHoldSilence m_silence;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_H
