// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_H

#include <modelnet/swarm_channelset/record.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Channel settlement plane.
 * Open stores one channel. Fund notes funding on its in-memory
 * SwarmChannelTx. Refund and Payout build in-memory templates through
 * SwarmBuildRefund and SwarmBuildPayout. ClaimAllowed returns
 * SwarmClaimBeforeRefund. Nothing is broadcast or mined. No spend key
 * is stored. automatic_spend() stays "0". broadcast(), mined(), and
 * multi_hop_qualified() stay false. bytes_moved() stays 0.
 */
class SwarmChannelSet {
public:
    /**
     * An empty name is CHANNEL and stores nothing.
     * capacity below 1 is CAPACITY and stores nothing.
     * A pubkey whose size is not MLDSA44_PUBKEY_SIZE is KEY and stores nothing.
     * A second open of any valid name is NOT_OPENED and leaves the first.
     */
    bool Open(const std::string& name, int64_t capacity, const std::vector<unsigned char>& sponsor_pubkey,
              const std::vector<unsigned char>& worker_pubkey, std::string& err);

    /**
     * Calls SwarmBuildRefund. refund_built() becomes true on success.
     * A second call is REPLAY. The template is not broadcast.
     */
    bool Refund(int refund_height, std::string& err);

    /**
     * Calls SwarmNoteChannelFunding. A second success is REPLAY.
     * This does not broadcast.
     */
    bool Fund(std::string& err);

    /**
     * Requires funding. A refund height that is not more than 160 blocks
     * above height is MARGIN and does not pay. cumulative above capacity
     * is SHORT and leaves cumulative unchanged. A second payout with a
     * lower cumulative is STALE. Otherwise calls SwarmBuildPayout.
     * The template is not broadcast.
     */
    bool Payout(int64_t cumulative, int height, int refund_height, std::string& err);

    /** Returns SwarmClaimBeforeRefund. Does not broadcast. */
    bool ClaimAllowed(int height, int refund_height) const;

    const std::string& name() const;
    int64_t capacity() const;
    int64_t cumulative() const;
    int refund_height() const;
    bool funded() const;
    bool refund_built() const;
    int64_t refund_value() const;
    std::size_t refund_outputs() const;
    int64_t payout_worker_value() const;
    int64_t payout_sponsor_value() const;
    std::size_t payout_outputs() const;

    /** Stays the string "0". */
    std::string automatic_spend() const;
    /** Always false. */
    bool broadcast() const;
    /** Always false. */
    bool mined() const;
    /** Always 0. */
    int64_t bytes_moved() const;
    /** Always false. There is no method that sets this true. */
    bool multi_hop_qualified() const;

private:
    ChannelSetRecord m_record;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_H
