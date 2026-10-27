// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_OPEN_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_OPEN_H

#include <modelnet/swarm_channelset/record.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Open one channel on record.
 * An empty name is CHANNEL and stores nothing.
 * capacity below 1 is CAPACITY and stores nothing.
 * A sponsor or worker pubkey whose size is not MLDSA44_PUBKEY_SIZE is KEY
 * and stores nothing.
 * When a channel is already open, any further valid name is NOT_OPENED
 * and the first name, capacity, and pubkeys stay.
 */
bool ChannelSetOpen(ChannelSetRecord& record, const std::string& name, int64_t capacity,
                    const std::vector<unsigned char>& sponsor_pubkey,
                    const std::vector<unsigned char>& worker_pubkey, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_OPEN_H
