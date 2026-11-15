// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_POLICY_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_POLICY_H

#include <cstdint>
#include <string>

namespace modelnet {

/** The automatic spend amount. This stays the string "0". */
std::string ChannelSetAutomaticSpend();

/** Nothing is broadcast. */
bool ChannelSetBroadcast();

/** Nothing is mined. */
bool ChannelSetMined();

/** No template bytes are moved. This stays 0. */
int64_t ChannelSetBytesMoved();

/**
 * Multi-hop qualified stays false.
 * There is no function here that can set it true.
 */
bool ChannelSetMultiHopQualified();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_POLICY_H
