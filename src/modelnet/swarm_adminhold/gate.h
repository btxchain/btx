// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_GATE_H

#include <modelnet/swarm_adminhold/book.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Refusal code for an Open that must not store, or empty when the
 * channel may be stored.
 * An empty channel is CHANNEL. refund_height below 1 is HEIGHT.
 * A sponsor_key size other than 1312 is KEY. A channel already stored,
 * after the attempt would otherwise be stored, is REPLAY.
 * This function does not modify the book.
 */
std::string SwarmAdminHoldRefusal(const SwarmAdminHoldBook& book,
                                   const std::string& channel,
                                   int64_t refund_height,
                                   const std::vector<unsigned char>& sponsor_key);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_GATE_H
