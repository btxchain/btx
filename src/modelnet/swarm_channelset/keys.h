// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_KEYS_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_KEYS_H

#include <vector>

namespace modelnet {

/**
 * True when pubkey.size() is MLDSA44_PUBKEY_SIZE from pqkey.h (1312).
 * Any other size, including a spend-key sized buffer, is refused.
 * This function does not copy the bytes and does not store a spend key.
 */
bool ChannelSetPubkey(const std::vector<unsigned char>& pubkey);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_KEYS_H
