// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/keys.h>

#include <pqkey.h>

namespace modelnet {

bool ChannelSetPubkey(const std::vector<unsigned char>& pubkey)
{
    return pubkey.size() == MLDSA44_PUBKEY_SIZE;
}

} // namespace modelnet
