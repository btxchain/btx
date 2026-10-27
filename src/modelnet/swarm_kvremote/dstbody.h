// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVREMOTE_DSTBODY_H
#define BITCOIN_MODELNET_SWARM_KVREMOTE_DSTBODY_H

#include <vector>

namespace modelnet {

/**
 * One byte that differs from body.
 * Transfer stores this as the dst placeholder. It is not the page copy.
 * The page copy is SwarmKvMove::Move.
 */
std::vector<unsigned char> SwarmKvRemoteDifferentByte(const std::vector<unsigned char>& body);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVREMOTE_DSTBODY_H
