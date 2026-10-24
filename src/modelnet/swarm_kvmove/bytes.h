// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_BYTES_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_BYTES_H

#include <vector>

namespace modelnet {

/**
 * Copy page bytes into a new buffer.
 * The result does not alias src. An empty src yields an empty buffer.
 * This is an in-process copy. It does not open a socket.
 */
std::vector<unsigned char> SwarmKvMoveCopyBytes(const std::vector<unsigned char>& src);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_BYTES_H
