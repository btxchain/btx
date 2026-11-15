// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_BYTES_H
#define BTX_MODELNET_SWARM_KVFABRIC_BYTES_H

namespace modelnet {

/** The KV fabric control plane never moves bytes. */
bool KvFabricBytesMoved();

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_BYTES_H
