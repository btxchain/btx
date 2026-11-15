// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/truncation.h>

#include <modelnet/swarm_kvfabric/codes.h>

namespace modelnet {

SwarmKvFabricResult KvFabricTruncation::Accept(int64_t size)
{
    if (size <= 0 || size > kKvFabricCacheBodyMax) {
        return KvFabricResult(kKvFabricTruncated);
    }
    // Record the admitted length only. No cache body is copied.
    m_accepted = true;
    m_size = size;
    return KvFabricResult(kKvFabricAccepted);
}

bool KvFabricTruncation::body_retained() const
{
    return false;
}

} // namespace modelnet
