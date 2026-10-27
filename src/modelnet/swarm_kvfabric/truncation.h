// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_TRUNCATION_H
#define BTX_MODELNET_SWARM_KVFABRIC_TRUNCATION_H

#include <modelnet/swarm_kvfabric/result.h>

#include <cstdint>

namespace modelnet {

/** Largest cache body the control plane will accept. 32 MiB. */
inline constexpr int64_t kKvFabricCacheBodyMax = 33554432;

/**
 * Accept records a cache-body size when size > 0 and size <= 33554432.
 * Any other size is TRUNCATED and stores nothing. The body bytes are not retained.
 */
class KvFabricTruncation {
public:
    SwarmKvFabricResult Accept(int64_t size);
    bool accepted() const { return m_accepted; }
    int64_t admitted_size() const { return m_size; }
    bool body_retained() const;

private:
    bool m_accepted{false};
    int64_t m_size{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_TRUNCATION_H
