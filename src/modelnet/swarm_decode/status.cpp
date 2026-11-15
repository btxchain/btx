// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/status.h>

#include <cstdint>

namespace modelnet {

bool SwarmDecodeStatus::measured() const
{
    return m_measured;
}

bool SwarmDecodeStatus::launched() const
{
    return m_launched;
}

bool SwarmDecodeStatus::gpu() const
{
    return m_gpu;
}

int64_t SwarmDecodeStatus::bytes_moved() const
{
    return m_bytes_moved;
}

} // namespace modelnet
