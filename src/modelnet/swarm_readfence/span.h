// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_SPAN_H
#define BITCOIN_MODELNET_SWARM_READFENCE_SPAN_H

#include <cstdint>

namespace modelnet {

/**
 * One accepted size.
 * Store keeps a size only when it is greater than 0 and at most 33554432.
 * Any other size is refused and the previously stored size stays.
 * Nothing is stored until the first accepted size.
 */
class SwarmReadSpan {
public:
    bool held() const { return m_held; }
    int64_t size() const { return m_held ? m_size : 0; }

    bool Store(int64_t size);

private:
    bool m_held{false};
    int64_t m_size{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_SPAN_H
