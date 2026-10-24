// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_STATUS_H
#define BITCOIN_MODELNET_SWARM_DECODE_STATUS_H

#include <cstdint>

namespace modelnet {

/**
 * Flags that stay at their initial values.
 * measured(), launched(), and gpu() stay false.
 * bytes_moved() stays 0.
 * A memory Pull appends prompt bytes to text() and does not write these fields.
 * Appended decode bytes are not counted here.
 */
class SwarmDecodeStatus {
public:
    bool measured() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;

private:
    bool m_measured{false};
    bool m_launched{false};
    bool m_gpu{false};
    int64_t m_bytes_moved{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_STATUS_H
