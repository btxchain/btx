// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_EPOCH_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_EPOCH_H

#include <cstdint>

namespace modelnet {

/**
 * The stored coordinator epoch.
 * The initial value is 0. Assign replaces it. There is no rewind helper.
 */
class SwarmFaultEpoch {
public:
    int64_t get() const;
    void Assign(int64_t epoch);

private:
    int64_t m_epoch{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_EPOCH_H
