// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_EPOCH_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_EPOCH_H

#include <cstdint>

namespace modelnet {

/**
 * Fence epoch. Starts at 1.
 * Bump moves it forward by one. Stored grants keep the epoch they were
 * given and are not rewritten here.
 */
class LeaseWorkEpoch {
public:
    int64_t current() const;
    void Bump();

private:
    int64_t m_epoch{1};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_EPOCH_H
