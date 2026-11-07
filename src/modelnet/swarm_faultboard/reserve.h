// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_RESERVE_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_RESERVE_H

#include <cstdint>

namespace modelnet {

/**
 * One collateral reservation and the reorg freeze bit.
 * store accepts a single amount that is already known to be >= 1.
 * A second store is refused and the first amount stays.
 * Freeze does not clear the reservation and does not touch earned rows.
 */
class SwarmFaultReserve {
public:
    bool frozen() const;
    bool has() const;
    int64_t amount() const;
    void Freeze();
    bool store(int64_t amount);

private:
    bool m_frozen{false};
    bool m_set{false};
    int64_t m_amount{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_RESERVE_H
