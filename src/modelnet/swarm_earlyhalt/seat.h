// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_SEAT_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_SEAT_H

#include <cstdint>

namespace modelnet {

/**
 * The opened row's budget.
 * admit stores a budget once. A later admit does not replace it.
 * There is no method that drops the seat. An early stop leaves it.
 */
class SwarmEarlyHaltSeat {
public:
    bool opened() const { return m_opened; }
    int64_t budget() const { return m_budget; }

    void admit(int64_t budget);

private:
    bool m_opened{false};
    int64_t m_budget{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_SEAT_H
