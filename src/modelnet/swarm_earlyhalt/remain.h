// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_REMAIN_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_REMAIN_H

#include <cstdint>

namespace modelnet {

/**
 * Steps still allowed on the opened row.
 * arm stores the budget once. spend drops the counter by one.
 * freeze sets the counter to zero and leaves the seat's budget alone.
 * There is no method that forgets the counter was armed.
 */
class SwarmEarlyHaltRemain {
public:
    int64_t left() const { return m_left; }
    bool armed() const { return m_armed; }
    bool exhausted() const { return m_left == 0; }

    void arm(int64_t budget);
    void spend();
    void freeze();

private:
    bool m_armed{false};
    int64_t m_left{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_REMAIN_H
