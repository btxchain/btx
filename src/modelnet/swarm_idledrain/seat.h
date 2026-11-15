// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_SEAT_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_SEAT_H

namespace modelnet {

/**
 * Whether Open has already been accepted.
 * admit records it once. A later admit does not clear it.
 * The worker count is not stored here.
 */
class SwarmIdleDrainSeat {
public:
    bool opened() const { return m_opened; }
    void admit();

private:
    bool m_opened{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_SEAT_H
