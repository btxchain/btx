// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_MARK_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_MARK_H

namespace modelnet {

/**
 * Drain latch.
 * raise sets it. Nothing in this type clears it. A later admit sees
 * the latch and does not add a worker. A second matching drain sees
 * it and does not run again.
 */
class SwarmIdleDrainMark {
public:
    bool set() const { return m_set; }
    void raise();

private:
    bool m_set{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_MARK_H
