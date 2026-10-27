// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_RECORD_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_RECORD_H

#include <cstdint>

namespace modelnet {

/**
 * Step counter for one scale.
 * Make starts it at 0. advance adds 1 to this counter only.
 * There is no setter that copies another scale's step onto this one.
 */
class SwarmFourScaleRecord {
public:
    static SwarmFourScaleRecord Make();

    int64_t steps() const { return m_steps; }

    /** Add one. A counter that cannot grow stays where it is and returns false. */
    bool advance();

private:
    int64_t m_steps{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_RECORD_H
