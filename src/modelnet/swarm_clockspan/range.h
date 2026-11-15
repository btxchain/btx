// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_RANGE_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_RANGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * seconds below 1 is RANGE. The caller stores nothing.
 * A value of 1 or more is not this refusal.
 */
class SwarmClockSpanRange {
public:
    bool accept(int64_t seconds, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_RANGE_H
