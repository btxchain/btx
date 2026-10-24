// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_WIDTH_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_WIDTH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A positive seconds value other than 90 is SPACING.
 * The caller stores nothing. 90 is not this refusal.
 * A value below 1 is RANGE and is not this refusal.
 */
class SwarmClockSpanWidth {
public:
    bool accept(int64_t seconds, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_WIDTH_H
