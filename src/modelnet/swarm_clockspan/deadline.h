// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_DEADLINE_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_DEADLINE_H

#include <string>

namespace modelnet {

/**
 * A 90-second block spacing is not a wall-clock deadline.
 * ClaimDeadline sets err to NOT_DEADLINE and returns false.
 * There is no method that mines, counts a block, or writes a spacing.
 */
class SwarmClockSpanDeadline {
public:
    bool ClaimDeadline(std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_DEADLINE_H
