// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_BLANK_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a witness that can be recorded.
 * A witness is an opaque short label. An empty witness is WITNESS.
 * The caller stores nothing on that result.
 */
class SwarmSchedWitnessBlank {
public:
    bool accept(const std::string& witness, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_BLANK_H
