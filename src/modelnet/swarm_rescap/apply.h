// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_APPLY_H
#define BITCOIN_MODELNET_SWARM_RESCAP_APPLY_H

#include <modelnet/swarm_rescap/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Records one thread count and leaves it unraised.
 * threads below 1 is CAP and the book stays as it was.
 * threads above 64 is CAPPED and the book stays as it was.
 * A new count from 1 through 64 is stored. The call returns false and
 * err is CAPPED. A second Raise of the same count is REPLAY and leaves
 * the first count. Those checks run in that order. Nothing is raised
 * and no bytes move.
 */
class SwarmResCapApply {
public:
    bool Apply(SwarmResCapBook& book, int64_t threads, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_APPLY_H
