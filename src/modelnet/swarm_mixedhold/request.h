// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MIXEDHOLD_REQUEST_H
#define BITCOIN_MODELNET_SWARM_MIXEDHOLD_REQUEST_H

#include <modelnet/swarm_mixedhold/book.h>

#include <string>

namespace modelnet {

/**
 * Records one mixed-precision request and leaves it stopped.
 * An empty name is PRECISION and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is HELD.
 * A second Request of the same name is REPLAY and leaves the first request.
 * Those checks run in that order. Nothing runs and no bytes move.
 * running() stays false.
 */
class SwarmMixedHoldRequest {
public:
    bool Apply(SwarmMixedHoldBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MIXEDHOLD_REQUEST_H
