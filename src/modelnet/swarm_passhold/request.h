// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PASSHOLD_REQUEST_H
#define BITCOIN_MODELNET_SWARM_PASSHOLD_REQUEST_H

#include <modelnet/swarm_passhold/book.h>

#include <string>

namespace modelnet {

/**
 * Records one GPU passthrough request and leaves it unstarted.
 * An empty name is PASSTHROUGH and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is NOT_STARTED.
 * A second Request of the same name is REPLAY and leaves the first request.
 * Those checks run in that order. Nothing is started, nothing is passed,
 * and no bytes move.
 */
class SwarmPassHoldRequest {
public:
    bool Apply(SwarmPassHoldBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PASSHOLD_REQUEST_H
