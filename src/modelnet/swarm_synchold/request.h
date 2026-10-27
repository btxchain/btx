// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SYNCHOLD_REQUEST_H
#define BITCOIN_MODELNET_SWARM_SYNCHOLD_REQUEST_H

#include <modelnet/swarm_synchold/book.h>

#include <string>

namespace modelnet {

/**
 * Records one gradient sync request and leaves it unsynced.
 * An empty name is SYNC and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is HELD.
 * A second Request of the same name is REPLAY and leaves the first request.
 * Those checks run in that order. Nothing is synced and no bytes move.
 */
class SwarmSyncHoldRequest {
public:
    bool Apply(SwarmSyncHoldBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SYNCHOLD_REQUEST_H
