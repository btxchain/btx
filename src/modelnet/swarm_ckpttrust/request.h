// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_REQUEST_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_REQUEST_H

#include <modelnet/swarm_ckpttrust/book.h>

#include <string>

namespace modelnet {

/**
 * Records one claim and leaves it untrusted.
 * An empty claim is CLAIM and the book stays as it was.
 * A new non-empty claim is stored. The call returns false and err is NOT_TRUST.
 * A second Trust of the same claim is REPLAY and leaves the first claim.
 * Those checks run in that order. Nothing is trusted and no bytes move.
 * A checkpoint-only claim is not lineage authority.
 */
class SwarmCheckpointTrustRequest {
public:
    bool Apply(SwarmCheckpointTrustBook& book, const std::string& claim, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_REQUEST_H
