// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_REQUEST_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_REQUEST_H

#include <modelnet/swarm_holdrot/book.h>

#include <string>

namespace modelnet {

/**
 * Records one holdout and leaves it not rotating.
 * An empty holdout is HOLDOUT and the book stays as it was.
 * A new non-empty holdout is stored. The call returns false and err is NOT_ROTATING.
 * A second Rotate of the same holdout is REPLAY and leaves the first holdout.
 * Those checks run in that order. Nothing is rotating and no bytes move.
 */
class SwarmHoldoutRotateRequest {
public:
    bool Apply(SwarmHoldoutRotateBook& book, const std::string& holdout, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_REQUEST_H
