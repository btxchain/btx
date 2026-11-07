// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTSAVE_REQUEST_H
#define BITCOIN_MODELNET_SWARM_CKPTSAVE_REQUEST_H

#include <modelnet/swarm_ckptsave/book.h>

#include <string>

namespace modelnet {

/**
 * Records one checkpoint save request and leaves it unsaved.
 * An empty name is CHECKPOINT and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is HELD.
 * A second Request of the same name is REPLAY and leaves the first request.
 * Those checks run in that order. Nothing is saved and no bytes move.
 */
class SwarmCkptSaveRequest {
public:
    bool Apply(SwarmCkptSaveBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTSAVE_REQUEST_H
