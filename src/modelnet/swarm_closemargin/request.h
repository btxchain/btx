// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_REQUEST_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_REQUEST_H

#include <modelnet/swarm_closemargin/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Records one shrink request and leaves the margin unshrunk.
 * A count other than 160 is MARGIN and the book stays as it was.
 * A new count of 160 is stored. The call returns false and err is HELD.
 * A second Shrink of 160 is REPLAY and leaves the first request.
 * Those checks run in that order. The margin stays 160 and no bytes move.
 */
class SwarmCloseMarginHoldRequest {
public:
    bool Apply(SwarmCloseMarginHoldBook& book, int64_t blocks, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_REQUEST_H
