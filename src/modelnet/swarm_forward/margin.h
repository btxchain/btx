// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_MARGIN_H
#define BITCOIN_MODELNET_SWARM_FORWARD_MARGIN_H

#include <string>

namespace modelnet {

/**
 * Route margin of 160 blocks.
 * SwarmRouteMargin fails when its first expiry is below its second plus
 * the margin. The outgoing expiry is passed in the first position so an
 * outgoing expiry below incoming_expiry + 160 is MARGIN.
 */
class SwarmForwardMargin {
public:
    bool Accept(int incoming_expiry, int outgoing_expiry, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_MARGIN_H
