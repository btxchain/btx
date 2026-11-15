// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_BLANK_H
#define BITCOIN_MODELNET_SWARM_NATPUB_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts an endpoint that can be claimed.
 * An empty endpoint is ENDPOINT. The caller stores nothing on that result.
 */
class SwarmNatPubBlank {
public:
    bool accept(const std::string& endpoint, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_BLANK_H
