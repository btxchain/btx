// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_NAME_H
#define BITCOIN_MODELNET_SWARM_NATPUB_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies an endpoint as the stored label.
 * The characters are kept as written. An endpoint is an opaque string.
 * An empty endpoint copies nothing.
 */
class SwarmNatPubName {
public:
    std::string copy(const std::string& endpoint) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_NAME_H
