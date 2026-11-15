// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_SHELF_H
#define BITCOIN_MODELNET_SWARM_NATPUB_SHELF_H

#include <modelnet/swarm_natpub/limits.h>

#include <string>

namespace modelnet {

/**
 * Publication flag for this plane.
 * It starts false. mark refuses every endpoint and leaves it false.
 * There is no method that sets it.
 */
class SwarmNatPubShelf {
public:
    bool published() const;
    bool published(const std::string& endpoint) const;
    bool mark(const std::string& endpoint);

private:
    bool m_published{kSwarmNatPubPublished};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_SHELF_H
