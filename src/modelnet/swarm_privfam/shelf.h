// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_SHELF_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_SHELF_H

#include <modelnet/swarm_privfam/limits.h>

#include <string>

namespace modelnet {

/**
 * Publication flag for this plane.
 * It starts false. mark refuses every family and leaves it false.
 * There is no method that sets it.
 */
class SwarmPrivFamShelf {
public:
    bool published() const;
    bool published(const std::string& family) const;
    bool mark(const std::string& family);

private:
    bool m_published{kSwarmPrivFamPublished};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_SHELF_H
