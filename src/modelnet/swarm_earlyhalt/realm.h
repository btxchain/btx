// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_REALM_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_REALM_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Status this plane cannot change.
 * Promote returns REALM and does not take the row. No bytes move.
 * gpu(), graduated(), and mined() stay false. A score step does not
 * graduate and does not mine.
 */
class SwarmEarlyHaltRealm {
public:
    bool Promote(std::string& err) const;
    int64_t bytes_moved() const;
    bool gpu() const;
    bool graduated() const;
    bool mined() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_REALM_H
