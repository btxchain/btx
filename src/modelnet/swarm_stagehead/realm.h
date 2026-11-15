// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_REALM_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_REALM_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Status this plane cannot change.
 * No bytes move. Nothing is mined, broadcast, or spent. graduated stays
 * false. Promote sets err to REALM and returns false. It has no active id
 * to change.
 */
class SwarmStageRealm {
public:
    bool Promote(std::string& err) const;
    int64_t bytes_moved() const;
    bool mined() const;
    bool graduated() const;
    bool broadcast() const;
    bool spent() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_REALM_H
