// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_DISCOVER_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_DISCOVER_H

#include <string>

namespace modelnet {

/**
 * Nothing on this plane connects.
 * connects() is false for every family, including one that has been
 * offered. There is no method that opens a connection or stores a family.
 */
class SwarmPrivFamDiscover {
public:
    bool connects() const;
    bool connects(const std::string& family) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_DISCOVER_H
