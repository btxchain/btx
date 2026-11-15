// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_BOUND_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_BOUND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Bound check for an arm.
 * atoms below 1 is BOUND and nothing is recorded. A bound of at least 1
 * is accepted. This check does not arm and does not spend.
 */
class SwarmNodeDefaultBound {
public:
    bool Accept(int64_t atoms, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_BOUND_H
