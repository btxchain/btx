// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_LIMITS_H
#define BITCOIN_MODELNET_SWARM_FORM_LIMITS_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Invariants of an in-process formation plane.
 * bytes are not moved, a sidecar is not launched, and no DNS seed is recorded.
 */
class SwarmFormLimits {
public:
    bool bytes_moved() const;
    bool launched_sidecar() const;
    std::vector<std::string> dns_seeds() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_LIMITS_H
