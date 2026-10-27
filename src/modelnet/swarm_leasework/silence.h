// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_SILENCE_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_SILENCE_H

#include <cstdint>

namespace modelnet {

/**
 * What this plane is not allowed to do.
 * bytes_moved() stays 0. launched() stays false. broadcast() stays false.
 * There is no method that sets any of these. No process is spawned.
 */
class LeaseWorkSilence {
public:
    int64_t bytes_moved() const;
    bool launched() const;
    bool broadcast() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_SILENCE_H
