// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_REALM_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_REALM_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Status this board cannot change.
 * Graduate always returns REALM. graduated() stays false. The active id
 * stays "base". The board does not mine, does not broadcast, moves no
 * bytes, and does not claim a GPU ran. Acceptance does not graduate.
 */
class SwarmEvalRealm {
public:
    bool Graduate(const std::string& subject, std::string& err);

    bool graduated() const;
    const char* active_id() const;
    uint64_t bytes_moved() const;
    bool gpu() const;
    bool mines() const;
    bool broadcasts() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_REALM_H
