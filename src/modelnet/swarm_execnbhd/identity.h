// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_IDENTITY_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_IDENTITY_H

#include <string>

namespace modelnet {

/**
 * One neighborhood id. An empty id stores nothing.
 * The same id again is refused and the first stays.
 * A different id is refused and the first stays.
 */
class SwarmExecNbhdIdentity {
public:
    bool Set(const std::string& neighborhood_id, std::string& err);
    std::string Get() const;

private:
    std::string m_id;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_IDENTITY_H
