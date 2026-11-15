// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_SEATING_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_SEATING_H

#include <modelnet/swarm_execnbhd/record.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Nearby set plus remote set for one execution neighborhood.
 * Replace drops the previous seating and stores the new one.
 * It does not connect and does not open a socket.
 */
class SwarmExecNbhdSeating {
public:
    bool Replace(const std::vector<SwarmExecNbhdRecord>& eligible, std::string& err);

    int64_t nearby_count() const;
    int64_t remote_count() const;
    bool nearby(const std::string& peer) const;
    bool remote(const std::string& peer) const;
    bool seated(const std::string& peer) const;
    /** Domain of a seated peer. Empty when the peer is not seated. */
    std::string domain(const std::string& peer) const;

private:
    const SwarmExecNbhdRecord* Find(const std::string& peer) const;

    std::map<std::string, SwarmExecNbhdRecord> m_nearby;
    std::map<std::string, SwarmExecNbhdRecord> m_remote;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_SEATING_H
