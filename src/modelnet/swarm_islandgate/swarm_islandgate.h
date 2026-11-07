// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_H

#include <modelnet/swarm_islandgate/exchange.h>
#include <modelnet/swarm_islandgate/quiet.h>
#include <modelnet/swarm_islandgate/roster.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Island-admission plane.
 * A stale island is not admitted. An exchange moves no bytes.
 *
 * Admit stores an island only when the id is non-empty and epoch >= now.
 * Empty island is ISLAND and stores nothing. An island already stored is
 * REPLAY and keeps the first epoch, including when the new epoch is stale
 * or later. Otherwise epoch < now is STALE and stores nothing. A fresh
 * epoch stores the island and returns true.
 *
 * Exchange sets err to HELD and returns false. exchanged() stays false.
 * bytes_moved() stays 0. admitted() of a stale island stays false.
 * gpu() stays false. launched() stays false.
 */
class SwarmIslandGate {
public:
    bool Admit(const std::string& island, int64_t epoch, int64_t now, std::string& err);
    bool Exchange(std::string& err);

    bool admitted(const std::string& island) const;
    int64_t epoch_of(const std::string& island) const;
    std::size_t admitted_count() const;
    bool exchanged() const;
    int64_t bytes_moved() const;
    bool gpu() const;
    bool launched() const;

private:
    SwarmIslandGateRoster m_roster;
    SwarmIslandGateExchange m_exchange;
    SwarmIslandGateQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_H
