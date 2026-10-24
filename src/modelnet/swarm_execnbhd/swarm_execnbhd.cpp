// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>

#include <modelnet/swarm_execnbhd/fallback.h>
#include <modelnet/swarm_execnbhd/share.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmExecNeighborhood::Offer(const std::string& peer, int64_t rtt_ms, const std::string& trust_domain,
                                  bool authorized, bool compatible, std::string& err)
{
    return m_offers.Offer(peer, rtt_ms, trust_domain, authorized, compatible, err);
}

bool SwarmExecNeighborhood::Seat(std::string& err)
{
    return m_seating.Replace(m_offers.Eligible(), err);
}

bool SwarmExecNeighborhood::Fallback(const std::string& peer, std::string& err)
{
    return SwarmExecNbhdFallback(peer, err);
}

bool SwarmExecNeighborhood::ShareKv(const std::string& left_peer, const std::string& right_peer, std::string& err)
{
    return SwarmExecNbhdShareKv(m_seating, left_peer, right_peer, err);
}

bool SwarmExecNeighborhood::Identity(const std::string& neighborhood_id, std::string& err)
{
    return m_identity.Set(neighborhood_id, err);
}

int64_t SwarmExecNeighborhood::offered_count() const
{
    return m_offers.count();
}

int64_t SwarmExecNeighborhood::nearby_count() const
{
    return m_seating.nearby_count();
}

int64_t SwarmExecNeighborhood::remote_count() const
{
    return m_seating.remote_count();
}

bool SwarmExecNeighborhood::seated(const std::string& peer) const
{
    return m_seating.seated(peer);
}

bool SwarmExecNeighborhood::nearby(const std::string& peer) const
{
    return m_seating.nearby(peer);
}

bool SwarmExecNeighborhood::remote(const std::string& peer) const
{
    return m_seating.remote(peer);
}

std::string SwarmExecNeighborhood::domain_of(const std::string& peer) const
{
    return m_offers.domain(peer);
}

std::string SwarmExecNeighborhood::identity() const
{
    return m_identity.Get();
}

bool SwarmExecNeighborhood::connected() const
{
    return m_quiet.connected();
}

bool SwarmExecNeighborhood::socket_opened() const
{
    return m_quiet.socket_opened();
}

bool SwarmExecNeighborhood::launched() const
{
    return m_quiet.launched();
}

bool SwarmExecNeighborhood::gpu() const
{
    return m_quiet.gpu();
}

bool SwarmExecNeighborhood::broadcast() const
{
    return m_quiet.broadcast();
}

int64_t SwarmExecNeighborhood::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::string SwarmExecNeighborhood::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

int64_t SwarmExecNeighborhood::atoms_moved() const
{
    return m_quiet.atoms_moved();
}

} // namespace modelnet
