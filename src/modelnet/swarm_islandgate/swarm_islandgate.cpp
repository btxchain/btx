// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/swarm_islandgate.h>

#include <modelnet/swarm_islandgate/admit.h>

namespace modelnet {

bool SwarmIslandGate::Admit(const std::string& island, int64_t epoch, int64_t now, std::string& err)
{
    return SwarmIslandGateApply(m_roster, island, epoch, now, err);
}

bool SwarmIslandGate::Exchange(std::string& err)
{
    return m_exchange.Exchange(err);
}

bool SwarmIslandGate::admitted(const std::string& island) const
{
    return m_roster.contains(island);
}

int64_t SwarmIslandGate::epoch_of(const std::string& island) const
{
    return m_roster.epoch_of(island);
}

std::size_t SwarmIslandGate::admitted_count() const
{
    return m_roster.size();
}

bool SwarmIslandGate::exchanged() const
{
    return m_exchange.exchanged();
}

int64_t SwarmIslandGate::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmIslandGate::gpu() const
{
    return m_quiet.gpu();
}

bool SwarmIslandGate::launched() const
{
    return m_quiet.launched();
}

} // namespace modelnet
