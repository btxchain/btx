// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/swarm_familyadmit.h>

#include <modelnet/swarm_familyadmit/admit.h>

namespace modelnet {

bool SwarmFamilyAdmit::Admit(const std::string& peer,
                              const std::string& family,
                              const std::string& advertised_family,
                              bool claims_compatible,
                              std::string& err)
{
    return SwarmFamilyAdmitApply(m_roster, peer, family, advertised_family, claims_compatible, err);
}

bool SwarmFamilyAdmit::AddSeed(const std::string& seed, std::string& err)
{
    return m_seeds.Add(seed, err);
}

bool SwarmFamilyAdmit::admitted(const std::string& peer) const
{
    return m_roster.contains(peer);
}

std::string SwarmFamilyAdmit::family_of(const std::string& peer) const
{
    return m_roster.family_of(peer);
}

std::size_t SwarmFamilyAdmit::admitted_count() const
{
    return m_roster.size();
}

bool SwarmFamilyAdmit::connected(const std::string& peer) const
{
    return m_link.connected(peer);
}

const std::vector<std::string>& SwarmFamilyAdmit::dns_seeds() const
{
    return m_seeds.list();
}

int64_t SwarmFamilyAdmit::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmFamilyAdmit::launched() const
{
    return m_quiet.launched();
}

} // namespace modelnet
