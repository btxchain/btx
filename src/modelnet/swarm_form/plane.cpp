// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/plane.h>

namespace modelnet {

bool FormationPlane::Open(const std::filesystem::path& modeldir, std::string& err)
{
    return m_directory.Open(modeldir, err);
}

bool FormationPlane::Form(std::string& err)
{
    if (!m_directory.opened()) {
        err = "MODELDIR";
        return false;
    }
    const bool formed = m_membership.Form(m_directory.path(), err);
    if (m_membership.formed()) {
        std::string election_err;
        if (!m_election.Load(m_directory.path(), election_err)) {
            err = election_err;
            return false;
        }
    }
    return formed;
}

bool FormationPlane::Claim(const std::string& candidate, uint64_t epoch, std::string& err)
{
    if (!m_directory.opened()) {
        err = "MODELDIR";
        return false;
    }
    return m_election.Claim(m_directory.path(), m_membership, candidate, epoch, err);
}

bool FormationPlane::Discover(const std::string& peer_id, const std::string& family_id, bool advertises_compatibility, std::string& err)
{
    if (!m_directory.opened()) {
        err = "MODELDIR";
        return false;
    }
    return m_discovery.Consider(m_directory.path(), m_membership, peer_id, family_id, advertises_compatibility, err);
}

bool FormationPlane::admitted(const std::string& node_id) const
{
    return m_membership.admitted(node_id);
}

bool FormationPlane::bytes_moved() const
{
    return m_limits.bytes_moved();
}

bool FormationPlane::launched_sidecar() const
{
    return m_limits.launched_sidecar();
}

std::vector<std::string> FormationPlane::dns_seeds() const
{
    return m_limits.dns_seeds();
}

bool FormationPlane::connects() const
{
    return m_discovery.connects();
}

bool SwarmFormPlane(const std::filesystem::path& modeldir, std::string& err)
{
    FormationPlane plane;
    if (!plane.Open(modeldir, err)) return false;
    return plane.Form(err);
}

} // namespace modelnet
