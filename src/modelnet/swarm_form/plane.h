// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_PLANE_H
#define BITCOIN_MODELNET_SWARM_FORM_PLANE_H

#include <modelnet/swarm_form/directory.h>
#include <modelnet/swarm_form/discovery.h>
#include <modelnet/swarm_form/election.h>
#include <modelnet/swarm_form/limits.h>
#include <modelnet/swarm_form/membership.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process swarm formation plane for a normal btxd observer.
 * It does not exec a sidecar, open a socket, add a DNS seed, broadcast, or spend.
 */
class FormationPlane {
public:
    bool Open(const std::filesystem::path& modeldir, std::string& err);
    bool Form(std::string& err);
    bool Claim(const std::string& candidate, uint64_t epoch, std::string& err);
    bool Discover(const std::string& peer_id, const std::string& family_id, bool advertises_compatibility, std::string& err);
    bool admitted(const std::string& node_id) const;
    const std::string& leader() const { return m_election.leader(); }
    uint64_t epoch() const { return m_election.epoch(); }
    const SwarmFormMember& membership() const { return m_membership.member(); }
    bool bytes_moved() const;
    bool launched_sidecar() const;
    std::vector<std::string> dns_seeds() const;
    bool connects() const;
    const fs::path& directory() const { return m_directory.path(); }

private:
    SwarmFormDirectory m_directory;
    SwarmFormMembership m_membership;
    SwarmFormElection m_election;
    SwarmFormDiscovery m_discovery;
    SwarmFormLimits m_limits;
};

/**
 * Create modeldir/swarm when it is missing and form the local membership.
 * An empty modeldir returns false with err MODELDIR and creates nothing.
 * A symlink at modeldir/swarm returns false with err SYMLINK and is not written through.
 * A second call on the same directory loads the existing valid membership, returns success, and does not rewrite it.
 */
bool SwarmFormPlane(const std::filesystem::path& modeldir, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_PLANE_H
