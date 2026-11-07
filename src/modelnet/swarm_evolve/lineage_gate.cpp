// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/lineage_gate.h>

#include <modelnet/swarm_frontier.h>

namespace modelnet {

bool SwarmEvolveLineage::Seed(const std::string& baseline, std::string& err)
{
    if (!m_lineage.AddBaseline(baseline, err)) return false;
    if (!m_lineage.Assign("general", baseline, err)) return false;
    m_parent = baseline;
    m_seeded = true;
    err.clear();
    return true;
}

bool SwarmEvolveLineage::Adopt(const std::string& graduated_id, std::string& err)
{
    if (graduated_id.empty() || !m_seeded) {
        err = "GRADUATE";
        return false;
    }
    std::string adopt_err;
    const std::string adopted = SwarmAdopt(SwarmReleasePolicy::Follow, m_parent, graduated_id, true, adopt_err);
    if (adopted != graduated_id) {
        err = adopt_err.empty() ? std::string("LOCAL_INCOMPATIBLE") : adopt_err;
        return false;
    }
    if (!m_lineage.Fork(m_parent, graduated_id, true, err)) return false;
    if (!m_lineage.Assign("general", graduated_id, err)) return false;
    m_parent = adopted;
    err.clear();
    return true;
}

bool SwarmEvolveLineage::Average(const std::string& left, const std::string& right, std::string& err)
{
    const std::string parent_before = m_parent;
    auto fork_incompatible = [&](const std::string& child) {
        if (child.empty() || child == parent_before) return;
        std::string fork_err;
        m_lineage.Fork(parent_before, child, false, fork_err);
    };
    fork_incompatible(left);
    fork_incompatible(right);
    const bool averaged = m_lineage.Average(left, right, err);
    m_parent = parent_before;
    return averaged;
}

std::vector<std::string> SwarmEvolveLineage::Heads(const std::string& channel) const
{
    return m_lineage.Heads(channel);
}

} // namespace modelnet
