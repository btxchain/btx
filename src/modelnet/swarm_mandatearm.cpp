// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mandatearm.h>

#include <string>

namespace modelnet {

bool SwarmMandateArm::Arm(int64_t bound_atoms, bool operator_signed, bool research_key, bool scheduler, std::string& err)
{
    if (m_armed) {
        err = "REPLAY";
        return false;
    }
    if (research_key || scheduler) {
        err = "NOT_SIGNED";
        return false;
    }
    if (!operator_signed) {
        err = "NOT_SIGNED";
        return false;
    }
    if (bound_atoms < 1) {
        err = "BOUND";
        return false;
    }
    m_bound_atoms = bound_atoms;
    m_armed = true;
    m_automatic_spend = std::to_string(bound_atoms);
    err.clear();
    return true;
}

std::string SwarmMandateArm::automatic_spend() const
{
    return m_automatic_spend;
}

bool SwarmMandateArm::armed() const
{
    return m_armed;
}

int64_t SwarmMandateArm::atoms_moved() const
{
    return 0;
}

} // namespace modelnet
