// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/earned.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmFaultEarnedBook::Keep(const std::string& work, int64_t atoms, std::string& err)
{
    if (atoms < 0) {
        err = kSwarmFaultAtoms;
        return false;
    }
    const auto found = m_rows.find(work);
    if (found != m_rows.end()) {
        if (found->second == atoms) {
            err.clear();
            return true;
        }
        err = kSwarmFaultConflict;
        return false;
    }
    m_rows.emplace(work, atoms);
    err.clear();
    return true;
}

bool SwarmFaultEarnedBook::contains(const std::string& work) const
{
    return m_rows.find(work) != m_rows.end();
}

int64_t SwarmFaultEarnedBook::atoms_for(const std::string& work) const
{
    const auto found = m_rows.find(work);
    if (found == m_rows.end()) {
        return 0;
    }
    return found->second;
}

std::size_t SwarmFaultEarnedBook::count() const
{
    return m_rows.size();
}

} // namespace modelnet
