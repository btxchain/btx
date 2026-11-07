// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_headpin.h>

namespace modelnet {

bool SwarmHeadPin::Stage(const std::string& candidate, std::string& err)
{
    if (candidate.empty()) {
        err = "MODEL";
        return false;
    }
    m_staged = candidate;
    err.clear();
    return true;
}

bool SwarmHeadPin::Follow(bool local_compatible, std::string& err)
{
    if (m_staged.empty()) {
        err = "STAGE";
        return false;
    }
    if (!local_compatible) {
        err = "LOCAL_INCOMPATIBLE";
        return false;
    }
    m_active = m_staged;
    m_staged.clear();
    err.clear();
    return true;
}

bool SwarmHeadPin::Pin(std::string& err)
{
    if (m_staged.empty()) {
        err = "STAGE";
        return false;
    }
    m_staged.clear();
    err.clear();
    return true;
}

const std::string& SwarmHeadPin::active() const
{
    return m_active;
}

} // namespace modelnet
