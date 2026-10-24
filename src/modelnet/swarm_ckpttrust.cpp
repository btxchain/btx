// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust.h>

namespace modelnet {

bool SwarmCkptTrust::Claim(const std::string& checkpoint, bool recipe_present, bool dataset_bound, std::string& err)
{
    if (checkpoint.empty()) {
        err = "CHECKPOINT";
        return false;
    }
    if (m_stored.find(checkpoint) != m_stored.end()) {
        err = "REPLAY";
        return false;
    }
    if (!recipe_present || !dataset_bound) {
        m_stored.emplace(checkpoint, false);
        err = "NOT_TRUST";
        return false;
    }
    m_stored.emplace(checkpoint, true);
    err.clear();
    return true;
}

bool SwarmCkptTrust::trusted(const std::string& checkpoint) const
{
    const auto it = m_stored.find(checkpoint);
    if (it == m_stored.end()) {
        return false;
    }
    return it->second;
}

bool SwarmCkptTrust::bytes_moved() const
{
    return false;
}

} // namespace modelnet
