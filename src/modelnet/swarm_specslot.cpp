// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_specslot.h>

namespace modelnet {

bool SwarmSpecSlot::Open(const std::string& niche, int64_t slots, std::string& err)
{
    if (niche.empty()) {
        err = "NICHE";
        return false;
    }
    if (slots < 1) {
        err = "SLOTS";
        return false;
    }
    if (m_remaining.find(niche) != m_remaining.end()) {
        err = "REPLAY";
        return false;
    }
    m_remaining.emplace(niche, slots);
    err.clear();
    return true;
}

bool SwarmSpecSlot::Spend(const std::string& niche, int64_t slots, std::string& err)
{
    const auto it = m_remaining.find(niche);
    if (it == m_remaining.end()) {
        err = "NICHE";
        return false;
    }
    if (slots < 1) {
        err = "SLOTS";
        return false;
    }
    if (slots > it->second) {
        err = "EXHAUSTED";
        return false;
    }
    it->second -= slots;
    err.clear();
    return true;
}

int64_t SwarmSpecSlot::Remaining(const std::string& niche) const
{
    const auto it = m_remaining.find(niche);
    if (it == m_remaining.end()) return -1;
    return it->second;
}

} // namespace modelnet
