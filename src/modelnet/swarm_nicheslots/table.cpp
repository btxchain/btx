// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/table.h>

#include <modelnet/swarm_nicheslots/limits.h>

namespace modelnet {

bool SwarmNicheSlotsTable::opened(const std::string& niche) const
{
    return m_rows.find(niche) != m_rows.end();
}

int64_t SwarmNicheSlotsTable::remaining(const std::string& niche) const
{
    const auto found = m_rows.find(niche);
    if (found == m_rows.end()) return kSwarmNicheSlotsAbsent;
    return found->second.remaining;
}

bool SwarmNicheSlotsTable::has_task(const std::string& niche, const std::string& task) const
{
    const auto found = m_rows.find(niche);
    if (found == m_rows.end()) return false;
    for (const std::string& prior : found->second.tasks) {
        if (prior == task) return true;
    }
    return false;
}

std::vector<std::string> SwarmNicheSlotsTable::tasks(const std::string& niche) const
{
    const auto found = m_rows.find(niche);
    if (found == m_rows.end()) return {};
    return found->second.tasks;
}

void SwarmNicheSlotsTable::Open(const std::string& niche, int64_t slots)
{
    if (m_rows.find(niche) != m_rows.end()) return;
    if (slots < kSwarmNicheSlotsMin) return;
    SwarmNicheSlotsRecord row;
    row.remaining = slots;
    m_rows.emplace(niche, std::move(row));
}

void SwarmNicheSlotsTable::Spend(const std::string& niche, const std::string& task)
{
    const auto found = m_rows.find(niche);
    if (found == m_rows.end()) return;
    if (found->second.remaining <= 0) return;
    for (const std::string& prior : found->second.tasks) {
        if (prior == task) return;
    }
    found->second.tasks.push_back(task);
    --found->second.remaining;
}

} // namespace modelnet
