// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/queue.h>

#include <modelnet/swarm_experience/kind.h>

namespace modelnet {

void ExperienceQueue::Enqueue(const std::vector<ExperienceRow>& rows)
{
    for (const ExperienceRow& row : rows) {
        if (row.id.empty()) continue;
        std::string err;
        if (!ExperienceKindAllowed(row.kind, err)) continue;
        if (Contains(row.id)) continue;
        m_ids.push_back(row.id);
    }
}

bool ExperienceQueue::Contains(const std::string& id) const
{
    for (const std::string& queued : m_ids) {
        if (queued == id) return true;
    }
    return false;
}

} // namespace modelnet
