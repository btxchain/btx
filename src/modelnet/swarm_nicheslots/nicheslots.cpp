// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/nicheslots.h>

#include <modelnet/swarm_nicheslots/move.h>
#include <modelnet/swarm_nicheslots/open.h>
#include <modelnet/swarm_nicheslots/spend.h>

namespace modelnet {

bool SwarmNicheSlots::Open(const std::string& niche, int64_t slots, std::string& err)
{
    return SwarmNicheSlotsOpen(m_table, niche, slots, err);
}

int64_t SwarmNicheSlots::Remaining(const std::string& niche) const
{
    return m_table.remaining(niche);
}

bool SwarmNicheSlots::Spend(const std::string& niche, const std::string& task, std::string& err)
{
    return SwarmNicheSlotsSpend(m_table, niche, task, err);
}

bool SwarmNicheSlots::Move(const std::string& task, const std::string& from, const std::string& to, std::string& err)
{
    return SwarmNicheSlotsMove(m_table, task, from, to, err);
}

std::vector<std::string> SwarmNicheSlots::tasks(const std::string& niche) const
{
    return m_table.tasks(niche);
}

} // namespace modelnet
