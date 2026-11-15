// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/obligations.h>

#include <modelnet/swarm_paycycle/codes.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmPayObligations::Lease(const std::string& pool, const std::string& work, const std::string& worker,
                                std::string& err)
{
    if (work.empty() || worker.empty()) {
        err = SWARM_PAYCYCLE_WORK;
        return false;
    }
    const auto key = std::make_pair(pool, work);
    if (m_rows.find(key) != m_rows.end()) {
        err = SWARM_PAYCYCLE_REPLAY;
        return false;
    }
    Row row;
    row.worker = worker;
    row.earned = false;
    m_rows.emplace(key, std::move(row));
    err.clear();
    return true;
}

bool SwarmPayObligations::Pay(const std::string& pool, const std::string& work, const std::string& label,
                              std::string& err)
{
    if (label == "profit-share") {
        err = SWARM_PAYCYCLE_REFUSED;
        return false;
    }
    if (label != "work-payment") {
        err = SWARM_PAYCYCLE_LABEL;
        return false;
    }
    const auto it = m_rows.find(std::make_pair(pool, work));
    if (it == m_rows.end()) {
        err = SWARM_PAYCYCLE_WORK;
        return false;
    }
    if (!it->second.earned) {
        it->second.earned = true;
        ++m_earned;
    }
    err = SWARM_PAYCYCLE_HELD;
    return false;
}

bool SwarmPayObligations::leased(const std::string& pool, const std::string& work) const
{
    return m_rows.find(std::make_pair(pool, work)) != m_rows.end();
}

bool SwarmPayObligations::earned(const std::string& pool, const std::string& work) const
{
    const auto it = m_rows.find(std::make_pair(pool, work));
    return it != m_rows.end() && it->second.earned;
}

int64_t SwarmPayObligations::earned_count() const
{
    return m_earned;
}

std::string SwarmPayObligations::worker(const std::string& pool, const std::string& work) const
{
    const auto it = m_rows.find(std::make_pair(pool, work));
    if (it == m_rows.end()) return {};
    return it->second.worker;
}

} // namespace modelnet
