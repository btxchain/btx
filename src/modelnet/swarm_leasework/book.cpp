// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/book.h>

#include <modelnet/swarm_leasework/expiry.h>

namespace modelnet {

bool LeaseWorkBook::contains(const std::string& task) const
{
    return m_grants.find(task) != m_grants.end();
}

std::string LeaseWorkBook::worker(const std::string& task) const
{
    const auto found = m_grants.find(task);
    if (found == m_grants.end()) return {};
    return found->second.worker;
}

int64_t LeaseWorkBook::grant_epoch(const std::string& task) const
{
    const auto found = m_grants.find(task);
    if (found == m_grants.end()) return 0;
    return found->second.epoch;
}

int64_t LeaseWorkBook::until_ms(const std::string& task) const
{
    const auto found = m_grants.find(task);
    if (found == m_grants.end()) return 0;
    return found->second.until_ms;
}

bool LeaseWorkBook::committed(const std::string& task) const
{
    const auto found = m_grants.find(task);
    if (found == m_grants.end()) return false;
    return found->second.committed;
}

std::string LeaseWorkBook::result_hash(const std::string& task) const
{
    const auto found = m_grants.find(task);
    if (found == m_grants.end() || !found->second.committed) return {};
    return found->second.result_hash;
}

bool LeaseWorkBook::holds(const std::string& worker) const
{
    if (worker.empty()) return false;
    for (const auto& item : m_grants) {
        if (item.second.worker == worker) return true;
    }
    return false;
}

bool LeaseWorkBook::worker_live(const std::string& worker) const
{
    if (worker.empty() || !m_have_now) return false;
    for (const auto& item : m_grants) {
        if (item.second.worker != worker) continue;
        if (LeaseWorkGrantLive(item.second.until_ms, m_observed_now)) return true;
    }
    return false;
}

int64_t LeaseWorkBook::observed_now() const
{
    return m_observed_now;
}

std::size_t LeaseWorkBook::size() const
{
    return m_grants.size();
}

bool LeaseWorkBook::Insert(const std::string& task, const std::string& worker, int64_t epoch, int64_t now_ms,
                           int64_t until_ms)
{
    if (task.empty() || worker.empty()) return false;
    if (m_grants.find(task) != m_grants.end()) return false;
    const auto inserted = m_grants.emplace(task, LeaseWorkMakeGrant(task, worker, epoch, now_ms, until_ms));
    if (!inserted.second) return false;
    if (!m_have_now || now_ms > m_observed_now) m_observed_now = now_ms;
    m_have_now = true;
    return true;
}

bool LeaseWorkBook::StoreHash(const std::string& task, const std::string& result_hash)
{
    const auto found = m_grants.find(task);
    if (found == m_grants.end()) return false;
    if (found->second.committed) return false;
    if (result_hash.empty()) return false;
    found->second.result_hash = result_hash;
    found->second.committed = true;
    return true;
}

} // namespace modelnet
