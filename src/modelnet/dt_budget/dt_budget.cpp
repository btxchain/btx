// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_budget/dt_budget.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtBudget::RejectEmpty(const std::string& id, std::string& err) const
{
    if (id.empty()) {
        err = DT_BUDGET_REQUEST;
        return true;
    }
    return false;
}

bool DtBudget::Reserve(const std::string& id, int64_t bytes, std::string& err)
{
    if (RejectEmpty(id, err)) return false;
    if (m_leases.find(id) != m_leases.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    const int64_t remaining = DT_BUDGET_CAPACITY_BYTES - m_reserved;
    if (bytes < static_cast<int64_t>(1) || bytes > remaining) {
        err = DT_BUDGET_CAPACITY;
        return false;
    }
    Lease lease;
    lease.bytes = bytes;
    m_leases.emplace(id, lease);
    m_reserved += bytes;
    m_physical += bytes;
    err.clear();
    return true;
}

bool DtBudget::Schedule(const std::string& id, std::string& err)
{
    if (RejectEmpty(id, err)) return false;
    const auto it = m_leases.find(id);
    if (it == m_leases.end()) {
        err = DT_BUDGET_RESERVE;
        return false;
    }
    it->second.scheduled = true;
    err.clear();
    return true;
}

bool DtBudget::Cancel(const std::string& id, std::string& err)
{
    if (RejectEmpty(id, err)) return false;
    const auto it = m_leases.find(id);
    if (it == m_leases.end()) {
        err = DT_BUDGET_RESERVE;
        return false;
    }
    if (!it->second.canceled) {
        it->second.canceled = true;
        m_canceled_leases += static_cast<int64_t>(1);
    }
    err.clear();
    return true;
}

bool DtBudget::Quiesce(const std::string& id, std::string& err)
{
    if (RejectEmpty(id, err)) return false;
    const auto it = m_leases.find(id);
    if (it == m_leases.end()) {
        err = DT_BUDGET_RESERVE;
        return false;
    }
    it->second.quiesced = true;
    err.clear();
    return true;
}

bool DtBudget::Release(const std::string& id, std::string& err)
{
    if (RejectEmpty(id, err)) return false;
    const auto it = m_leases.find(id);
    if (it == m_leases.end()) {
        err = DT_BUDGET_RESERVE;
        return false;
    }
    if (!it->second.quiesced) {
        err = DT_BUDGET_PINNED;
        return false;
    }
    const int64_t bytes = it->second.bytes;
    if (it->second.canceled) {
        m_canceled_leases -= static_cast<int64_t>(1);
    }
    m_leases.erase(it);
    m_reserved -= bytes;
    m_physical -= bytes;
    err.clear();
    return true;
}

} // namespace modelnet
