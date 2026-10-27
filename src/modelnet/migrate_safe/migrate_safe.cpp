// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/migrate_safe/migrate_safe.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool MigrateSafe::Store(const std::string& id, const std::string& body, int64_t assurance, std::string& err)
{
    if (id.empty() || body.empty()) {
        err = MIGRATE_SAFE_FIELD;
        return false;
    }
    if (assurance < static_cast<int64_t>(0)) {
        err = MIGRATE_SAFE_BOUND;
        return false;
    }
    Row& row = m_rows[id];
    row.body = body;
    row.assurance = assurance;
    err.clear();
    return true;
}

bool MigrateSafe::Move(const std::string& id, int64_t claimed, std::string& err)
{
    if (m_failed) {
        err = MIGRATE_SAFE_JOURNAL;
        return false;
    }
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        err = MIGRATE_SAFE_ID;
        return false;
    }
    if (claimed > it->second.assurance) {
        err = MIGRATE_SAFE_UPGRADE;
        return false;
    }
    err.clear();
    return true;
}

void MigrateSafe::Fail()
{
    m_failed = true;
}

void MigrateSafe::Clear()
{
    m_failed = false;
}

bool MigrateSafe::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool MigrateSafe::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool MigrateSafe::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool MigrateSafe::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool MigrateSafe::present(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

std::string MigrateSafe::body(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        return std::string();
    }
    return it->second.body;
}

int64_t MigrateSafe::assurance(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        return static_cast<int64_t>(0);
    }
    return it->second.assurance;
}

} // namespace modelnet
