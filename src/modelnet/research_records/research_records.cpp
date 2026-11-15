// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_records/research_records.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool ResearchRecords::stored(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

std::string ResearchRecords::body(const std::string& id) const
{
    const auto found = m_rows.find(id);
    if (found == m_rows.end()) return {};
    return found->second.body;
}

int64_t ResearchRecords::sequence(const std::string& id) const
{
    const auto found = m_rows.find(id);
    if (found == m_rows.end()) return static_cast<int64_t>(0);
    return found->second.sequence;
}

std::string ResearchRecords::author(const std::string& id) const
{
    const auto found = m_rows.find(id);
    if (found == m_rows.end()) return {};
    return found->second.author;
}

bool ResearchRecords::Publish(const std::string& id, const std::string& body, const std::string& author, int64_t sequence, std::string& err)
{
    if (id.empty() || body.empty() || author.empty()) {
        err = RESEARCH_RECORDS_FIELD;
        return false;
    }
    if (sequence < static_cast<int64_t>(1)) {
        err = RESEARCH_RECORDS_SEQUENCE;
        return false;
    }
    const auto found = m_rows.find(id);
    if (found == m_rows.end()) {
        m_rows.emplace(id, Row{body, author, sequence});
        err.clear();
        return true;
    }
    Row& row = found->second;
    if (body != row.body) {
        err = RESEARCH_RECORDS_MISMATCH;
        return false;
    }
    if (sequence < row.sequence) {
        err = RESEARCH_RECORDS_ROLLBACK;
        return false;
    }
    if (sequence == row.sequence) {
        err = NIFDT_REPLAY;
        return false;
    }
    row.sequence = sequence;
    err.clear();
    return true;
}

bool ResearchRecords::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool ResearchRecords::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool ResearchRecords::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ResearchRecords::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
