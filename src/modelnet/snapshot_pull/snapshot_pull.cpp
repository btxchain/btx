// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/snapshot_pull/snapshot_pull.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool SnapshotPull::stored(const std::string& digest) const
{
    return m_rows.find(digest) != m_rows.end();
}

std::string SnapshotPull::body(const std::string& digest) const
{
    const auto found = m_rows.find(digest);
    if (found == m_rows.end()) return {};
    return found->second.body;
}

int64_t SnapshotPull::sequence(const std::string& digest) const
{
    const auto found = m_rows.find(digest);
    if (found == m_rows.end()) return static_cast<int64_t>(0);
    return found->second.sequence;
}

bool SnapshotPull::Publish(int64_t sequence, const std::string& digest, const std::string& body, std::string& err)
{
    if (digest.empty() || body.empty()) {
        err = SNAPSHOT_PULL_FIELD;
        return false;
    }
    if (sequence < static_cast<int64_t>(1)) {
        err = SNAPSHOT_PULL_SEQUENCE;
        return false;
    }
    const auto found = m_rows.find(digest);
    if (found == m_rows.end()) {
        m_rows.emplace(digest, Row{body, sequence});
        err.clear();
        return true;
    }
    Row& row = found->second;
    if (body != row.body) {
        err = SNAPSHOT_PULL_MISMATCH;
        return false;
    }
    if (sequence < row.sequence) {
        err = SNAPSHOT_PULL_ROLLBACK;
        return false;
    }
    if (sequence > row.sequence) {
        row.sequence = sequence;
    }
    err.clear();
    return true;
}

bool SnapshotPull::Pull(int64_t sequence, const std::string& digest, std::string& err)
{
    const auto found = m_rows.find(digest);
    if (found == m_rows.end()) {
        err = SNAPSHOT_PULL_MISMATCH;
        return false;
    }
    if (sequence < found->second.sequence) {
        err = SNAPSHOT_PULL_ROLLBACK;
        return false;
    }
    m_pulled += static_cast<int64_t>(1);
    err.clear();
    return true;
}

bool SnapshotPull::Replace(const std::string& digest, const std::string& body, std::string& err)
{
    if (digest.empty() || body.empty()) {
        err = SNAPSHOT_PULL_FIELD;
        return false;
    }
    const auto found = m_rows.find(digest);
    if (found == m_rows.end() || body != found->second.body) {
        err = SNAPSHOT_PULL_MISMATCH;
        return false;
    }
    err.clear();
    return true;
}

bool SnapshotPull::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = SNAPSHOT_PULL_HOSTS;
        return false;
    }
    err.clear();
    return true;
}

bool SnapshotPull::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SnapshotPull::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool SnapshotPull::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool SnapshotPull::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
