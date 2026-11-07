// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_sync/dt_sync.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtSync::Admit(const std::string& fragment, const std::string& member, int64_t version, std::string& err)
{
    if (fragment.empty()) {
        err = kDtSyncFragment;
        return false;
    }
    if (member.empty()) {
        err = kDtSyncMember;
        return false;
    }
    if (m_fragments.count(fragment) != 0) {
        err = NIFDT_REPLAY;
        return false;
    }
    Fragment row;
    row.member = member;
    row.version = version;
    row.usable = true;
    m_fragments.emplace(fragment, std::move(row));
    err.clear();
    return true;
}

bool DtSync::NoteStale(const std::string& fragment, int64_t lag, std::string& err)
{
    if (fragment.empty()) {
        err = kDtSyncFragment;
        return false;
    }
    const auto it = m_fragments.find(fragment);
    if (it == m_fragments.end()) {
        err = kDtSyncFragment;
        return false;
    }
    if (lag > static_cast<int64_t>(2)) {
        it->second.usable = false;
        err = kDtSyncStale;
        return false;
    }
    err.clear();
    return true;
}

bool DtSync::Replace(const std::string& old_sync, const std::string& new_sync, std::string& err)
{
    if (new_sync.empty()) {
        err = kDtSyncSync;
        return false;
    }
    if (!m_sync.empty() && old_sync != m_sync) {
        err = kDtSyncSync;
        return false;
    }
    m_sync = new_sync;
    err.clear();
    return true;
}

bool DtSync::Commit(std::string& err)
{
    if (m_partition) {
        err = kDtSyncPartition;
        return false;
    }
    int64_t usable = 0;
    int64_t sum = 0;
    bool saw_unusable = false;
    for (const auto& item : m_fragments) {
        if (!item.second.usable) {
            saw_unusable = true;
            continue;
        }
        sum += item.second.version;
        usable += static_cast<int64_t>(1);
    }
    if (saw_unusable) {
        err = kDtSyncStale;
        return false;
    }
    if (usable < static_cast<int64_t>(2)) {
        err = kDtSyncQuorum;
        return false;
    }
    m_head = sum / usable;
    err.clear();
    return true;
}

void DtSync::Partition()
{
    m_partition = true;
}

bool DtSync::Wan(std::string& err)
{
    err = NIFDT_NO_ROUTE;
    return false;
}

bool DtSync::Scan(std::string& err)
{
    err = NIFDT_NOT_SCAN;
    return false;
}

bool DtSync::admitted(const std::string& fragment) const
{
    return m_fragments.find(fragment) != m_fragments.end();
}

bool DtSync::usable(const std::string& fragment) const
{
    const auto it = m_fragments.find(fragment);
    if (it == m_fragments.end()) return false;
    return it->second.usable;
}

std::string DtSync::member(const std::string& fragment) const
{
    const auto it = m_fragments.find(fragment);
    if (it == m_fragments.end()) return {};
    return it->second.member;
}

int64_t DtSync::version(const std::string& fragment) const
{
    const auto it = m_fragments.find(fragment);
    if (it == m_fragments.end()) return static_cast<int64_t>(0);
    return it->second.version;
}

} // namespace modelnet
