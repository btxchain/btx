// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/selective_files.h>

namespace modelnet {

void SelectiveFileSet::ClearUpgradeTracking()
{
    m_reused.clear();
    m_newly.clear();
}

void SelectiveFileSet::SelectAll()
{
    m_all = true;
    m_files.clear();
    ClearUpgradeTracking();
}

void SelectiveFileSet::SelectOnly(const std::vector<uint32_t>& files)
{
    m_all = false;
    m_files.clear();
    ClearUpgradeTracking();
    for (uint32_t f : files) m_files.insert(f);
}

void SelectiveFileSet::SetFileCount(uint32_t n)
{
    m_file_count = n;
}

void SelectiveFileSet::UpgradeSelection(const std::vector<uint32_t>& more_files)
{
    ClearUpgradeTracking();
    std::set<uint32_t> seen;
    for (uint32_t f : more_files) {
        if (!seen.insert(f).second) continue;
        if (Selected(f)) {
            m_reused.push_back(f);
        } else {
            m_newly.push_back(f);
            m_files.insert(f);
        }
    }
}

bool SelectiveFileSet::Selected(uint32_t file_index) const
{
    if (m_all) return true;
    return m_files.count(file_index) != 0;
}

bool SelectiveFileSet::AdvertiseHave(uint32_t file_index) const
{
    return Selected(file_index);
}

bool SelectiveFileSet::AdvertiseComplete() const
{
    return AllFiles();
}

bool SelectiveFileSet::AllFiles() const
{
    if (m_all) return true;
    if (m_file_count == 0) return false;
    for (uint32_t i = 0; i < m_file_count; ++i) {
        if (m_files.count(i) == 0) return false;
    }
    return true;
}

} // namespace modelnet
