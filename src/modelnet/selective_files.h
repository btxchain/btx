// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SELECTIVE_FILES_H
#define BITCOIN_MODELNET_SELECTIVE_FILES_H

#include <cstdint>
#include <set>
#include <vector>

namespace modelnet {

/** SELECTIVE_FILES_V1: only selected file indexes may be advertised as HAVE. */
class SelectiveFileSet {
    std::set<uint32_t> m_files;
    std::vector<uint32_t> m_reused;
    std::vector<uint32_t> m_newly;
    uint32_t m_file_count{0};
    bool m_all{true};

    void ClearUpgradeTracking();

public:
    void SelectAll();
    void SelectOnly(const std::vector<uint32_t>& files);
    /** Known catalog size. AllFiles() is true when every index in [0, n) is selected. */
    void SetFileCount(uint32_t n);
    /** Union more_files into the selected set without clearing existing members. */
    void UpgradeSelection(const std::vector<uint32_t>& more_files);
    bool Selected(uint32_t file_index) const;
    /** Unselected files must not be advertised. */
    bool AdvertiseHave(uint32_t file_index) const;
    /** COMPLETE (full artifact) only when AllFiles(). IncompleteMustNotAdvertiseComplete. */
    bool AdvertiseComplete() const;
    bool AllFiles() const;
    const std::vector<uint32_t>& ReusedFiles() const { return m_reused; }
    const std::vector<uint32_t>& NewlyRequested() const { return m_newly; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SELECTIVE_FILES_H
