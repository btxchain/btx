// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/auto_storage.h>

#include <modelnet/policy.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/statvfs.h>
#include <system_error>

namespace modelnet {

const char* StorageModeName(StorageMode mode)
{
    switch (mode) {
    case StorageMode::AUTO: return "AUTO";
    case StorageMode::FIXED: return "FIXED";
    case StorageMode::DISABLED: return "DISABLED";
    }
    return "DISABLED";
}

bool StorageModeFromName(const std::string& name, StorageMode& out)
{
    std::string s = name;
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (s == "auto") {
        out = StorageMode::AUTO;
        return true;
    }
    if (s == "fixed") {
        out = StorageMode::FIXED;
        return true;
    }
    if (s == "disabled" || s == "off" || s == "0") {
        out = StorageMode::DISABLED;
        return true;
    }
    return false;
}

bool ParseModelStorage(const std::string& in, StorageMode& mode, uint64_t& fixed_bytes, std::string& err)
{
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (c != ' ' && c != '_') s.push_back(c);
    }
    if (s.empty()) {
        err = "empty storage spec";
        return false;
    }
    std::string lower = s;
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (lower == "auto") {
        mode = StorageMode::AUTO;
        fixed_bytes = 0;
        return true;
    }
    if (!ParseModelBytes(s, fixed_bytes, err)) return false;
    mode = (fixed_bytes == 0) ? StorageMode::DISABLED : StorageMode::FIXED;
    return true;
}

uint64_t DefaultFreeSpaceReserve(uint64_t capacity, const AutoStorageParams& p)
{
    if (p.reserve_override > 0) return p.reserve_override;
    const uint64_t tenth = capacity / 10;
    return std::max(p.min_useful, tenth);
}

AutoQuotaResult ComputeAutoQuota(const FsStats& fs, const AutoStorageParams& p)
{
    AutoQuotaResult r;
    if (fs.capacity == 0) return r;
    r.reserve_bytes = DefaultFreeSpaceReserve(fs.capacity, p);
    r.safe_available_bytes = fs.available > r.reserve_bytes ? fs.available - r.reserve_bytes : 0;
    const uint64_t max_auto = p.max_auto == 0 ? (512 * GIB) : p.max_auto;
    r.target_bytes = std::min(max_auto, fs.capacity / 10);
    uint64_t effective = r.target_bytes;
    if (effective < p.min_useful) {
        if (r.safe_available_bytes >= p.min_useful) effective = p.min_useful;
        else effective = r.safe_available_bytes;
    } else {
        effective = std::min(effective, r.safe_available_bytes);
    }
    r.effective_bytes = effective;
    return r;
}

AutoGrowResult GrowAutoQuotaForRequest(const FsStats& fs, const AutoStorageParams& p,
                                       uint64_t current_effective, uint64_t used_bytes,
                                       uint64_t need_bytes)
{
    AutoGrowResult g;
    g.required_bytes = need_bytes;
    const AutoQuotaResult base = ComputeAutoQuota(fs, p);
    g.allowance_bytes = current_effective ? current_effective : base.effective_bytes;
    g.safe_disk_bytes = base.safe_available_bytes;
    const uint64_t max_auto = p.max_auto == 0 ? (512 * GIB) : p.max_auto;
    const uint64_t want = used_bytes > UINT64_MAX - need_bytes ? UINT64_MAX : used_bytes + need_bytes;
    if (want <= g.allowance_bytes) {
        g.ok = true;
        g.effective_bytes = g.allowance_bytes;
        return g;
    }
    if (need_bytes > max_auto) {
        g.error = "Model requires more than the automatic storage cap. Model requires: " +
                  std::to_string(need_bytes) + " Current automatic storage allowance: " +
                  std::to_string(g.allowance_bytes) + " Safe disk available: " +
                  std::to_string(base.safe_available_bytes);
        g.effective_bytes = g.allowance_bytes;
        return g;
    }
    const uint64_t grown = std::min(want, std::min(max_auto, base.safe_available_bytes));
    if (grown < want) {
        g.error = "Not enough safe disk above the free-space reserve. Model requires: " +
                  std::to_string(need_bytes) + " Current automatic storage allowance: " +
                  std::to_string(g.allowance_bytes) + " Safe disk available: " +
                  std::to_string(base.safe_available_bytes);
        g.effective_bytes = g.allowance_bytes;
        return g;
    }
    g.ok = true;
    g.effective_bytes = grown;
    return g;
}

bool StatFilesystem(const fs::path& path, FsStats& out, std::string& err)
{
    out = {};
    std::error_code ec;
    fs::create_directories(path);
    struct statvfs s {};
    if (statvfs(path.c_str(), &s) != 0) {
        err = std::strerror(errno);
        return false;
    }
    const uint64_t fr = s.f_frsize ? static_cast<uint64_t>(s.f_frsize) : static_cast<uint64_t>(s.f_bsize);
    out.capacity = fr * static_cast<uint64_t>(s.f_blocks);
    out.available = fr * static_cast<uint64_t>(s.f_bavail);
    return true;
}

bool WriteKeepsReserve(const FsStats& fs, uint64_t reserve_bytes, uint64_t need_bytes)
{
    if (fs.available < reserve_bytes) return false;
    return fs.available - reserve_bytes >= need_bytes;
}

} // namespace modelnet
