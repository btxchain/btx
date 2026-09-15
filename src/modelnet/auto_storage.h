// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_AUTO_STORAGE_H
#define BITCOIN_MODELNET_AUTO_STORAGE_H

#include <modelnet/types.h>
#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

enum class StorageMode : uint8_t {
    AUTO = 0,
    FIXED = 1,
    DISABLED = 2,
};

const char* StorageModeName(StorageMode mode);
bool StorageModeFromName(const std::string& name, StorageMode& out);

/** Injected filesystem stats for the volume that holds the model store. */
struct FsStats {
    uint64_t capacity{0};
    uint64_t available{0};
};

struct AutoStorageParams {
    uint64_t min_useful{32 * GIB};
    uint64_t max_auto{512 * GIB};
    /** 0 = max(min_useful, 10% of capacity). */
    uint64_t reserve_override{0};
};

struct AutoQuotaResult {
    uint64_t target_bytes{0};
    uint64_t effective_bytes{0};
    uint64_t reserve_bytes{0};
    uint64_t safe_available_bytes{0};
};

struct AutoGrowResult {
    bool ok{false};
    uint64_t effective_bytes{0};
    std::string error;
    uint64_t required_bytes{0};
    uint64_t allowance_bytes{0};
    uint64_t safe_disk_bytes{0};
};

/** Parse `auto`, `0`, `80GiB`, raw bytes. `auto` is not a magic byte count. */
bool ParseModelStorage(const std::string& in, StorageMode& mode, uint64_t& fixed_bytes, std::string& err);

uint64_t DefaultFreeSpaceReserve(uint64_t capacity, const AutoStorageParams& p);

/** AUTO budget for the model-store filesystem. Never encoded as a magic quota. */
AutoQuotaResult ComputeAutoQuota(const FsStats& fs, const AutoStorageParams& p);

/** Grow AUTO quota for an intentional import/getmodel. Never past max_auto. */
AutoGrowResult GrowAutoQuotaForRequest(const FsStats& fs, const AutoStorageParams& p,
                                       uint64_t current_effective, uint64_t used_bytes,
                                       uint64_t need_bytes);

bool StatFilesystem(const fs::path& path, FsStats& out, std::string& err);

/** True when a write of need_bytes would keep reserve free space. */
bool WriteKeepsReserve(const FsStats& fs, uint64_t reserve_bytes, uint64_t need_bytes);

} // namespace modelnet

#endif // BITCOIN_MODELNET_AUTO_STORAGE_H
