// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_execute.h>

#include <modelnet/package_install.h>
#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <span.h>
#include <util/fs.h>
#include <util/time.h>

#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <set>

namespace modelnet {
namespace {

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

std::string NowMsString()
{
    const int64_t now_ms = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    return std::to_string(now_ms < 0 ? 0 : now_ms);
}

bool EnsureParentsNoFollow(const fs::path& dest_file, std::string& err_code, std::string& err)
{
    fs::path parent = dest_file.parent_path();
    if (parent.empty()) return true;
    fs::path cur;
    for (const auto& part : parent) {
        cur /= part;
        if (std::filesystem::is_symlink(cur)) {
            return Fail(err_code, err, "SYMLINK_REFUSED", "materialize parent is a symlink");
        }
        if (!fs::exists(cur)) {
            try {
                fs::create_directories(cur);
            } catch (const fs::filesystem_error&) {
                return Fail(err_code, err, "IO_ERROR", "mkdir");
            }
        } else if (!std::filesystem::is_directory(cur)) {
            return Fail(err_code, err, "OVERWRITE_REFUSED", "parent not a directory");
        }
    }
    return true;
}

bool ReadAll(const std::string& path, std::string& bytes, std::string& err)
{
    bytes.clear();
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        err = "source open";
        return false;
    }
    bytes.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.size() > ACQ_EXECUTE_MAX_FILE_BYTES) {
        err = "file too large";
        return false;
    }
    return true;
}

} // namespace

bool MaterializePathAllowed(const std::string& rel_path, std::string& err)
{
    return InstallArchiveEntryAllowed(rel_path, /*is_symlink=*/false, /*is_duplicate_name=*/false, err);
}

bool Sha384Path(const std::string& path, std::string& hex, std::string& err)
{
    hex.clear();
    std::string bytes;
    if (!ReadAll(path, bytes, err)) return false;
    unsigned char d[CSHA384::OUTPUT_SIZE];
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    hasher.Finalize(d);
    hex = HexStr(Span<const unsigned char>{d, CSHA384::OUTPUT_SIZE});
    return true;
}

bool ExclusiveNofollowWrite(const std::string& dest_path, const std::string& bytes, std::string& err_code,
                            std::string& err)
{
    if (bytes.size() > ACQ_EXECUTE_MAX_FILE_BYTES) {
        return Fail(err_code, err, "BUDGET_EXCEEDED", "file too large");
    }
    const fs::path dest = fs::PathFromString(dest_path);
    if (std::filesystem::is_symlink(dest)) {
        return Fail(err_code, err, "SYMLINK_REFUSED", "dest is a symlink");
    }
    if (!EnsureParentsNoFollow(dest, err_code, err)) return false;
    const int fd = ::open(dest.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return Fail(err_code, err, (errno == EEXIST) ? "OVERWRITE_REFUSED" : "IO_ERROR",
                    (errno == EEXIST) ? "overwrite refused" : "open failed");
    }
    const ssize_t n = ::write(fd, bytes.data(), bytes.size());
    ::close(fd);
    if (n < 0 || static_cast<size_t>(n) != bytes.size()) {
        ::unlink(dest.c_str());
        return Fail(err_code, err, "IO_ERROR", "write failed");
    }
    return true;
}

CreditBroker& GlobalAcquisitionCredits()
{
    static CreditBroker g{64ull << 20};
    return g;
}

bool TryEvictUnleasedPath(const std::string& path, const std::vector<OutputLease>& leases, std::string& err_code,
                           std::string& err)
{
    err_code.clear();
    err.clear();
    for (const auto& l : leases) {
        if (l.active && l.path == path) {
            return Fail(err_code, err, "LEASE_HOLD", "active lease");
        }
    }
    const fs::path p = fs::PathFromString(path);
    if (std::filesystem::is_symlink(p)) {
        return Fail(err_code, err, "SYMLINK_REFUSED", "evict symlink");
    }
    if (!fs::exists(p)) return true;
    std::error_code ec;
    std::filesystem::remove(p, ec);
    if (ec) return Fail(err_code, err, "IO_ERROR", ec.message());
    return true;
}

bool ExecuteBtxAcquisition(const ExecuteAcquisitionRequest& req, AcquisitionReceipt& out, uint64_t& reserved_bytes,
                           std::string& err_code, std::string& err)
{
    out = {};
    reserved_bytes = 0;
    err_code.clear();
    err.clear();
    if (req.plan.retrieval_mode != "FREE_ONLY") {
        return Fail(err_code, err, "PAID_PATH_FORBIDDEN", "FREE_ONLY");
    }
    if (req.plan.destination.empty() || req.plan.destination.find("://") != std::string::npos) {
        return Fail(err_code, err, "DESTINATION_REQUIRED", "local destination");
    }
    if (req.files.empty()) {
        return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "no verified local files");
    }
    if (req.files.size() > ACQ_EXECUTE_MAX_FILES) {
        return Fail(err_code, err, "BUDGET_EXCEEDED", "too many files");
    }

    const fs::path dest_root = fs::PathFromString(req.plan.destination);
    if (std::filesystem::is_symlink(dest_root)) {
        return Fail(err_code, err, "SYMLINK_REFUSED", "destination is a symlink");
    }

    std::set<std::string> seen;
    uint64_t need = 0;
    for (const auto& f : req.files) {
        std::string path_err;
        if (!MaterializePathAllowed(f.relative_path, path_err)) {
            return Fail(err_code, err, "DOCUMENT_PATH_REJECTED", path_err);
        }
        if (!seen.insert(f.relative_path).second) {
            return Fail(err_code, err, "OVERWRITE_REFUSED", "duplicate path");
        }
        if (f.sha384_hex.size() != 96) {
            return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "sha384");
        }
        if (!f.source_path.empty()) {
            std::string bytes, rerr;
            if (!ReadAll(f.source_path, bytes, rerr)) {
                return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", rerr);
            }
            need += bytes.size();
        }
    }
    const uint64_t reserve = req.reserve_bytes ? req.reserve_bytes : std::max<uint64_t>(need, 1);
    if (req.credit) {
        if (!req.credit->TryReserve(reserve)) {
            return Fail(err_code, err, "BUDGET_EXCEEDED", "acquisition credit");
        }
        reserved_bytes = reserve;
    }

    auto release_on_fail = [&]() {
        if (req.credit && reserved_bytes) {
            req.credit->Release(reserved_bytes);
            reserved_bytes = 0;
        }
    };

    try {
        if (!fs::exists(dest_root)) {
            fs::create_directories(dest_root);
        }
        if (std::filesystem::is_symlink(dest_root)) {
            release_on_fail();
            return Fail(err_code, err, "SYMLINK_REFUSED", "destination became a symlink");
        }
    } catch (const fs::filesystem_error&) {
        release_on_fail();
        return Fail(err_code, err, "IO_ERROR", "create destination");
    }

    UniValue paths(UniValue::VARR);
    for (const auto& f : req.files) {
        const fs::path dest = dest_root / fs::PathFromString(f.relative_path);
        const std::string dest_s = fs::PathToString(dest);
        if (std::filesystem::is_symlink(dest)) {
            release_on_fail();
            return Fail(err_code, err, "SYMLINK_REFUSED", "output is a symlink");
        }
        if (fs::exists(dest) && !std::filesystem::is_directory(dest)) {
            std::string have, herr;
            if (Sha384Path(dest_s, have, herr) && have == f.sha384_hex) {
                paths.push_back(dest_s);
                continue;
            }
            std::error_code ec;
            std::filesystem::remove(dest, ec);
            if (ec || std::filesystem::is_symlink(dest) || fs::exists(dest)) {
                release_on_fail();
                return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "stale cache not replaced");
            }
        }
        if (f.source_path.empty()) {
            release_on_fail();
            return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "no source after cache miss");
        }
        std::string bytes, rerr;
        if (!ReadAll(f.source_path, bytes, rerr)) {
            release_on_fail();
            return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", rerr);
        }
        unsigned char d[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
        hasher.Finalize(d);
        const std::string got = HexStr(Span<const unsigned char>{d, CSHA384::OUTPUT_SIZE});
        if (got != f.sha384_hex) {
            release_on_fail();
            return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "source hash mismatch");
        }
        if (!ExclusiveNofollowWrite(dest_s, bytes, err_code, err)) {
            release_on_fail();
            return false;
        }
        std::string again;
        if (!Sha384Path(dest_s, again, rerr) || again != f.sha384_hex) {
            ::unlink(dest.c_str());
            release_on_fail();
            return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "post-write hash");
        }
        paths.push_back(dest_s);
    }

    UniValue rec(UniValue::VOBJ);
    rec.pushKV("schema_version", 1);
    rec.pushKV("receipt_id", req.plan.plan_id_hex);
    rec.pushKV("package_core_id", req.plan.package_core_id.Hex());
    rec.pushKV("plan_id", req.plan.plan_id_hex);
    UniValue rids(UniValue::VARR);
    for (const auto& id : req.plan.resource_ids) rids.push_back(id);
    rec.pushKV("resource_ids", rids);
    rec.pushKV("state", "MODEL_READY");
    rec.pushKV("local_paths", paths);
    rec.pushKV("manifest_verified", true);
    rec.pushKV("file_bytes_verified", true);
    UniValue src(UniValue::VARR);
    src.push_back("LOCAL_DISK");
    rec.pushKV("source_classes_used", src);
    rec.pushKV("lease_id", req.plan.plan_id_hex.size() >= 32 ? req.plan.plan_id_hex.substr(0, 32) : req.plan.plan_id_hex);
    rec.pushKV("runtime_executed", false);
    rec.pushKV("created_at_ms", NowMsString());
    out.receipt_id_hex = req.plan.plan_id_hex;
    out.plan_id_hex = req.plan.plan_id_hex;
    out.ready_state = "MODEL_READY";
    out.json = std::move(rec);
    return true;
}

} // namespace modelnet
