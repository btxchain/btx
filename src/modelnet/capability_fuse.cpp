// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>

#include <util/fs.h>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

bool PiecesFullyVerified(const std::vector<std::vector<unsigned char>>& pieces,
                         const std::vector<bool>& verified_bitmap)
{
    if (pieces.size() != verified_bitmap.size()) return false;
    for (size_t i = 0; i < pieces.size(); ++i) {
        if (!verified_bitmap[i] || pieces[i].empty()) return false;
    }
    return true;
}

bool ReadVerifiedSlice(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                       const std::vector<bool>& verified_bitmap, uint64_t piece_size,
                       std::vector<unsigned char>& out, std::string& err_code, std::string& err)
{
    out.clear();
    if (SparseHoleIsUnverified(offset, length, verified_bitmap, piece_size)) {
        return Fail(err_code, err, "RANGE_UNVERIFIED", "unverified hole; refusing sparse zeros");
    }
    if (offset > verified_bytes.size() || length > verified_bytes.size() - offset) {
        return Fail(err_code, err, "RANGE_UNVERIFIED", "range not covered by verified bytes");
    }
    if (length == 0) return true;
    out.assign(verified_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
               verified_bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
    return true;
}

} // namespace

bool FuseAvailable()
{
#ifdef __linux__
    return fs::exists(fs::PathFromString("/dev/fuse"));
#else
    // Never pretend macOS (or any non-Linux) FUSE is a Linux fault path.
    return false;
#endif
}

bool FuseReadVerified(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                      const std::vector<bool>& verified_bitmap, uint64_t piece_size,
                      std::vector<unsigned char>& out, std::string& err_code, std::string& err)
{
    return ReadVerifiedSlice(verified_bytes, offset, length, verified_bitmap, piece_size, out, err_code, err);
}

bool PortableStreamRead(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                        const std::vector<bool>& verified_bitmap, uint64_t piece_size,
                        std::vector<unsigned char>& out, std::string& err_code, std::string& err)
{
    return ReadVerifiedSlice(verified_bytes, offset, length, verified_bitmap, piece_size, out, err_code, err);
}

bool FuseMountDirectory(const std::string& dest_dir, const std::string& filename,
                        const std::vector<std::vector<unsigned char>>& pieces,
                        const std::vector<bool>& verified_bitmap, Generation16 gen, std::string& err_code,
                        std::string& err)
{
    if (dest_dir.empty() || filename.empty() || dest_dir.find("..") != std::string::npos ||
        filename.find("..") != std::string::npos || filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos) {
        return Fail(err_code, err, "INVALID_PARAMETER", "dest");
    }
    if (!PiecesFullyVerified(pieces, verified_bitmap)) {
        return Fail(err_code, err, "INCOMPLETE_FILE",
                    "ordinary export refuses incomplete/unverified extents");
    }
    const fs::path dir = fs::PathFromString(dest_dir);
    if (!fs::exists(dir) && !fs::create_directories(dir)) {
        return Fail(err_code, err, "IO_ERROR", "mkdir");
    }
    const fs::path dest = dir / filename.c_str();
    return MaterializeCompleteFile(pieces, fs::PathToString(dest), gen, err_code, err);
}

bool FuseHelperAliveRead(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                         const std::vector<bool>& verified_bitmap, uint64_t piece_size, bool helper_alive,
                         bool& retry_materialized, std::vector<unsigned char>& out, std::string& err_code,
                         std::string& err)
{
    retry_materialized = false;
    out.clear();
    if (!helper_alive) {
        retry_materialized = true;
        return Fail(err_code, err, "FAULT_FAILURE",
                    "helper died during fault-gated read; retry materialized mode");
    }
    return FuseReadVerified(verified_bytes, offset, length, verified_bitmap, piece_size, out, err_code, err);
}

bool CrashBitmapRecover(bool file_exists, bool sidecar_bit, bool metadata_committed, bool independently_reverified,
                        std::vector<bool>& promoted, std::string& err_code, std::string& err)
{
    promoted.clear();
    (void)file_exists;
    (void)sidecar_bit;
    if (!metadata_committed || !independently_reverified) {
        return Fail(err_code, err, "UNCERTAIN_EXTENT",
                    "recovery never promotes solely because a file or bitmap bit exists");
    }
    promoted.push_back(true);
    return true;
}

bool MaterializeSafeSnapshot(const std::string& operator_src, const std::string& dest, Generation16 gen,
                             std::string& err_code, std::string& err)
{
    if (operator_src.empty() || dest.empty() || dest.find("..") != std::string::npos) {
        return Fail(err_code, err, "INVALID_PARAMETER", "path");
    }
    std::ifstream in(operator_src, std::ios::binary);
    if (!in) return Fail(err_code, err, "IO_ERROR", "open operator source");
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> bytes(raw.begin(), raw.end());
    if (bytes.empty()) return Fail(err_code, err, "INCOMPLETE_FILE", "empty operator source");
    return MaterializeCompleteFile({std::move(bytes)}, dest, gen, err_code, err);
}

LoadStrategyResult DenseReadiness(const std::vector<bool>& required_layer_piece_verified)
{
    for (bool v : required_layer_piece_verified) {
        if (!v) return LoadStrategyResult::CLEAN_MISS;
    }
    return LoadStrategyResult::READY;
}

bool LoadStagesWithinBudget(const std::vector<int64_t>& stage_ms, bool overlapped, uint64_t extra_full_copies,
                            int64_t& wall_ms, std::string& err)
{
    wall_ms = 0;
    if (extra_full_copies != 0) {
        err = "hidden full duplicate";
        return false;
    }
    wall_ms = CriticalPathTtcMs(stage_ms, overlapped);
    return true;
}

bool LoaderAdmitWithBackpressure(HostResourceBroker& broker, uint64_t host, uint64_t pinned, uint64_t device,
                                 std::string& err_code, std::string& err)
{
    std::string perr;
    if (!broker.Reserve(host, pinned, device, /*speculative=*/false, perr)) {
        return Fail(err_code, err, "BUDGET_EXCEEDED", perr);
    }
    return true;
}

LoadStrategyResult ApplyFailedStrategy(std::vector<unsigned char>& dest,
                                       const std::vector<unsigned char>& partial_transform, bool mutated)
{
    if (mutated) {
        dest = partial_transform;
        return LoadStrategyResult::FAILED_MUTATED;
    }
    return LoadStrategyResult::FAILED_UNMUTATED;
}

void ResetLoadDestination(std::vector<unsigned char>& dest)
{
    dest.clear();
}

LoadStrategyResult ApplyReadyStrategy(std::vector<unsigned char>& dest, const std::vector<unsigned char>& clean)
{
    dest = clean;
    return LoadStrategyResult::READY;
}

bool ClassifyLoadError(bool target_oom, bool source_corrupt, bool& source_health_ok, std::string& err_code,
                       std::string& err)
{
    if (source_corrupt) {
        source_health_ok = false;
        return Fail(err_code, err, "SOURCE_CORRUPT", "source bytes failed verification");
    }
    if (target_oom) {
        return Fail(err_code, err, "TARGET_OOM", "local replan; source health unchanged");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool DeviceVerificationGate(const std::vector<unsigned char>& dma, const std::vector<unsigned char>& expected,
                            bool& compute_consumed, std::string& err_code, std::string& err)
{
    compute_consumed = false;
    if (dma != expected) {
        return Fail(err_code, err, "DEVICE_VERIFY_FAILED",
                    "destination bytes do not match verified commitment");
    }
    compute_consumed = true;
    return true;
}

bool BindOpenGeneration(const Digest48& manifest, Generation16 gen, const std::vector<unsigned char>& bytes,
                        VerifiedRangeLease& out, std::string& err_code, std::string& err)
{
    return ReadVerifiedRange(manifest, /*file_index=*/0, /*offset=*/0, bytes.size(), bytes, gen, out, err_code,
                             err);
}

} // namespace modelnet
