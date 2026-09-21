// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Native coverage for JIT-MAT-01..07 and JIT-LOAD-01..07.
// Live Linux FUSE kernel mounts remain NOT_RUN (BOOST_TEST_MESSAGE).

#include <crypto/sha384.h>
#include <modelnet/capability.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <util/readwritefile.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace modelnet {

bool FuseAvailable();
bool FuseReadVerified(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                      const std::vector<bool>& verified_bitmap, uint64_t piece_size,
                      std::vector<unsigned char>& out, std::string& err_code, std::string& err);
bool PortableStreamRead(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                        const std::vector<bool>& verified_bitmap, uint64_t piece_size,
                        std::vector<unsigned char>& out, std::string& err_code, std::string& err);
bool FuseMountDirectory(const std::string& dest_dir, const std::string& filename,
                        const std::vector<std::vector<unsigned char>>& pieces,
                        const std::vector<bool>& verified_bitmap, Generation16 gen, std::string& err_code,
                        std::string& err);
bool FuseHelperAliveRead(const std::vector<unsigned char>& verified_bytes, uint64_t offset, uint64_t length,
                         const std::vector<bool>& verified_bitmap, uint64_t piece_size, bool helper_alive,
                         bool& retry_materialized, std::vector<unsigned char>& out, std::string& err_code,
                         std::string& err);
bool CrashBitmapRecover(bool file_exists, bool sidecar_bit, bool metadata_committed, bool independently_reverified,
                        std::vector<bool>& promoted, std::string& err_code, std::string& err);
bool MaterializeSafeSnapshot(const std::string& operator_src, const std::string& dest, Generation16 gen,
                             std::string& err_code, std::string& err);
LoadStrategyResult DenseReadiness(const std::vector<bool>& required_layer_piece_verified);
bool LoadStagesWithinBudget(const std::vector<int64_t>& stage_ms, bool overlapped, uint64_t extra_full_copies,
                            int64_t& wall_ms, std::string& err);
bool LoaderAdmitWithBackpressure(HostResourceBroker& broker, uint64_t host, uint64_t pinned, uint64_t device,
                                 std::string& err_code, std::string& err);
LoadStrategyResult ApplyFailedStrategy(std::vector<unsigned char>& dest,
                                       const std::vector<unsigned char>& partial_transform, bool mutated);
void ResetLoadDestination(std::vector<unsigned char>& dest);
LoadStrategyResult ApplyReadyStrategy(std::vector<unsigned char>& dest, const std::vector<unsigned char>& clean);
bool ClassifyLoadError(bool target_oom, bool source_corrupt, bool& source_health_ok, std::string& err_code,
                       std::string& err);
bool DeviceVerificationGate(const std::vector<unsigned char>& dma, const std::vector<unsigned char>& expected,
                            bool& compute_consumed, std::string& err_code, std::string& err);
bool BindOpenGeneration(const Digest48& manifest, Generation16 gen, const std::vector<unsigned char>& bytes,
                        VerifiedRangeLease& out, std::string& err_code, std::string& err);

} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_mat_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Concat(const std::vector<std::vector<unsigned char>>& pieces)
{
    std::vector<unsigned char> out;
    for (const auto& p : pieces) out.insert(out.end(), p.begin(), p.end());
    return out;
}

modelnet::Digest48 Sha384(const std::vector<unsigned char>& bytes)
{
    modelnet::Digest48 d;
    CSHA384 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(d.data.data());
    return d;
}

std::vector<unsigned char> FileBytes(const fs::path& p)
{
    const auto [ok, raw] = ReadBinaryFile(p);
    BOOST_REQUIRE(ok);
    return std::vector<unsigned char>(raw.begin(), raw.end());
}

} // namespace

BOOST_AUTO_TEST_CASE(jit_mat_01_no_zero_holes)
{
    using namespace modelnet;
    const uint64_t piece_size = 4;
    const std::vector<unsigned char> backing{0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00};
    std::vector<bool> bitmap{true, false};
    std::vector<unsigned char> out{0xff};
    std::string err_code, err;

    BOOST_CHECK(SparseHoleIsUnverified(4, 4, bitmap, piece_size));
    BOOST_CHECK(!FuseReadVerified(backing, 4, 4, bitmap, piece_size, out, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RANGE_UNVERIFIED");
    BOOST_CHECK(out.empty());
    BOOST_CHECK(out.size() != 4);

    out.assign(4, 0xaa);
    BOOST_CHECK(!PortableStreamRead(backing, 2, 4, bitmap, piece_size, out, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RANGE_UNVERIFIED");
    BOOST_CHECK(out.empty());

    out.clear();
    BOOST_REQUIRE(FuseReadVerified(backing, 0, 4, bitmap, piece_size, out, err_code, err));
    BOOST_CHECK_EQUAL(out.size(), 4U);
    BOOST_CHECK(out[0] == 0x11);

    std::vector<std::vector<unsigned char>> pieces{{0x11, 0x22, 0x33, 0x44}, {}};
    const fs::path dir = m_path_root / "jit-mat-01";
    const std::string dest_dir = fs::PathToString(dir);
    Generation16 gen{};
    BOOST_CHECK(!FuseMountDirectory(dest_dir, "model.bin", pieces, bitmap, gen, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "INCOMPLETE_FILE");
    BOOST_CHECK(!fs::exists(dir / "model.bin"));
}

BOOST_AUTO_TEST_CASE(jit_mat_02_final_offset_writes)
{
    using namespace modelnet;
    std::vector<std::vector<unsigned char>> src{{0xa1, 0xa2, 0xa3, 0xa4}, {0xb1, 0xb2, 0xb3, 0xb4}, {0xc1, 0xc2}};
    std::vector<int> arrival{2, 0, 1};
    std::vector<std::vector<unsigned char>> assembled(src.size());
    std::vector<bool> bitmap(src.size(), false);
    for (int i : arrival) {
        assembled[static_cast<size_t>(i)] = src[static_cast<size_t>(i)];
        bitmap[static_cast<size_t>(i)] = true;
    }
    const std::vector<unsigned char> full = Concat(src);
    const fs::path dir = m_path_root / "jit-mat-02";
    std::string err_code, err;
    Generation16 gen{};
    BOOST_REQUIRE(FuseMountDirectory(fs::PathToString(dir), "final.bin", assembled, bitmap, gen, err_code, err));
    const std::vector<unsigned char> on_disk = FileBytes(dir / "final.bin");
    BOOST_CHECK(StreamingEqualsFullFile(on_disk, full));
    BOOST_CHECK(Sha384(on_disk) == Sha384(full));

    std::vector<unsigned char> streamed;
    BOOST_REQUIRE(PortableStreamRead(full, 0, full.size(), bitmap, /*piece_size=*/4, streamed, err_code, err));
    BOOST_CHECK(StreamingEqualsFullFile(streamed, full));
}

BOOST_AUTO_TEST_CASE(jit_mat_03_fault_failure)
{
    using namespace modelnet;
    const std::vector<unsigned char> bytes{0x10, 0x20, 0x30, 0x40};
    const std::vector<bool> bitmap{true};
    std::vector<unsigned char> out{0x00, 0x00, 0x00, 0x00};
    std::string err_code, err;
    bool retry = false;
    BOOST_CHECK(!FuseHelperAliveRead(bytes, 0, 4, bitmap, 4, /*helper_alive=*/false, retry, out, err_code, err));
    BOOST_CHECK(retry);
    BOOST_CHECK_EQUAL(err_code, "FAULT_FAILURE");
    BOOST_CHECK(out.empty());

    retry = false;
    BOOST_REQUIRE(FuseHelperAliveRead(bytes, 0, 4, bitmap, 4, /*helper_alive=*/true, retry, out, err_code, err));
    BOOST_CHECK(!retry);
    BOOST_CHECK_EQUAL(out.size(), 4U);

    BOOST_TEST_MESSAGE("JIT-MAT-03 live helper kill NOT_RUN; simulated helper_alive=false proven");
}

BOOST_AUTO_TEST_CASE(jit_mat_04_immutable_generation)
{
    using namespace modelnet;
    Digest48 manifest{};
    manifest.data[0] = 0x44;
    Generation16 gen_open{};
    gen_open[0] = 0x01;
    Generation16 gen_latest{};
    gen_latest[0] = 0x02;
    const std::vector<unsigned char> open_bytes{0x01, 0x02, 0x03, 0x04};
    std::vector<unsigned char> latest = open_bytes;
    VerifiedRangeLease lease;
    std::string err_code, err;
    BOOST_REQUIRE(BindOpenGeneration(manifest, gen_open, open_bytes, lease, err_code, err));
    latest.assign(4, 0xff);
    BOOST_CHECK(lease.generation == gen_open);
    BOOST_CHECK(lease.generation != gen_latest);
    BOOST_CHECK(StreamingEqualsFullFile(lease.bytes, open_bytes));
    BOOST_CHECK(!StreamingEqualsFullFile(lease.bytes, latest));

    const fs::path dir = m_path_root / "jit-mat-04";
    std::vector<std::vector<unsigned char>> pieces{open_bytes};
    std::vector<bool> bitmap{true};
    BOOST_REQUIRE(FuseMountDirectory(fs::PathToString(dir), "gen.bin", pieces, bitmap, gen_open, err_code, err));
    BOOST_CHECK(!FuseMountDirectory(fs::PathToString(dir), "gen.bin", pieces, bitmap, gen_latest, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "OVERWRITE_REFUSED");
    BOOST_CHECK(StreamingEqualsFullFile(FileBytes(dir / "gen.bin"), open_bytes));
}

BOOST_AUTO_TEST_CASE(jit_mat_05_unsafe_hardlink)
{
    using namespace modelnet;
    const fs::path src = m_path_root / "jit-mat-05-src.bin";
    const fs::path dest = m_path_root / "jit-mat-05-snap.bin";
    const std::string original("SAFE-BYTES-v1");
    BOOST_REQUIRE(WriteBinaryFile(src, original));
    std::string err_code, err;
    Generation16 gen{};
    BOOST_REQUIRE(MaterializeSafeSnapshot(fs::PathToString(src), fs::PathToString(dest), gen, err_code, err));
    BOOST_REQUIRE(WriteBinaryFile(src, std::string("MUTATED-OPERATOR")));
    const auto snap = FileBytes(dest);
    BOOST_CHECK_EQUAL(std::string(snap.begin(), snap.end()), original);
    BOOST_CHECK(std::string(snap.begin(), snap.end()) != "MUTATED-OPERATOR");

    struct stat st_src {}, st_dst {};
    BOOST_REQUIRE_EQUAL(::stat(fs::PathToString(src).c_str(), &st_src), 0);
    BOOST_REQUIRE_EQUAL(::stat(fs::PathToString(dest).c_str(), &st_dst), 0);
    BOOST_CHECK(st_src.st_ino != st_dst.st_ino);
    BOOST_CHECK(!FuseMountDirectory(fs::PathToString(m_path_root), "jit-mat-05-snap.bin", {std::vector<unsigned char>(snap.begin(), snap.end())},
                                    {true}, gen, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "OVERWRITE_REFUSED");
}

BOOST_AUTO_TEST_CASE(jit_mat_06_crash_bitmap)
{
    using namespace modelnet;
    std::vector<bool> promoted;
    std::string err_code, err;
    BOOST_CHECK(!CrashBitmapRecover(/*file_exists=*/true, /*sidecar_bit=*/true, /*metadata_committed=*/false,
                                    /*independently_reverified=*/false, promoted, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "UNCERTAIN_EXTENT");
    BOOST_CHECK(promoted.empty());

    BOOST_CHECK(!CrashBitmapRecover(true, true, /*metadata_committed=*/true, /*independently_reverified=*/false,
                                    promoted, err_code, err));
    BOOST_CHECK(promoted.empty());

    BOOST_REQUIRE(CrashBitmapRecover(true, true, true, true, promoted, err_code, err));
    BOOST_REQUIRE_EQUAL(promoted.size(), 1U);
    BOOST_CHECK(promoted[0]);
}

BOOST_AUTO_TEST_CASE(jit_mat_07_cross_platform_path)
{
    using namespace modelnet;
#ifdef __APPLE__
    BOOST_CHECK(!FuseAvailable());
    BOOST_TEST_MESSAGE("JIT-MAT-07 macOS FUSE NOT_RUN: portable reader only");
#elif defined(__linux__)
    if (!FuseAvailable()) {
        BOOST_TEST_MESSAGE("JIT-MAT-07 Linux FUSE mount NOT_RUN: /dev/fuse absent");
    } else {
        BOOST_TEST_MESSAGE("JIT-MAT-07 /dev/fuse present; live FUSE kernel mount NOT_RUN");
    }
#else
    BOOST_CHECK(!FuseAvailable());
    BOOST_TEST_MESSAGE("JIT-MAT-07 FUSE mount NOT_RUN: non-Linux platform");
#endif
    const std::vector<unsigned char> full{0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1};
    const std::vector<bool> bitmap{true, true};
    std::vector<unsigned char> streamed;
    std::string err_code, err;
    BOOST_REQUIRE(PortableStreamRead(full, 0, full.size(), bitmap, 4, streamed, err_code, err));
    BOOST_CHECK(StreamingEqualsFullFile(streamed, full));

    const fs::path dir = m_path_root / "jit-mat-07";
    std::vector<std::vector<unsigned char>> pieces{{0x9a, 0x9b, 0x9c, 0x9d}, {0x9e, 0x9f, 0xa0, 0xa1}};
    Generation16 gen{};
    BOOST_REQUIRE(FuseMountDirectory(fs::PathToString(dir), "portable.bin", pieces, bitmap, gen, err_code, err));
    BOOST_CHECK(StreamingEqualsFullFile(FileBytes(dir / "portable.bin"), full));
}

BOOST_AUTO_TEST_CASE(jit_load_01_stage_overlap)
{
    using namespace modelnet;
    const std::vector<int64_t> delays{/*network*/ 100, /*hash*/ 80, /*device_copy*/ 90};
    int64_t wall = 0;
    std::string err;
    BOOST_REQUIRE(LoadStagesWithinBudget(delays, /*overlapped=*/true, /*extra_full_copies=*/0, wall, err));
    BOOST_CHECK_EQUAL(wall, 100);
    BOOST_CHECK_EQUAL(CriticalPathTtcMs(delays, true), 100);
    BOOST_CHECK_EQUAL(CriticalPathTtcMs(delays, false), 270);
    BOOST_CHECK(!LoadStagesWithinBudget(delays, true, /*extra_full_copies=*/1, wall, err));
    BOOST_CHECK(err.find("duplicate") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(jit_load_02_dense_readiness)
{
    using namespace modelnet;
    std::vector<bool> layers{true, true, true, false};
    BOOST_CHECK(DenseReadiness(layers) != LoadStrategyResult::READY);
    BOOST_CHECK_EQUAL(LoadStrategyResultName(DenseReadiness(layers)), "CLEAN_MISS");
    layers.back() = true;
    BOOST_CHECK(DenseReadiness(layers) == LoadStrategyResult::READY);
}

BOOST_AUTO_TEST_CASE(jit_load_03_backpressure)
{
    using namespace modelnet;
    HostResourceBroker broker;
    MemoryLimits lim;
    lim.host_physical_bytes = 1024;
    lim.host_pinned_bytes = 256;
    lim.device_bytes = 64;
    std::string cfg_err;
    BOOST_REQUIRE(broker.Configure(lim, cfg_err));
    std::string err_code, err;
    BOOST_REQUIRE(LoaderAdmitWithBackpressure(broker, 200, 200, 0, err_code, err));
    BOOST_CHECK(!LoaderAdmitWithBackpressure(broker, 200, 200, 0, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "BUDGET_EXCEEDED");
    const UniValue st = broker.StatusJson();
    BOOST_CHECK_EQUAL(st["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(std::stoull(st["pinned_used"].get_str()) <= 256);
    BOOST_CHECK(std::stoull(st["host_used"].get_str()) <= 1024);
}

BOOST_AUTO_TEST_CASE(jit_load_04_mutation_fallback)
{
    using namespace modelnet;
    std::vector<unsigned char> dest;
    const std::vector<unsigned char> mixed{0x11, 0x22};
    const std::vector<unsigned char> clean{0xaa, 0xbb, 0xcc};
    BOOST_CHECK(ApplyFailedStrategy(dest, mixed, /*mutated=*/true) == LoadStrategyResult::FAILED_MUTATED);
    BOOST_CHECK(StreamingEqualsFullFile(dest, mixed));
    ResetLoadDestination(dest);
    BOOST_CHECK(dest.empty());
    BOOST_CHECK(ApplyReadyStrategy(dest, clean) == LoadStrategyResult::READY);
    BOOST_CHECK(StreamingEqualsFullFile(dest, clean));
    BOOST_CHECK(!StreamingEqualsFullFile(dest, mixed));
}

BOOST_AUTO_TEST_CASE(jit_load_05_error_classification)
{
    using namespace modelnet;
    bool source_health_ok = true;
    std::string err_code, err;
    BOOST_CHECK(!ClassifyLoadError(/*target_oom=*/true, /*source_corrupt=*/false, source_health_ok, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "TARGET_OOM");
    BOOST_CHECK(source_health_ok);

    BOOST_CHECK(!ClassifyLoadError(/*target_oom=*/false, /*source_corrupt=*/true, source_health_ok, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "SOURCE_CORRUPT");
    BOOST_CHECK(!source_health_ok);
}

BOOST_AUTO_TEST_CASE(jit_load_06_device_verification_gate)
{
    using namespace modelnet;
    const std::vector<unsigned char> expected{0x01, 0x02, 0x03, 0x04};
    const std::vector<unsigned char> wrong{0x01, 0x02, 0x03, 0xff};
    bool compute_consumed = true;
    std::string err_code, err;
    BOOST_CHECK(!DeviceVerificationGate(wrong, expected, compute_consumed, err_code, err));
    BOOST_CHECK(!compute_consumed);
    BOOST_CHECK_EQUAL(err_code, "DEVICE_VERIFY_FAILED");

    BOOST_REQUIRE(DeviceVerificationGate(expected, expected, compute_consumed, err_code, err));
    BOOST_CHECK(compute_consumed);
}

BOOST_AUTO_TEST_CASE(jit_load_07_whole_file_parity)
{
    using namespace modelnet;
    const std::vector<std::vector<unsigned char>> pieces{{0x70, 0x71, 0x72, 0x73}, {0x74, 0x75, 0x76, 0x77}};
    const std::vector<bool> bitmap{true, true};
    const std::vector<unsigned char> full = Concat(pieces);
    std::vector<unsigned char> streamed;
    std::string err_code, err;
    BOOST_REQUIRE(PortableStreamRead(full, 0, full.size(), bitmap, 4, streamed, err_code, err));
    BOOST_CHECK(StreamingEqualsFullFile(streamed, full));

    const fs::path dir = m_path_root / "jit-load-07";
    Generation16 gen{};
    BOOST_REQUIRE(FuseMountDirectory(fs::PathToString(dir), "parity.bin", pieces, bitmap, gen, err_code, err));
    const std::vector<unsigned char> materialized = FileBytes(dir / "parity.bin");
    BOOST_CHECK(StreamingEqualsFullFile(streamed, materialized));
    BOOST_CHECK(Sha384(streamed) == Sha384(materialized));
    BOOST_CHECK_EQUAL(GlobalCapabilityBroker().StatusJson()["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
