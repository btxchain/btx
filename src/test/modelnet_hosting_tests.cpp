// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// 0.34.7 default hosting / AUTO storage / pin / shard TDD.
// CACHE-01.., START-02/10/11/12 (library), SHARD-01..18 (no 13GiB unless env).

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <chainparams.h>
#include <common/args.h>
#include <crypto/common.h>
#include <modelnet/model_nat.h>
#include <netbase.h>
#include <modelnet/auto_storage.h>
#include <modelnet/catalog.h>
#include <modelnet/generate.h>
#include <modelnet/qualification.h>
#include <modelnet/helper.h>
#include <modelnet/hcp.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/policy.h>
#include <modelnet/store.h>
#include <modelnet/supervisor.h>
#include <modelnet/swarm.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/syserror.h>

#include <boost/test/unit_test.hpp>

#include <cerrno>
#include <cstring>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_hosting_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

std::vector<unsigned char> TinyExl3()
{
    const std::string json =
        "{\"model.layers.0.mlp.trellis\":{\"dtype\":\"U16\",\"shape\":[1],\"data_offsets\":[0,2]},"
        "\"model.layers.0.mlp.suh\":{\"dtype\":\"F16\",\"shape\":[1],\"data_offsets\":[2,4]},"
        "\"model.layers.0.mlp.svh\":{\"dtype\":\"F16\",\"shape\":[1],\"data_offsets\":[4,6]}}";
    std::vector<unsigned char> st(8 + json.size() + 6, 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

fs::path WriteExl3Checkout(const fs::path& dir, const char* config_json)
{
    fs::create_directories(dir);
    const auto exl3 = TinyExl3();
    {
        std::ofstream out(dir / "model.exl3", std::ios::binary);
        out.write(reinterpret_cast<const char*>(exl3.data()), static_cast<std::streamsize>(exl3.size()));
    }
    if (config_json != nullptr) {
        std::ofstream cfg(dir / "config.json");
        cfg << config_json;
    }
    return dir;
}

modelnet::HostGenerateProfile Exl3CliHost()
{
    modelnet::HostGenerateProfile host;
    host.exl3_cli = true;
    host.exl3_cli_path = "/bin/true";
    return host;
}

fs::path WriteTinyModel(const fs::path& dir, unsigned char tag)
{
    fs::create_directories(dir);
    const auto st = TinySafeTensors(tag);
    std::ofstream out(dir / "model.safetensors", std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    return dir;
}

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat, const fs::path& dir, unsigned char tag, bool pin)
{
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(WriteTinyModel(dir, tag)), pin, imported, err), err);
    return imported;
}

std::vector<unsigned char> ReadFileBytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    BOOST_REQUIRE_MESSAGE(in, fs::PathToString(path));
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

/** Directory result, or the safetensors file itself. */
fs::path SafeTensorsFile(const fs::path& path)
{
    std::error_code ec;
    if (fs::is_regular_file(path, ec) && !ec) return path;
    return path / "model.safetensors";
}

} // namespace

BOOST_AUTO_TEST_CASE(cache_01_auto_quota_matrix)
{
    using modelnet::ComputeAutoQuota;
    using modelnet::FsStats;
    using modelnet::GIB;
    modelnet::AutoStorageParams p;
    const struct {
        uint64_t cap;
        uint64_t avail;
        uint64_t min_eff;
        uint64_t max_eff;
    } rows[] = {
        {128 * GIB, 80 * GIB, 10 * GIB, 16 * GIB},
        {256 * GIB, 200 * GIB, 24 * GIB, 28 * GIB},
        {512 * GIB, 400 * GIB, 45 * GIB, 60 * GIB},
        {1024 * GIB, 800 * GIB, 90 * GIB, 120 * GIB},
        {2048 * GIB, 1536 * GIB, 180 * GIB, 230 * GIB},
        {8192 * GIB, 7168 * GIB, 500 * GIB, 512 * GIB},
    };
    for (const auto& row : rows) {
        FsStats fs;
        fs.capacity = row.cap;
        fs.available = row.avail;
        const auto q = ComputeAutoQuota(fs, p);
        BOOST_CHECK_GE(q.effective_bytes, row.min_eff);
        BOOST_CHECK_LE(q.effective_bytes, row.max_eff);
        BOOST_CHECK_LE(q.effective_bytes, q.safe_available_bytes);
        BOOST_CHECK_EQUAL(q.reserve_bytes, row.cap / 10);
        BOOST_CHECK_LE(q.effective_bytes, row.cap / 10);
    }
}

BOOST_AUTO_TEST_CASE(cache_01_small_disk_is_not_raised_to_32gib)
{
    using modelnet::ComputeAutoQuota;
    using modelnet::FsStats;
    using modelnet::GIB;
    modelnet::AutoStorageParams p;
    FsStats small;
    small.capacity = 16 * GIB;
    small.available = 14 * GIB;
    const auto a = ComputeAutoQuota(small, p);
    BOOST_CHECK_EQUAL(a.target_bytes, small.capacity / 10);
    BOOST_CHECK_EQUAL(a.effective_bytes, small.capacity / 10);
    BOOST_CHECK_LT(a.effective_bytes, 32 * GIB);
    BOOST_CHECK_LT(a.reserve_bytes, 32 * GIB);

    FsStats disk64;
    disk64.capacity = 64 * GIB;
    disk64.available = 60 * GIB;
    const auto b = ComputeAutoQuota(disk64, p);
    BOOST_CHECK_EQUAL(b.effective_bytes, disk64.capacity / 10);
    BOOST_CHECK_LT(b.effective_bytes * 2, disk64.capacity);
    BOOST_CHECK_LT(b.reserve_bytes * 2, disk64.capacity);
}

BOOST_AUTO_TEST_CASE(cache_02_quota_shrinks_under_external_pressure)
{
    modelnet::FsStats plenty{512 * modelnet::GIB, 400 * modelnet::GIB};
    modelnet::FsStats tight{512 * modelnet::GIB, 40 * modelnet::GIB};
    modelnet::AutoStorageParams p;
    const auto a = modelnet::ComputeAutoQuota(plenty, p);
    const auto b = modelnet::ComputeAutoQuota(tight, p);
    BOOST_CHECK_GT(a.effective_bytes, b.effective_bytes);
}

BOOST_AUTO_TEST_CASE(cache_03_quota_grows_when_safe)
{
    modelnet::AutoStorageParams p;
    modelnet::FsStats low{1024 * modelnet::GIB, 120 * modelnet::GIB};
    modelnet::FsStats high{1024 * modelnet::GIB, 800 * modelnet::GIB};
    const auto a = modelnet::ComputeAutoQuota(low, p);
    const auto b = modelnet::ComputeAutoQuota(high, p);
    BOOST_CHECK_LT(a.effective_bytes, b.effective_bytes);
}

BOOST_AUTO_TEST_CASE(parse_model_storage_auto_fixed_disabled)
{
    modelnet::StorageMode mode;
    uint64_t n = 99;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseModelStorage("auto", mode, n, err));
    BOOST_CHECK(mode == modelnet::StorageMode::AUTO);
    BOOST_CHECK_EQUAL(n, 0);
    BOOST_REQUIRE(modelnet::ParseModelStorage("0", mode, n, err));
    BOOST_CHECK(mode == modelnet::StorageMode::DISABLED);
    BOOST_REQUIRE(modelnet::ParseModelStorage("80GiB", mode, n, err));
    BOOST_CHECK(mode == modelnet::StorageMode::FIXED);
    BOOST_CHECK_EQUAL(n, 80 * modelnet::GIB);
}

BOOST_AUTO_TEST_CASE(cache_04_pinned_never_evicted)
{
    const fs::path tmp = m_path_root / "host-pin";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto unpinned = ImportTiny(cat, tmp / "u", 0x10, false);
    const auto pinned = ImportTiny(cat, tmp / "p", 0x11, true);
    (void)unpinned;
    modelnet::PreservationPolicy pol = cat.Policy();
    pol.storage_quota_bytes = cat.UsedBytes() - 1;
    cat.SetPolicy(pol);
    std::string err;
    (void)cat.EnforceQuota(0, err);
    modelnet::CatalogEntry still;
    BOOST_REQUIRE(cat.Find(pinned.artifact_id, still));
    BOOST_CHECK(still.pinned);
}

BOOST_AUTO_TEST_CASE(pin_a_survives_restart)
{
    const fs::path tmp = m_path_root / "pin-restart";
    modelnet::Digest48 id;
    {
        modelnet::ModelCatalog cat{tmp, 1 << 20};
        const auto imported = ImportTiny(cat, tmp / "src", 0x21, true);
        id = imported.model_id;
        BOOST_CHECK(imported.pinned);
        BOOST_CHECK(cat.Store().IsPinned(imported.artifact_id));
    }
    modelnet::ModelCatalog resumed{tmp, 1 << 20};
    modelnet::CatalogEntry found;
    BOOST_REQUIRE(resumed.Find(id, found));
    BOOST_CHECK(found.pinned);
    BOOST_CHECK(resumed.Store().IsPinned(found.artifact_id));
}

BOOST_AUTO_TEST_CASE(store_gc_removes_only_empty_unpinned_artifacts)
{
    const fs::path tmp = m_path_root / "store-gc";
    modelnet::ModelStore store{tmp, 1 << 20};
    modelnet::Digest48 id;
    id.data[0] = 0x42;
    const fs::path empty = tmp / "artifacts" / id.Hex().c_str();
    fs::create_directories(empty);
    std::filesystem::last_write_time(
        empty, std::filesystem::file_time_type::clock::now() - std::chrono::hours(48));

    store.EvictUnpinned();
    BOOST_CHECK(!fs::exists(empty));

    fs::create_directories(empty);
    std::filesystem::last_write_time(
        empty, std::filesystem::file_time_type::clock::now() - std::chrono::hours(48));
    std::string err;
    BOOST_REQUIRE(store.Pin(id, err));
    store.EvictUnpinned();
    BOOST_CHECK(fs::exists(empty));
}

BOOST_AUTO_TEST_CASE(pin_f_unpin_makes_eligible)
{
    const fs::path tmp = m_path_root / "pin-unpin";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pinned = ImportTiny(cat, tmp / "p", 0x31, true);
    const auto common = ImportTiny(cat, tmp / "c", 0x32, false);
    (void)common;
    std::string err;
    BOOST_REQUIRE(cat.PinModel(pinned.model_id, false, err));
    modelnet::CatalogEntry after;
    BOOST_REQUIRE(cat.Find(pinned.artifact_id, after));
    BOOST_CHECK(!after.pinned);
    modelnet::PreservationPolicy p = cat.Policy();
    p.storage_quota_bytes = 1;
    cat.SetPolicy(p);
    (void)cat.EnforceQuota(0, err);
    modelnet::CatalogEntry gone;
    BOOST_CHECK(!cat.Find(pinned.artifact_id, gone));
}

BOOST_AUTO_TEST_CASE(evict_priority_order)
{
    modelnet::EvictItem stale, cipher, failed, giveback, common, seeded, rare, recent, pin;
    stale.incomplete = true;
    cipher.expired_ciphertext = true;
    failed.failed_unqualified = true;
    giveback.giveback_complete = true;
    seeded.seeded = true;
    rare.observed_sources = 1;
    recent.recently_protected = true;
    pin.pinned = true;
    BOOST_CHECK_LT(modelnet::EvictPriority(stale), modelnet::EvictPriority(cipher));
    BOOST_CHECK_LT(modelnet::EvictPriority(cipher), modelnet::EvictPriority(failed));
    BOOST_CHECK_LT(modelnet::EvictPriority(giveback), modelnet::EvictPriority(common));
    BOOST_CHECK_LT(modelnet::EvictPriority(common), modelnet::EvictPriority(seeded));
    BOOST_CHECK_LT(modelnet::EvictPriority(seeded), modelnet::EvictPriority(rare));
    BOOST_CHECK_LT(modelnet::EvictPriority(rare), modelnet::EvictPriority(recent));
    BOOST_CHECK_LT(modelnet::EvictPriority(recent), modelnet::EvictPriority(pin));
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(pin), 1000);
}

BOOST_AUTO_TEST_CASE(start_02_nomodelnet_argv)
{
    modelnet::HelperLaunchConfig cfg;
    cfg.helper_exe = fs::PathFromString("/bin/false");
    const auto argv = modelnet::BuildHelperArgv(cfg);
    BOOST_CHECK(!modelnet::ArgvContainsWalletMaterial(argv));
    for (const auto& a : argv) {
        BOOST_CHECK(a.find("wallet") == std::string::npos);
        BOOST_CHECK(a.find("cookie") == std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(start_10_sanitize_env_strips_wallet)
{
    char cookie[] = "BITCOIN_COOKIE=/tmp/cookie";
    char wallet[] = "WALLET_PASSPHRASE=secret";
    char path[] = "PATH=/usr/bin";
    char* envp[] = {cookie, wallet, path, nullptr};
    const auto out = modelnet::SanitizeHelperEnv(envp);
    BOOST_REQUIRE_EQUAL(out.size(), 1);
    BOOST_CHECK_EQUAL(out[0], "PATH=/usr/bin");
    BOOST_CHECK(modelnet::EnvLooksLikeWalletSecret("BITCOIN_COOKIE"));
    BOOST_CHECK(modelnet::EnvLooksLikeWalletSecret("RPCUSER"));
}

BOOST_AUTO_TEST_CASE(start_07_backoff_bounded)
{
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(0, 0), 1000);
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(1, 0), 2000);
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(2, 0), 5000);
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(3, 0), 10000);
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(4, 0), 30000);
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(5, 0), 60000);
    BOOST_CHECK_EQUAL(modelnet::NextBackoffMs(99, 0), 60000);
    BOOST_CHECK_LE(modelnet::NextBackoffMs(0, 20), 1200);
}

BOOST_AUTO_TEST_CASE(shard_01_02_03_deterministic_pieces)
{
    std::vector<unsigned char> file(modelnet::PIECE_SIZE + 17, 0x5a);
    const auto rows = modelnet::BuildChunkTree(file);
    BOOST_REQUIRE(!rows.empty());
    const uint64_t n = (file.size() + modelnet::PIECE_SIZE - 1) / modelnet::PIECE_SIZE;
    BOOST_CHECK_EQUAL(n, 2);
    const auto leaf0 = modelnet::ChunkLeaf(0, Span<const unsigned char>{file.data(), modelnet::PIECE_SIZE});
    const auto leaf1 = modelnet::ChunkLeaf(1, Span<const unsigned char>{file.data() + modelnet::PIECE_SIZE, 17});
    BOOST_CHECK(rows.front()[0] == leaf0);
    BOOST_CHECK(rows.front()[1] == leaf1);
    const auto again = modelnet::BuildChunkTree(file);
    BOOST_CHECK(rows.back()[0] == again.back()[0]);
    file[0] ^= 0x01;
    const auto changed = modelnet::BuildChunkTree(file);
    BOOST_CHECK(rows.back()[0] != changed.back()[0]);
}

BOOST_AUTO_TEST_CASE(shard_05_06_wrong_index_rejected)
{
    const fs::path tmp = m_path_root / "shard-index";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x40, true);
    std::string err;
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_CHECK(!cat.PutFetchedPiece(imported.artifact_id, 0, 1, bytes, proof, file_size, imported.core.files[0].pieces_root, err));
    BOOST_CHECK(!cat.PutFetchedPiece(imported.artifact_id, 1, 0, bytes, proof, file_size, imported.core.files[0].pieces_root, err));
}

BOOST_AUTO_TEST_CASE(shard_08_three_disjoint_ranges)
{
    std::vector<modelnet::PieceNeed> missing;
    for (uint32_t i = 0; i < 100; ++i) {
        modelnet::PieceNeed p;
        p.file_index = 0;
        p.piece_index = i;
        missing.push_back(p);
    }
    std::vector<modelnet::SourceOffer> sources;
    auto add = [&](uint32_t first, uint32_t count, const char* peer) {
        modelnet::SourceOffer s;
        s.peer = peer;
        s.available = true;
        s.file_index = 0;
        s.first_piece = first;
        s.piece_count = count;
        sources.push_back(s);
    };
    add(0, 40, "A");
    add(40, 40, "B");
    add(80, 20, "C");
    const auto plan = modelnet::PlanRetrieval(missing, sources, modelnet::RetrievalMode::FREE_ONLY, 0, false);
    BOOST_CHECK_EQUAL(plan.free_pieces.size(), 100);
    BOOST_CHECK(plan.paid_pieces.empty());
}

BOOST_AUTO_TEST_CASE(shard_09_overlap_deduplicates)
{
    std::vector<uint32_t> idx = {0, 1, 2, 3, 4};
    std::vector<modelnet::PieceRange> ranges;
    std::string err;
    BOOST_REQUIRE(modelnet::CompactPieceRanges(idx, ranges, err));
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_CHECK_EQUAL(ranges[0].first, 0);
    BOOST_CHECK_EQUAL(ranges[0].count, 5);
}

BOOST_AUTO_TEST_CASE(shard_14_15_17_partial_ranges)
{
    std::vector<uint32_t> have;
    for (uint32_t i = 0; i < 40; ++i) have.push_back(i);
    std::vector<modelnet::PieceRange> ranges;
    std::string err;
    BOOST_REQUIRE(modelnet::CompactPieceRanges(have, ranges, err));
    BOOST_CHECK_EQUAL(ranges.size(), 1);
    BOOST_CHECK(!modelnet::PieceComplete(100 * modelnet::PIECE_SIZE, 40));
    UniValue huge(UniValue::VARR);
    for (int i = 0; i < 2000; ++i) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("first", i * 2);
        o.pushKV("count", 1);
        huge.push_back(o);
    }
    std::vector<modelnet::PieceRange> parsed;
    BOOST_CHECK(!modelnet::ParsePieceRangesJson(huge, parsed, err));
}

BOOST_AUTO_TEST_CASE(shard_18_empty_file)
{
    const auto rows = modelnet::BuildChunkTree(Span<const unsigned char>{});
    BOOST_REQUIRE(!rows.empty());
    BOOST_CHECK(rows.back()[0] == modelnet::EmptyFileRoot());
}

BOOST_AUTO_TEST_CASE(list_availability_not_complete_when_partial)
{
    const fs::path tmp = m_path_root / "avail";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x50, true);
    UniValue listed;
    BOOST_REQUIRE(cat.List(listed));
    BOOST_REQUIRE(listed.exists("models"));
    BOOST_CHECK(listed["models"][0]["complete"].get_bool());
    const auto files = cat.FileAvailabilityJson(imported.artifact_id, imported.core);
    BOOST_REQUIRE(!files.getValues().empty());
    BOOST_CHECK(files[0]["complete"].get_bool());
}

BOOST_AUTO_TEST_CASE(grow_auto_cap_message)
{
    modelnet::FsStats fs;
    fs.capacity = 1024 * modelnet::GIB;
    fs.available = 800 * modelnet::GIB;
    modelnet::AutoStorageParams p;
    const auto g = modelnet::GrowAutoQuotaForRequest(fs, p, 32 * modelnet::GIB, 0, 600 * modelnet::GIB);
    BOOST_CHECK(!g.ok);
    BOOST_CHECK(g.error.find("Model requires") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(start_12_with_modelnet_on)
{
#ifdef ENABLE_MODELNET
    BOOST_CHECK(modelnet::IsHcpHelperMethod("hcphealth"));
    BOOST_CHECK(modelnet::IsHcpHelperMethod("gethcpreadiness"));
    BOOST_CHECK(modelnet::IsHcpHelperMethod("sethcpreporting"));
    BOOST_CHECK(!modelnet::IsHcpHelperMethod("dumpprivkey"));
    BOOST_CHECK(!modelnet::IsHcpHelperMethod("sendtoaddress"));
#else
    BOOST_FAIL("this binary was not built WITH_MODELNET");
#endif
}

BOOST_AUTO_TEST_CASE(start_03_find_packaged_missing_override)
{
    BOOST_CHECK(modelnet::FindPackagedModeld(fs::PathFromString("/no/such/btx-modeld")).empty());
}

BOOST_AUTO_TEST_CASE(start_03_explicit_missing_does_not_spawn)
{
    modelnet::HelperLaunchConfig cfg;
    cfg.helper_explicitly_missing = true;
    cfg.helper_exe.clear();
    modelnet::HelperSupervisor sup(std::move(cfg));
    std::string err;
    BOOST_REQUIRE(sup.Start(err));
    BOOST_CHECK(!err.empty());
    BOOST_CHECK(sup.Snapshot().state == modelnet::HelperState::FAILED_RETRYING);
    BOOST_CHECK(sup.Snapshot().pid <= 0);
    BOOST_CHECK(sup.Snapshot().managed_by_btxd);
}

BOOST_AUTO_TEST_CASE(start_10_argv_has_bind_not_wallet)
{
    modelnet::HelperLaunchConfig cfg;
    cfg.helper_exe = fs::PathFromString("/usr/bin/btx-modeld");
    cfg.bind = "127.0.0.1:29447";
    cfg.modeldir = fs::PathFromString("/tmp/modelnet-test");
    const auto argv = modelnet::BuildHelperArgv(cfg);
    BOOST_CHECK(!modelnet::ArgvContainsWalletMaterial(argv));
    bool has_bind = false;
    for (const auto& a : argv) {
        if (a.rfind("-modelbind=", 0) == 0) has_bind = true;
        BOOST_CHECK(a.find("rpcpassword") == std::string::npos);
    }
    BOOST_CHECK(has_bind);
}

BOOST_AUTO_TEST_CASE(start_11_argv_forwards_peers_and_follow_default)
{
    modelnet::HelperLaunchConfig cfg;
    cfg.helper_exe = fs::PathFromString("/usr/bin/btx-modeld");
    cfg.peers.push_back("127.0.0.1:29448");
    cfg.follow_peers = false;
    const auto argv = modelnet::BuildHelperArgv(cfg);
    bool has_peer = false;
    bool has_follow_off = false;
    for (const auto& a : argv) {
        if (a == "-modelpeer=127.0.0.1:29448") has_peer = true;
        if (a == "-modelfollowpeers=0") has_follow_off = true;
    }
    BOOST_CHECK(has_peer);
    BOOST_CHECK(has_follow_off);
}

BOOST_AUTO_TEST_CASE(start_12_argv_omits_follow_off_when_default_on)
{
    modelnet::HelperLaunchConfig cfg;
    cfg.helper_exe = fs::PathFromString("/usr/bin/btx-modeld");
    cfg.follow_peers = true;
    const auto argv = modelnet::BuildHelperArgv(cfg);
    for (const auto& a : argv) {
        BOOST_CHECK(a != "-modelfollowpeers=0");
    }
}

BOOST_AUTO_TEST_CASE(cache_09_restart_preserves_retention)
{
    const fs::path tmp = m_path_root / "cache09";
    modelnet::Digest48 id;
    int64_t imported = 0;
    {
        modelnet::ModelCatalog cat{tmp, 8 << 20};
        const auto e = ImportTiny(cat, tmp / "src", 0x61, false);
        id = e.model_id;
        imported = e.imported_at;
        BOOST_CHECK_GT(imported, 0);
    }
    modelnet::ModelCatalog resumed{tmp, 8 << 20};
    modelnet::CatalogEntry found;
    BOOST_REQUIRE(resumed.Find(id, found));
    BOOST_CHECK_EQUAL(found.imported_at, imported);
    BOOST_CHECK(!found.pinned);
}

BOOST_AUTO_TEST_CASE(cache_10_active_transfer_not_gc)
{
    const fs::path tmp = m_path_root / "cache10";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto e = ImportTiny(cat, tmp / "src", 0x62, false);
    cat.BeginTransfer(e.artifact_id);
    modelnet::PreservationPolicy p = cat.Policy();
    p.storage_quota_bytes = 1;
    cat.SetPolicy(p);
    std::string err;
    (void)cat.EnforceQuota(0, err);
    modelnet::CatalogEntry still;
    BOOST_REQUIRE(cat.Find(e.artifact_id, still));
    cat.EndTransfer(e.artifact_id);
}

BOOST_AUTO_TEST_CASE(pin_g_h_pinned_pressure)
{
    const fs::path tmp = m_path_root / "pin-gh";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pinned = ImportTiny(cat, tmp / "p", 0x63, true);
    modelnet::PreservationPolicy p = cat.Policy();
    p.storage_quota_bytes = 1;
    cat.SetPolicy(p);
    std::string err;
    BOOST_CHECK(!cat.EnforceQuota(1, err));
    BOOST_CHECK_EQUAL(err, "PINNED_STORAGE_PRESSURE");
    modelnet::CatalogEntry still;
    BOOST_REQUIRE(cat.Find(pinned.artifact_id, still));
    BOOST_CHECK(still.pinned);
}

BOOST_AUTO_TEST_CASE(cache_06_common_before_rare)
{
    modelnet::EvictItem common, rare;
    common.observed_sources = 0;
    rare.observed_sources = 1;
    rare.seeded = true;
    BOOST_CHECK_LT(modelnet::EvictPriority(common), modelnet::EvictPriority(rare));
}

BOOST_AUTO_TEST_CASE(demand_seed_skips_incomplete_replica)
{
    const fs::path tmp = m_path_root / "demand-seed-incomplete";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x71, false);
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.MarkIncomplete(imported.model_id, true, err), err);

    modelnet::CatalogEntry before;
    BOOST_REQUIRE_MESSAGE(cat.Find(imported.model_id, before), "Find before demand-seed");
    BOOST_CHECK(before.incomplete);
    BOOST_CHECK(!before.bytes_verified);
    BOOST_CHECK(before.admission == modelnet::AdmissionLevel::FETCHING);
    BOOST_CHECK(!before.seeded);

    BOOST_REQUIRE_MESSAGE(cat.ApplyDemandSeed(imported.model_id, err), err);
    modelnet::CatalogEntry after;
    BOOST_REQUIRE_MESSAGE(cat.Find(imported.model_id, after), "Find still succeeds");
    BOOST_CHECK(after.incomplete);
    BOOST_CHECK(!after.bytes_verified);
    BOOST_CHECK(!after.seeded);
    BOOST_CHECK(after.admission == modelnet::AdmissionLevel::FETCHING);
    BOOST_REQUIRE_MESSAGE(after.admission != modelnet::AdmissionLevel::SEEDING,
                          "incomplete replica must not be newly claimed SEEDING");
    BOOST_CHECK_EQUAL(after.useful_bytes_served, 0);
    BOOST_CHECK_EQUAL(after.useful_bytes_received, 0);

    UniValue listed;
    BOOST_REQUIRE(cat.List(listed));
    BOOST_CHECK(!listed.exists("automatic_spend"));
    BOOST_CHECK(!listed.exists("automatic_spend_atoms"));
    BOOST_REQUIRE(listed["models"].isArray());
    BOOST_REQUIRE_EQUAL(listed["models"].size(), 1);
    const UniValue& row = listed["models"][0];
    BOOST_CHECK(!row.exists("automatic_spend"));
    BOOST_CHECK(!row.exists("automatic_spend_atoms"));
    BOOST_CHECK(row["incomplete"].get_bool());
    BOOST_CHECK(!row["complete"].get_bool());
    BOOST_CHECK(!row["bytes_verified"].get_bool());
    BOOST_CHECK_EQUAL(row["admission"].get_str(), "FETCHING");

    std::ifstream catalog_in(tmp / "catalog.json");
    std::string catalog_body;
    std::string line;
    while (std::getline(catalog_in, line)) catalog_body += line;
    BOOST_REQUIRE(catalog_in.eof());
    BOOST_CHECK(catalog_body.find("automatic_spend") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(materialize_checkout_rebuilds_original_bytes)
{
    const fs::path tmp = m_path_root / "materialize-checkout";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    constexpr unsigned char tag = 0x81;
    const auto imported = ImportTiny(cat, tmp / "src", tag, true);
    const fs::path dest = tmp / "rebuilt";
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.MaterializeCheckout(imported.model_id, dest, err), err);
    BOOST_CHECK(fs::PathToString(dest) != imported.source_path);
    const auto got = ReadFileBytes(dest / "model.safetensors");
    const auto expect = TinySafeTensors(tag);
    BOOST_CHECK_EQUAL(got.size(), expect.size());
    BOOST_CHECK(got == expect);
}

BOOST_AUTO_TEST_CASE(exportmodelpath_returns_usable_runtime_root_from_pieces)
{
    const fs::path tmp = m_path_root / "export-runtime-root";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    constexpr unsigned char tag = 0x82;
    const auto imported = ImportTiny(cat, tmp / "src", tag, true);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "exportmodelpath");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);

    BOOST_REQUIRE(result.exists("path"));
    BOOST_REQUIRE(result["path"].isStr());
    const fs::path checkout = fs::PathFromString(result["path"].get_str());
    BOOST_CHECK(fs::is_directory(checkout));
    BOOST_CHECK(fs::PathToString(checkout) != imported.source_path);
    const fs::path expect_root = tmp / "checkout" / fs::PathFromString(imported.artifact_id.Hex());
    std::error_code ec;
    const bool checkout_matches = fs::equivalent(checkout, expect_root, ec);
    BOOST_CHECK(!ec);
    BOOST_CHECK(checkout_matches);
    const auto got = ReadFileBytes(checkout / "model.safetensors");
    const auto expect = TinySafeTensors(tag);
    BOOST_CHECK_EQUAL(got.size(), expect.size());
    BOOST_CHECK(got == expect);

    BOOST_REQUIRE(result.exists("usable_runtime_root"));
    BOOST_REQUIRE(result["usable_runtime_root"].isStr());
    const fs::path runtime = fs::PathFromString(result["usable_runtime_root"].get_str());
    BOOST_CHECK(fs::is_directory(runtime));
    ec.clear();
    const bool runtime_matches = fs::equivalent(runtime, checkout, ec);
    BOOST_CHECK(!ec);
    BOOST_CHECK(runtime_matches);

    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["runtime_started"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["runtime_exec"].get_bool(), false);
    if (result.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
    }
}

BOOST_AUTO_TEST_CASE(loadmodel_incomplete_replica_is_rejected)
{
    const fs::path tmp = m_path_root / "load-incomplete";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x83, true);
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.MarkIncomplete(imported.model_id, true, err), err);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "loadmodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    err.clear();
    const bool ok = modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    const bool failed = !ok || !err.empty() || (result.isObject() && result.exists("error"));
    BOOST_CHECK(failed);
    if (result.isObject() && result.exists("device_loaded")) {
        BOOST_CHECK_EQUAL(result["device_loaded"].get_bool(), false);
    }
}

BOOST_AUTO_TEST_CASE(loadmodel_lists_local_files_without_starting_inference)
{
    const fs::path tmp = m_path_root / "load-local";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    constexpr unsigned char tag = 0x84;
    const auto imported = ImportTiny(cat, tmp / "src", tag, true);
    ::unsetenv("BTX_MODEL_CUDA_LOADER");

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "loadmodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);

    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["runtime_started"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["device_loaded"].get_bool(), false);
    BOOST_REQUIRE(result.exists("path"));
    BOOST_REQUIRE(result["path"].isStr());
    const fs::path weights = SafeTensorsFile(fs::PathFromString(result["path"].get_str()));
    BOOST_CHECK(weights.filename() == "model.safetensors");
    const auto got = ReadFileBytes(weights);
    const auto expect = TinySafeTensors(tag);
    BOOST_CHECK_EQUAL(got.size(), expect.size());
    BOOST_CHECK(got == expect);
}

BOOST_AUTO_TEST_CASE(getmodel_opens_btx_share_file)
{
    const fs::path tmp = m_path_root / "getmodel-btx-file";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x85, true);
    const fs::path link = tmp / "granite.btx";

    UniValue wrpc(UniValue::VOBJ);
    wrpc.pushKV("method", "exportmodellink");
    UniValue wparams(UniValue::VARR);
    wparams.push_back(imported.model_id.Hex());
    wparams.push_back(fs::PathToString(link));
    wrpc.pushKV("params", wparams);
    UniValue written;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, wrpc, written, code, err), err);
    BOOST_CHECK(written["written"].get_bool());
    BOOST_CHECK(fs::exists(link));

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodel");
    UniValue params(UniValue::VARR);
    params.push_back(fs::PathToString(link));
    params.push_back("FREE_ONLY");
    rpc.pushKV("params", params);
    UniValue result;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["status"].get_str(), "local");
    BOOST_CHECK(result["uri"].get_str().rfind("btx://", 0) == 0);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(hostmodel_share_card_retrieves_free_only)
{
    const fs::path tmp = m_path_root / "host-share-retrieve";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x86, true);
    const fs::path link = tmp / "card.btx";
    UniValue wrpc(UniValue::VOBJ);
    wrpc.pushKV("method", "exportmodellink");
    UniValue wparams(UniValue::VARR);
    wparams.push_back(imported.model_id.Hex());
    wparams.push_back(fs::PathToString(link));
    wrpc.pushKV("params", wparams);
    UniValue written;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, wrpc, written, code, err), err);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "hostmodel");
    UniValue params(UniValue::VARR);
    params.push_back(fs::PathToString(link));
    rpc.pushKV("params", params);
    UniValue card;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, card, code, err), err);
    BOOST_CHECK(!card["imported"].get_bool());
    BOOST_CHECK_EQUAL(card["reason"].get_str(), "share_card");
    BOOST_REQUIRE(card.exists("retrieve"));
    BOOST_CHECK_EQUAL(card["retrieve"]["status"].get_str(), "local");
}

BOOST_AUTO_TEST_CASE(materialize_checkout_hardlinks_matching_source)
{
    const fs::path tmp = m_path_root / "checkout-hardlink";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x87, true);
    const fs::path dest = tmp / "checkout";
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.MaterializeCheckout(imported.model_id, dest, err), err);
    const fs::path srcf = fs::PathFromString(imported.source_path) / "model.safetensors";
    const fs::path dstf = dest / "model.safetensors";
    BOOST_REQUIRE(fs::exists(srcf));
    BOOST_REQUIRE(fs::exists(dstf));
    struct stat ss {}, ds {};
    BOOST_REQUIRE_EQUAL(::stat(fs::PathToString(srcf).c_str(), &ss), 0);
    BOOST_REQUIRE_EQUAL(::stat(fs::PathToString(dstf).c_str(), &ds), 0);
    BOOST_CHECK_EQUAL(ss.st_dev, ds.st_dev);
    BOOST_CHECK_EQUAL(ss.st_ino, ds.st_ino);
}

BOOST_AUTO_TEST_CASE(loadmodel_hold_fake_cuda_loader_then_unload)
{
    const fs::path tmp = m_path_root / "load-hold";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x88, true);
    const fs::path loader = tmp / "fake-cuda-loader";
    {
        std::ofstream out(loader);
        out << "#!/usr/bin/env python3\n"
               "import signal, sys, time\n"
               "hold = \"--hold\" in sys.argv\n"
               "print('{\"ok\":true,\"device_name\":\"fake\",\"tensors\":1,\"bytes_on_device\":8,\"resident\":true,\"smoke_passed\":true,\"smoke\":\"kernel\"}', flush=True)\n"
               "if hold:\n"
               "    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\n"
               "    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))\n"
               "    while True:\n"
               "        time.sleep(3600)\n"
               "sys.exit(0)\n";
    }
    ::chmod(fs::PathToString(loader).c_str(), 0755);
    BOOST_REQUIRE_EQUAL(::setenv("BTX_MODEL_CUDA_LOADER", fs::PathToString(loader).c_str(), 1), 0);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "loadmodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["device_loaded"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["weights_resident"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["runtime_started"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["smoke_passed"].get_bool(), true);
    BOOST_CHECK(result.exists("loader_pid"));
    BOOST_CHECK_GT(result["loader_pid"].getInt<int64_t>(), 0);

    UniValue urpc(UniValue::VOBJ);
    urpc.pushKV("method", "unloadmodel");
    urpc.pushKV("params", params);
    UniValue unloaded;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, urpc, unloaded, code, err), err);
    BOOST_CHECK_EQUAL(unloaded["unloaded"].get_bool(), true);
    BOOST_CHECK_EQUAL(unloaded["device_loaded"].get_bool(), false);
    ::unsetenv("BTX_MODEL_CUDA_LOADER");
}

BOOST_AUTO_TEST_CASE(host_generate_profile_cuda_smoke_is_not_generate)
{
    ::unsetenv("BTX_MODEL_GENERATE");
    ::unsetenv("BTX_LLAMA_CLI");
    ::unsetenv("BTX_EXL3_CLI");
    ::unsetenv("BTX_MODEL_CUDA_LOADER");
    const fs::path tmp = m_path_root / "host-profile";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodelhostprofile");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["can_generate"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["cuda_smoke_is_not_generate"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["remote_inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["trust_remote_code"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(inspect_checkout_rejects_pickle_and_unknown_arch)
{
    const fs::path pickle_dir = m_path_root / "gen-pickle";
    fs::create_directories(pickle_dir);
    {
        std::ofstream st(pickle_dir / "model.safetensors", std::ios::binary);
        const auto bytes = TinySafeTensors(0x91);
        st.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        std::ofstream pk(pickle_dir / "evil.pkl", std::ios::binary);
        pk << "pickle";
    }
    const auto pickle_view = modelnet::InspectCheckoutForGenerate(pickle_dir);
    BOOST_CHECK(pickle_view.pickle_or_executable);
    BOOST_CHECK(pickle_view.format == modelnet::GenerateFormat::Unsafe);
    std::string reason;
    modelnet::HostGenerateProfile host;
    host.generate_adapter = true;
    host.generate_adapter_path = "/bin/true";
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(pickle_view, host, reason));
    BOOST_CHECK_EQUAL(reason, "unsafe_format");

    const fs::path unknown = m_path_root / "gen-unknown";
    fs::create_directories(unknown);
    {
        std::ofstream st(unknown / "model.safetensors", std::ios::binary);
        const auto bytes = TinySafeTensors(0x92);
        st.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        std::ofstream cfg(unknown / "config.json");
        cfg << "{\"architectures\":[\"TotallyFakeForCausalLM\"]}\n";
    }
    const auto unk = modelnet::InspectCheckoutForGenerate(unknown);
    BOOST_CHECK(unk.format == modelnet::GenerateFormat::SafeTensors);
    BOOST_CHECK_EQUAL(unk.architecture, "TotallyFakeForCausalLM");
    BOOST_CHECK(!modelnet::SafeTensorsArchitectureIsHostCompatible(unk.architecture));
    reason.clear();
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(unk, host, reason));
    BOOST_CHECK_EQUAL(reason, "unknown_architecture");

    BOOST_CHECK(modelnet::SafeTensorsArchitectureIsHostCompatible("LlamaForCausalLM"));
    BOOST_CHECK(modelnet::SafeTensorsArchitectureIsHostCompatible("GraniteMoeHybridForCausalLM"));
    BOOST_CHECK(!modelnet::SafeTensorsArchitectureIsHostCompatible("custom_auto_map"));
}

BOOST_AUTO_TEST_CASE(generatemodel_compatible_fake_adapter)
{
    const fs::path tmp = m_path_root / "gen-ok";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    {
        const auto st = TinySafeTensors(0x93);
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream cfg(src / "config.json");
        cfg << "{\"architectures\":[\"LlamaForCausalLM\"],\"model_type\":\"llama\"}\n";
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, imported, err), err);

    const fs::path adapter = tmp / "fake-generate";
    {
        std::ofstream out(adapter);
        out << "#!/usr/bin/env python3\n"
               "import json, sys\n"
               "req = json.loads(sys.stdin.readline() or '{}')\n"
               "print(json.dumps({\"ok\":True,\"generated\":True,\"text\":\"echo:\"+str(req.get(\"prompt\",\"\")),\"backend\":\"fake\"}), flush=True)\n";
    }
    ::chmod(fs::PathToString(adapter).c_str(), 0755);
    BOOST_REQUIRE_EQUAL(::setenv("BTX_MODEL_GENERATE", fs::PathToString(adapter).c_str(), 1), 0);
    ::unsetenv("BTX_LLAMA_CLI");

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "generatemodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("prompt", "hello-btx");
    opts.pushKV("max_new_tokens", 8);
    params.push_back(opts);
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    err.clear();
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["generated"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["local_generate"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["compatible"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["remote_inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["network_server"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["text"].get_str(), "echo:hello-btx");
    BOOST_CHECK_EQUAL(result["backend"].get_str(), "fake");
    BOOST_CHECK_EQUAL(result["architecture"].get_str(), "LlamaForCausalLM");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(result["execution_profile"].getInt<int>(), 0);
    ::unsetenv("BTX_MODEL_GENERATE");
}

#if defined(__linux__)
namespace {

bool WriteProcSelf(const char* name, const std::string& value)
{
    const int fd = ::open((std::string{"/proc/self/"} + name).c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = ::write(fd, value.data(), value.size()) == static_cast<ssize_t>(value.size());
    ::close(fd);
    return ok;
}

/** Make the next child of this single-threaded process pid 1 of a new PID
 *  namespace. A privileged process can create one directly; anyone else
 *  needs a user namespace, which maps only our own uid and gid. */
bool EnterNewPidNamespace(std::string& why)
{
    if (::unshare(CLONE_NEWPID) == 0) return true;
    const uid_t uid = ::geteuid();
    const gid_t gid = ::getegid();
    if (::unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0) {
        why = "unshare: " + SysErrorString(errno);
        return false;
    }
    if (!WriteProcSelf("setgroups", "deny") ||
        !WriteProcSelf("uid_map", strprintf("%u %u 1\n", uid, uid)) ||
        !WriteProcSelf("gid_map", strprintf("%u %u 1\n", gid, gid))) {
        why = "user namespace id map: " + SysErrorString(errno);
        return false;
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(generatemodel_adapter_runs_when_helper_is_pid1)
{
    // A helper that is pid 1 of its PID namespace (a container entrypoint
    // without an init) is a live parent, so its generate adapter must run.
    // Run generatemodel as pid 1 of a new PID namespace; skip where the
    // kernel or a sandbox does not allow one.
    const fs::path tmp = m_path_root / "gen-pid1";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    {
        const auto st = TinySafeTensors(0x96);
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream cfg(src / "config.json");
        cfg << "{\"architectures\":[\"LlamaForCausalLM\"],\"model_type\":\"llama\"}\n";
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, imported, err), err);

    // The adapter reports its parent's pid, which is 1 when the helper is pid 1.
    const fs::path adapter = tmp / "fake-generate";
    {
        std::ofstream out(adapter);
        out << "#!/usr/bin/env python3\n"
               "import json, os, sys\n"
               "req = json.loads(sys.stdin.readline() or '{}')\n"
               "text = 'ppid=%d:%s' % (os.getppid(), req.get('prompt', ''))\n"
               "print(json.dumps({\"ok\":True,\"generated\":True,\"text\":text,\"backend\":\"fake\"}), flush=True)\n";
    }
    ::chmod(fs::PathToString(adapter).c_str(), 0755);
    BOOST_REQUIRE_EQUAL(::setenv("BTX_MODEL_GENERATE", fs::PathToString(adapter).c_str(), 1), 0);
    ::unsetenv("BTX_LLAMA_CLI");

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "generatemodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    params.push_back("hello-pid1");
    rpc.pushKV("params", params);

    // The forked side writes one report: the generated text, the error, or
    // "skip: <reason>". Boost assertions stay in this process.
    int report[2];
    BOOST_REQUIRE_EQUAL(::pipe2(report, O_CLOEXEC), 0);
    const pid_t runner = ::fork();
    BOOST_REQUIRE(runner >= 0);
    if (runner == 0) {
        ::close(report[0]);
        const auto send_report = [&](const std::string& s) {
            [[maybe_unused]] const ssize_t n = ::write(report[1], s.data(), s.size());
        };
        std::string why;
        if (!EnterNewPidNamespace(why)) {
            send_report("skip: " + why);
            ::_exit(0);
        }
        const pid_t init = ::fork();
        if (init < 0) {
            send_report("skip: fork in the new PID namespace: " + SysErrorString(errno));
            ::_exit(0);
        }
        if (init == 0) {
            std::string out;
            try {
                if (::getpid() != 1) {
                    out = "skip: not pid 1 in the new PID namespace";
                } else {
                    UniValue result;
                    std::string code;
                    std::string gen_err;
                    if (modelnet::DispatchHelperRpc(cat, rpc, result, code, gen_err)) {
                        out = result["text"].get_str();
                    } else {
                        out = code + ": " + gen_err;
                    }
                }
            } catch (const std::exception& e) {
                out = std::string{"exception: "} + e.what();
            }
            send_report(out);
            ::_exit(0);
        }
        int status = 0;
        while (::waitpid(init, &status, 0) < 0 && errno == EINTR) {}
        ::_exit(0);
    }
    ::close(report[1]);
    std::string out;
    char buf[256];
    for (;;) {
        const ssize_t n = ::read(report[0], buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    ::close(report[0]);
    int status = 0;
    while (::waitpid(runner, &status, 0) < 0 && errno == EINTR) {}
    ::unsetenv("BTX_MODEL_GENERATE");
    if (out.rfind("skip: ", 0) == 0) {
        BOOST_TEST_MESSAGE("Skipping pid-1 generate adapter test: " + out.substr(6));
        return;
    }
    BOOST_CHECK_EQUAL(out, "ppid=1:hello-pid1");
}
#endif // __linux__

BOOST_AUTO_TEST_CASE(generatemodel_unknown_architecture_fail_closed)
{
    const fs::path tmp = m_path_root / "gen-bad-arch";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    {
        const auto st = TinySafeTensors(0x94);
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream cfg(src / "config.json");
        cfg << "{\"architectures\":[\"TotallyFakeForCausalLM\"]}\n";
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, imported, err), err);
    const fs::path adapter = tmp / "fake-generate";
    {
        std::ofstream out(adapter);
        out << "#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps({\"ok\":True,\"text\":\"nope\"}), flush=True)\n";
    }
    ::chmod(fs::PathToString(adapter).c_str(), 0755);
    BOOST_REQUIRE_EQUAL(::setenv("BTX_MODEL_GENERATE", fs::PathToString(adapter).c_str(), 1), 0);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "generatemodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    params.push_back("hello");
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    err.clear();
    const bool ok = modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(code, "INCOMPATIBLE_HOST_PROFILE");
    BOOST_CHECK_EQUAL(err, "unknown_architecture");
    BOOST_CHECK_EQUAL(result["generated"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["compatible"].get_bool(), false);
    ::unsetenv("BTX_MODEL_GENERATE");
}

BOOST_AUTO_TEST_CASE(generatemodel_gguf_llama_cli)
{
    const fs::path tmp = m_path_root / "gen-gguf";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    {
        std::vector<unsigned char> gguf(24, 0);
        std::memcpy(gguf.data(), "GGUF", 4);
        WriteLE32(gguf.data() + 4, 3);
        std::ofstream gg(src / "model.gguf", std::ios::binary);
        gg.write(reinterpret_cast<const char*>(gguf.data()), static_cast<std::streamsize>(gguf.size()));
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, imported, err), err);

    const fs::path llama = tmp / "fake-llama";
    {
        std::ofstream out(llama);
        out << "#!/usr/bin/env python3\n"
               "import sys\n"
               "prompt = ''\n"
               "args = sys.argv[1:]\n"
               "for i, a in enumerate(args):\n"
               "    if a == '-p' and i + 1 < len(args):\n"
               "        prompt = args[i + 1]\n"
               "print('llama:' + prompt, flush=True)\n";
    }
    ::chmod(fs::PathToString(llama).c_str(), 0755);
    ::unsetenv("BTX_MODEL_GENERATE");
    BOOST_REQUIRE_EQUAL(::setenv("BTX_LLAMA_CLI", fs::PathToString(llama).c_str(), 1), 0);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "generatemodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    params.push_back("gguf-hi");
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    err.clear();
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["generated"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["text"].get_str(), "llama:gguf-hi");
    BOOST_CHECK_EQUAL(result["backend"].get_str(), "llama.cpp");
    BOOST_CHECK_EQUAL(result["local_generate"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["remote_inference"].get_bool(), false);
    ::unsetenv("BTX_LLAMA_CLI");
}

BOOST_AUTO_TEST_CASE(generatemodel_missing_adapter_is_not_run)
{
    ::unsetenv("BTX_MODEL_GENERATE");
    ::unsetenv("BTX_LLAMA_CLI");
    ::unsetenv("BTX_EXL3_CLI");
    const fs::path tmp = m_path_root / "gen-no-adapter";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    {
        const auto st = TinySafeTensors(0x95);
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream cfg(src / "config.json");
        cfg << "{\"architectures\":[\"LlamaForCausalLM\"]}\n";
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, imported, err), err);
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "generatemodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    params.push_back("hello");
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    err.clear();
    const bool ok = modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(code, "INCOMPATIBLE_HOST_PROFILE");
    BOOST_CHECK_EQUAL(err, "no_generate_adapter");
    ::unsetenv("BTX_MODEL_GENERATE");
    ::unsetenv("BTX_LLAMA_CLI");
}

BOOST_AUTO_TEST_CASE(exl3_is_safetensors_container_and_fail_closes_without_its_cli)
{
    modelnet::QualReport plain;
    const auto plain_bytes = TinySafeTensors(0x11);
    BOOST_CHECK(modelnet::QualifyBytes("model.safetensors", plain_bytes, plain) == modelnet::QualResult::STRUCTURE_VERIFIED);
    BOOST_CHECK(!plain.exl3);

    const auto exl3 = TinyExl3();
    modelnet::QualReport exl3_report;
    BOOST_CHECK(modelnet::QualifyBytes("model.exl3", exl3, exl3_report) == modelnet::QualResult::STRUCTURE_VERIFIED);
    BOOST_CHECK(exl3_report.exl3);
    BOOST_CHECK(modelnet::JsonDeclaresExl3("{\"quant_method\":\"exl3\"}"));
    BOOST_CHECK(modelnet::JsonDeclaresExl3("{\"quantization_config\":{\"quant_method\":\"exl3\"}}"));
    BOOST_CHECK(!modelnet::JsonDeclaresExl3("{\"quant_method\":\"EXL3\"}"));
    std::string nulled = "{\"quant_method\":\"exl3\"}";
    nulled.push_back('\0');
    BOOST_CHECK(!modelnet::JsonDeclaresExl3(nulled));

    const fs::path root = m_path_root / "exl3";
    fs::create_directories(root);
    const fs::path weights = root / "weights";
    fs::create_directories(weights);
    {
        std::ofstream out(weights / "model.exl3", std::ios::binary);
        out.write(reinterpret_cast<const char*>(exl3.data()), static_cast<std::streamsize>(exl3.size()));
        std::ofstream cfg(weights / "config.json");
        cfg << "{\"architectures\":[\"LlamaForCausalLM\"]}\n";
    }
    modelnet::QualReport file_report;
    BOOST_CHECK(modelnet::QualifyFile(fs::PathToString(weights / "model.exl3"), file_report) == modelnet::QualResult::STRUCTURE_VERIFIED);
    BOOST_CHECK(file_report.exl3);
    BOOST_CHECK(modelnet::WeightFileIsExl3(fs::PathToString(weights / "model.exl3")));

    const auto inspected = modelnet::InspectCheckoutForGenerate(weights);
    BOOST_CHECK(inspected.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(inspected.architecture, "LlamaForCausalLM");

    modelnet::HostGenerateProfile llama_only;
    llama_only.llama_cli = true;
    llama_only.llama_cli_path = "/bin/true";
    llama_only.generate_adapter = true;
    llama_only.generate_adapter_path = "/bin/false";
    std::string reason;
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(inspected, llama_only, reason));
    BOOST_CHECK_EQUAL(reason, "no_exl3_backend");
    BOOST_CHECK(modelnet::PickGenerateAdapter(inspected, llama_only).empty());

    modelnet::HostGenerateProfile exl3_host = llama_only;
    exl3_host.exl3_cli = true;
    exl3_host.exl3_cli_path = "/bin/true";
    reason.clear();
    BOOST_CHECK(modelnet::ArtifactCompatibleWithHost(inspected, exl3_host, reason));
    BOOST_CHECK_EQUAL(modelnet::PickGenerateAdapter(inspected, exl3_host), "/bin/true");

    const fs::path custom = root / "custom";
    fs::create_directories(custom);
    {
        std::ofstream out(custom / "model.exl3", std::ios::binary);
        out.write(reinterpret_cast<const char*>(exl3.data()), static_cast<std::streamsize>(exl3.size()));
        std::ofstream cfg(custom / "config.json");
        cfg << "{\"auto_map\":{\"AutoModel\":\"local\"}}\n";
    }
    const auto custom_view = modelnet::InspectCheckoutForGenerate(custom);
    BOOST_CHECK(custom_view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(custom_view.architecture, "custom_auto_map");
    reason.clear();
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(custom_view, exl3_host, reason));
    BOOST_CHECK_EQUAL(reason, "custom_code");

    const fs::path declared = root / "declared";
    fs::create_directories(declared);
    {
        const auto st = TinySafeTensors(0x12);
        std::ofstream out(declared / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream q(declared / "quantization_config.json");
        q << "{\"quant_method\":\"exl3\"}\n";
        std::ofstream cfg(declared / "config.json");
        cfg << "{\"architectures\":[\"LlamaForCausalLM\"]}\n";
    }
    const auto declared_view = modelnet::InspectCheckoutForGenerate(declared);
    BOOST_CHECK(declared_view.exl3_declared);
    BOOST_CHECK(declared_view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(declared_view.architecture, "LlamaForCausalLM");
    reason.clear();
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(declared_view, llama_only, reason));
    BOOST_CHECK_EQUAL(reason, "no_exl3_backend");

    const fs::path pickle = root / "pickle.exl3";
    {
        std::ofstream out(pickle, std::ios::binary);
        const unsigned char magic[] = {0x80, 0x04, 0x95, 0x00};
        out.write(reinterpret_cast<const char*>(magic), 4);
    }
    modelnet::QualReport pickle_report;
    BOOST_CHECK(modelnet::QualifyFile(fs::PathToString(pickle), pickle_report) == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const auto pickle_view = modelnet::InspectCheckoutForGenerate(pickle);
    BOOST_CHECK(pickle_view.format == modelnet::GenerateFormat::Unsafe);
    reason.clear();
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(pickle_view, exl3_host, reason));
    BOOST_CHECK_EQUAL(reason, "unsafe_format");

    const fs::path gguf_name = root / "not-really.exl3";
    {
        std::ofstream out(gguf_name, std::ios::binary);
        out << "GGUF";
        out.write("\0\0\0\0", 4);
    }
    const auto gguf_view = modelnet::InspectCheckoutForGenerate(gguf_name);
    BOOST_CHECK(gguf_view.format == modelnet::GenerateFormat::None);
    modelnet::QualReport gguf_report;
    BOOST_CHECK(modelnet::QualifyFile(fs::PathToString(gguf_name), gguf_report) != modelnet::QualResult::STRUCTURE_VERIFIED);

    const fs::path mixed = root / "mixed";
    fs::create_directories(mixed);
    {
        std::ofstream ex(mixed / "model.exl3", std::ios::binary);
        ex.write(reinterpret_cast<const char*>(exl3.data()), static_cast<std::streamsize>(exl3.size()));
        std::ofstream gg(mixed / "model.gguf", std::ios::binary);
        gg << "not-a-real-gguf";
    }
    BOOST_CHECK(modelnet::InspectCheckoutForGenerate(mixed).format == modelnet::GenerateFormat::Gguf);

    const fs::path cat_dir = root / "catalog";
    modelnet::Digest48 model_id;
    {
        modelnet::ModelCatalog cat{cat_dir, 8 << 20};
        modelnet::CatalogEntry imported;
        std::string err;
        BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(weights), true, imported, err), err);
        BOOST_CHECK_EQUAL(imported.core.format_profile, 1);
        BOOST_CHECK_EQUAL(imported.weight_format, "exl3");
        model_id = imported.model_id;
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", "previewmodelimport");
        UniValue params(UniValue::VARR);
        params.push_back(fs::PathToString(weights));
        rpc.pushKV("params", params);
        UniValue preview;
        std::string code;
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, preview, code, err), err);
        BOOST_CHECK_EQUAL(preview["format"].get_str(), "exl3");
    }
    {
        modelnet::ModelCatalog again{cat_dir, 8 << 20};
        modelnet::CatalogEntry loaded;
        BOOST_REQUIRE(again.Find(model_id, loaded));
        BOOST_CHECK_EQUAL(loaded.weight_format, "exl3");
        BOOST_CHECK_EQUAL(loaded.core.format_profile, 1);
    }
    {
        modelnet::ModelCatalog cat{root / "reject-pickle", 8 << 20};
        modelnet::CatalogEntry imported;
        std::string err;
        BOOST_CHECK(!cat.ImportPath(fs::PathToString(pickle), true, imported, err));
    }
}

BOOST_AUTO_TEST_CASE(exl3_missing_architecture_is_not_host_compatible)
{
    const fs::path dir = WriteExl3Checkout(m_path_root / "exl3-allowlist" / "missing", "{}\n");
    const auto view = modelnet::InspectCheckoutForGenerate(dir);
    BOOST_CHECK(view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK(view.architecture.empty());
    BOOST_CHECK(!modelnet::SafeTensorsArchitectureIsHostCompatible(view.architecture));
    const auto host = Exl3CliHost();
    std::string reason;
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(view, host, reason));
    BOOST_CHECK_EQUAL(reason, "missing_architecture");
}

BOOST_AUTO_TEST_CASE(exl3_unknown_architecture_is_not_host_compatible)
{
    const fs::path dir = WriteExl3Checkout(m_path_root / "exl3-allowlist" / "unknown",
                                           "{\"architectures\":[\"UnrecognizedForCausalLM\"]}\n");
    const auto view = modelnet::InspectCheckoutForGenerate(dir);
    BOOST_CHECK(view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(view.architecture, "UnrecognizedForCausalLM");
    BOOST_CHECK(!modelnet::SafeTensorsArchitectureIsHostCompatible(view.architecture));
    const auto host = Exl3CliHost();
    std::string reason;
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(view, host, reason));
    BOOST_CHECK_EQUAL(reason, "unknown_architecture");
}

BOOST_AUTO_TEST_CASE(exl3_unknown_architecture_with_auto_map_is_custom_code)
{
    const fs::path dir = WriteExl3Checkout(
        m_path_root / "exl3-allowlist" / "unknown-auto-map",
        "{\"architectures\":[\"UnrecognizedForCausalLM\"],\"auto_map\":{\"AutoModel\":\"local\"}}\n");
    const auto view = modelnet::InspectCheckoutForGenerate(dir);
    BOOST_CHECK(view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(view.architecture, "custom_auto_map");
    const auto host = Exl3CliHost();
    std::string reason;
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(view, host, reason));
    BOOST_CHECK_EQUAL(reason, "custom_code");

    const fs::path hidden = WriteExl3Checkout(
        m_path_root / "exl3-allowlist" / "allowlisted-auto-map",
        "{\"architectures\":[\"LlamaForCausalLM\"],\"auto_map\":{\"AutoModel\":\"local\"}}\n");
    const auto hidden_view = modelnet::InspectCheckoutForGenerate(hidden);
    BOOST_CHECK_EQUAL(hidden_view.architecture, "custom_auto_map");
    reason.clear();
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(hidden_view, host, reason));
    BOOST_CHECK_EQUAL(reason, "custom_code");
}

BOOST_AUTO_TEST_CASE(exl3_auto_map_alone_is_custom_code)
{
    const fs::path dir = WriteExl3Checkout(m_path_root / "exl3-allowlist" / "auto-map",
                                           "{\"auto_map\":{\"AutoModel\":\"local\"}}\n");
    const auto view = modelnet::InspectCheckoutForGenerate(dir);
    BOOST_CHECK(view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(view.architecture, "custom_auto_map");
    const auto host = Exl3CliHost();
    std::string reason;
    BOOST_CHECK(!modelnet::ArtifactCompatibleWithHost(view, host, reason));
    BOOST_CHECK_EQUAL(reason, "custom_code");
}

BOOST_AUTO_TEST_CASE(exl3_allowlisted_architecture_with_cli_is_compatible)
{
    const fs::path dir = WriteExl3Checkout(m_path_root / "exl3-allowlist" / "llama",
                                           "{\"architectures\":[\"LlamaForCausalLM\"]}\n");
    const auto view = modelnet::InspectCheckoutForGenerate(dir);
    BOOST_CHECK(view.format == modelnet::GenerateFormat::Exl3);
    BOOST_CHECK_EQUAL(view.architecture, "LlamaForCausalLM");
    BOOST_CHECK(modelnet::SafeTensorsArchitectureIsHostCompatible(view.architecture));
    const auto host = Exl3CliHost();
    std::string reason;
    BOOST_CHECK(modelnet::ArtifactCompatibleWithHost(view, host, reason));
    BOOST_CHECK_EQUAL(modelnet::PickGenerateAdapter(view, host), "/bin/true");
}

BOOST_AUTO_TEST_CASE(mldsa_tls_identity_is_minted_in_process_mode_0600)
{
    const fs::path dir = m_path_root / "tls-mint";
    fs::create_directories(dir);
    const fs::path cert = dir / "cert.pem";
    const fs::path key = dir / "key.pem";
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureMlDsaTlsFiles(cert, key, err), err);
    BOOST_CHECK(err.empty());
    struct stat cst {};
    struct stat kst {};
    BOOST_REQUIRE(::stat(fs::PathToString(cert).c_str(), &cst) == 0);
    BOOST_REQUIRE(::stat(fs::PathToString(key).c_str(), &kst) == 0);
    BOOST_CHECK_EQUAL(cst.st_mode & 0777, 0600);
    BOOST_CHECK_EQUAL(kst.st_mode & 0777, 0600);
    const auto cert_bytes = ReadFileBytes(cert);
    const auto key_bytes = ReadFileBytes(key);
    const std::string cert_pem(cert_bytes.begin(), cert_bytes.end());
    const std::string key_pem(key_bytes.begin(), key_bytes.end());
    BOOST_CHECK(cert_pem.find("BEGIN CERTIFICATE") != std::string::npos);
    BOOST_CHECK(key_pem.find("BEGIN") != std::string::npos);
    BOOST_REQUIRE(modelnet::EnsureMlDsaTlsFiles(cert, key, err));
    BOOST_CHECK(ReadFileBytes(key) == key_bytes);
    BOOST_CHECK(ReadFileBytes(cert) == cert_bytes);
}

BOOST_AUTO_TEST_CASE(removemodel_checks_in_use_before_unpin_and_deletes_the_directory)
{
    const fs::path tmp = m_path_root / "remove-model";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x91, true);
    const fs::path checkout = tmp / "checkout" / fs::PathFromString(imported.artifact_id.Hex());
    std::string merr;
    BOOST_REQUIRE_MESSAGE(cat.MaterializeCheckout(imported.model_id, checkout, merr), merr);
    BOOST_CHECK(fs::is_directory(checkout));
    const fs::path artifact_dir = cat.Store().Root() / "artifacts" / fs::PathFromString(imported.artifact_id.Hex());
    BOOST_CHECK(fs::exists(artifact_dir));

    cat.BeginTransfer(imported.artifact_id);
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "removemodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    std::string err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK_EQUAL(code, "IN_USE");
    modelnet::CatalogEntry still;
    BOOST_REQUIRE(cat.Find(imported.model_id, still));
    BOOST_CHECK(still.pinned);
    BOOST_CHECK(cat.Store().IsPinned(imported.model_id));
    BOOST_CHECK(fs::exists(artifact_dir));
    BOOST_CHECK(fs::is_directory(checkout));

    cat.EndTransfer(imported.artifact_id);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK(result["removed"].get_bool());
    BOOST_CHECK(result["checkout_removed"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!cat.Find(imported.model_id, still));
    BOOST_CHECK(!fs::exists(artifact_dir));
    BOOST_CHECK(!fs::exists(checkout));
}

BOOST_AUTO_TEST_CASE(model_dns_seeds_stay_empty_and_reject_addresses)
{
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(ArgsManager{}, chain);
        BOOST_REQUIRE(params);
        BOOST_CHECK(params->ModelDNSSeeds().empty());
    }
    BOOST_CHECK(!modelnet::ModelDnsNameAllowed("192.0.2.10"));
    BOOST_CHECK(!modelnet::ModelDnsNameAllowed("2001:db8::1"));
    BOOST_CHECK(!modelnet::ModelDnsNameAllowed(""));
    BOOST_CHECK(modelnet::ModelDnsNameAllowed("seed.example.invalid."));
    int calls = 0;
    const auto none = modelnet::ModelContactsFromDnsSeeds({}, modelnet::DEFAULT_MODEL_PORT, [&](const std::string&) {
        ++calls;
        return std::vector<CNetAddr>{};
    });
    BOOST_CHECK(none.empty());
    BOOST_CHECK_EQUAL(calls, 0);
    const auto doc = LookupHost("192.0.2.10", 1, false);
    BOOST_REQUIRE_EQUAL(doc.size(), 1U);
    int looked = 0;
    const auto got = modelnet::ModelContactsFromDnsSeeds({"seed.example.invalid.", "192.0.2.10"}, modelnet::DEFAULT_MODEL_PORT,
                                                         [&](const std::string& name) {
                                                             ++looked;
                                                             BOOST_CHECK_EQUAL(name, "seed.example.invalid");
                                                             return doc;
                                                         });
    BOOST_CHECK_EQUAL(looked, 1);
    BOOST_REQUIRE_EQUAL(got.size(), 1U);
    BOOST_CHECK_EQUAL(got[0], "192.0.2.10:" + std::to_string(modelnet::DEFAULT_MODEL_PORT));
}

BOOST_AUTO_TEST_SUITE_END()
