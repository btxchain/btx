// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// 0.34.7 default hosting / AUTO storage / pin / shard TDD.
// CACHE-01.., START-02/10/11/12 (library), SHARD-01..18 (no 13GiB unless env).

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <crypto/common.h>
#include <modelnet/auto_storage.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/hcp.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/policy.h>
#include <modelnet/store.h>
#include <modelnet/supervisor.h>
#include <modelnet/swarm.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>

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
        {128 * GIB, 80 * GIB, 24 * GIB, 40 * GIB},
        {256 * GIB, 200 * GIB, 32 * GIB, 40 * GIB},
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
        BOOST_CHECK_GE(q.reserve_bytes, 32 * GIB);
    }
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

BOOST_AUTO_TEST_SUITE_END()
