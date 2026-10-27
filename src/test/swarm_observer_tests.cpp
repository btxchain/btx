// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_observer.h>
#include <modelnet/swarm_close.h>
#include <modelnet/swarm_form/atomic.h>
#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_live.h>
#include <modelnet/swarm_node.h>

#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#ifndef WIN32
#include <sys/resource.h>
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <functional>
#include <future>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

BOOST_FIXTURE_TEST_SUITE(swarm_observer_tests, BasicTestingSetup)

namespace {

const std::string kModel(96, 'a');
const std::string kArtifact(96, 'b');
const std::string kFamily(96, 'c');

void WriteFile(const fs::path& path, const std::string& body)
{
    std::ofstream out(path, std::ios::trunc);
    out << body;
}

UniValue ReadJson(const fs::path& path)
{
    std::ifstream in(path);
    UniValue root;
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BOOST_REQUIRE(root.read(raw));
    return root;
}

} // namespace

BOOST_AUTO_TEST_CASE(provisional_lineage_matches_the_reference_digest)
{
    std::string model;
    model.reserve(96);
    for (int i = 0; i < 48; ++i) model += "ab";
    BOOST_CHECK_EQUAL(modelnet::SwarmProvisionalLineage(model),
                      "3959194cda24608705679e0148d84adc6b4f96ce54a3c9457605cac189c830eb86d795c3bc7d188ec86b3f425c9c5306");
}

BOOST_AUTO_TEST_CASE(verified_catalog_subscribes_an_observer_and_does_not_spend)
{
    const fs::path dir = m_args.GetDataDirBase() / "swarm_observer";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    std::ifstream in(dir / "swarm" / "observers.json");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK_EQUAL(root["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(!root["payment_authority"].get_bool());
    const UniValue& row = root["subscriptions"][0];
    BOOST_CHECK_EQUAL(row["role"].get_str(), "observer");
    BOOST_CHECK(!row["idle_compute_authorized"].get_bool());
    BOOST_CHECK(!row["private_data_training"].get_bool());
    BOOST_CHECK_EQUAL(row["visibility"].get_str(), "private");
    BOOST_CHECK_EQUAL(row["lineage_assurance"].get_str(), "PROVISIONAL_NOT_AUTHORITATIVE");
    BOOST_CHECK_EQUAL(row["lineage_id"].get_str(), modelnet::SwarmProvisionalLineage(kModel));
    BOOST_CHECK(modelnet::SwarmObserveCatalog(dir, err));
}

BOOST_AUTO_TEST_CASE(planted_temp_symlinks_are_not_written_through)
{
    const fs::path dir = m_path_root / "catalog_tmp_link";
    const fs::path swarm = dir / "swarm";
    const fs::path outside = m_path_root / "catalog_tmp_link_outside";
    fs::create_directories(swarm);
    fs::create_directories(outside);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    const auto plant = [&](const std::string& name) {
        fs::remove(swarm / fs::u8path(name + ".json"));
        WriteFile(outside / fs::u8path(name), "outside");
        fs::create_symlink(outside / fs::u8path(name), swarm / fs::u8path(name + ".json.tmp"));
    };
    for (const std::string name : {"mesh-state", "networks"}) plant(name);
    BOOST_CHECK(!modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_CHECK(!modelnet::SwarmPublishLive(dir, err));
    plant("contribution");
    BOOST_CHECK(!modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_CHECK_EQUAL(err, "SYMLINK");
    for (const std::string name : {"mesh-state", "networks", "contribution"}) {
        std::ifstream in(outside / fs::u8path(name));
        BOOST_CHECK_EQUAL(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()), "outside");
        BOOST_CHECK(!fs::exists(fs::symlink_status(swarm / fs::u8path(name + ".json"))));
    }
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(failed_writes_leave_the_swarm_files_unchanged)
{
    const fs::path dir = m_path_root / "catalog_short_write";
    const fs::path swarm = dir / "swarm";
    fs::create_directories(swarm);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    // Make every derived file differ from what the pass would write, then let
    // no write grow a file past 8 bytes, as on a full disk. Each file stays a
    // valid document, and contribution.json stays readable so that the live
    // step gets as far as networks.json.
    const std::vector<std::string> names{"observers", "mesh-state", "networks"};
    const std::string other = "{\"automatic_spend_atoms\":\"0\",\"payment_authority\":false,\"subscriptions\":[]}";
    for (const std::string& name : names) WriteFile(swarm / fs::u8path(name + ".json"), other);
    const fs::path contribution = swarm / "contribution.json";
    const std::string contribution_bytes = [&] {
        std::ifstream in(contribution);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }();
    WriteFile(swarm / "lineage-mappings.json",
              "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":\"public\"}}");
    rlimit before{};
    BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_FSIZE, &before), 0);
    rlimit tight = before;
    tight.rlim_cur = 8;
    const auto previous = std::signal(SIGXFSZ, SIG_IGN);
    BOOST_REQUIRE_EQUAL(setrlimit(RLIMIT_FSIZE, &tight), 0);
    std::vector<bool> wrote;
    std::string observe_err, join_err, mesh_err, live_err;
    wrote.push_back(modelnet::SwarmObserveCatalog(dir, observe_err));
    wrote.push_back(modelnet::SwarmIntegrateCatalog(dir, join_err));
    wrote.push_back(modelnet::SwarmRefreshLocalMesh(dir, mesh_err));
    wrote.push_back(modelnet::SwarmPublishLive(dir, live_err));
    BOOST_REQUIRE_EQUAL(setrlimit(RLIMIT_FSIZE, &before), 0);
    std::signal(SIGXFSZ, previous);
    BOOST_CHECK(!wrote[0]);
    BOOST_CHECK_EQUAL(observe_err, "OBSERVER_WRITE");
    BOOST_CHECK(!wrote[1]);
    BOOST_CHECK_EQUAL(join_err, "WRITE");
    BOOST_CHECK(!wrote[2]);
    BOOST_CHECK_EQUAL(mesh_err, "MESH_WRITE");
    BOOST_CHECK(!wrote[3]);
    BOOST_CHECK_EQUAL(live_err, "NETWORKS_WRITE");
    std::ifstream kept(contribution);
    BOOST_CHECK_EQUAL(std::string((std::istreambuf_iterator<char>(kept)), std::istreambuf_iterator<char>()), contribution_bytes);
    BOOST_CHECK(!fs::exists(fs::symlink_status(swarm / "contribution.json.tmp")));
    for (const std::string& name : names) {
        std::ifstream in(swarm / fs::u8path(name + ".json"));
        BOOST_CHECK_EQUAL(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()), other);
        BOOST_CHECK(!fs::exists(fs::symlink_status(swarm / fs::u8path(name + ".json.tmp"))));
    }
}
#endif

BOOST_AUTO_TEST_CASE(incomplete_or_unverified_models_do_not_subscribe)
{
    const fs::path dir = m_args.GetDataDirBase() / "swarm_observer_skip";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":true},"
                  "{\"artifact_id\":\"" +
                  kFamily + "\",\"model_id\":\"" + kModel + "\",\"bytes_verified\":false,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_CHECK(!fs::exists(dir / "swarm" / "observers.json"));
}

BOOST_AUTO_TEST_CASE(damaged_observers_file_is_set_aside_and_written_again)
{
    const fs::path dir = m_path_root / "catalog_bad_observers";
    const fs::path swarm = dir / "swarm";
    fs::create_directories(swarm);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    const fs::path observers = swarm / "observers.json";
    const fs::path aside = swarm / "observers.json.bad";
    const auto read = [](const fs::path& path) {
        std::ifstream in(path);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    };
    const std::string good = read(observers);
    // Cut short, a field that is not a string, and an id that is not an id.
    for (const std::string& damaged : {good.substr(0, good.size() / 2), std::string("{\"subscriptions\":[{\"artifact_id\":7}]}"),
                                       std::string("{\"subscriptions\":[{\"artifact_id\":\"x\",\"model_id\":\"x\","
                                                   "\"lineage_id\":\"x\",\"lineage_assurance\":\"x\",\"visibility\":\"x\"}]}")}) {
        WriteFile(observers, damaged);
        err = "stale";
        bool ok = false;
        BOOST_REQUIRE_NO_THROW(ok = modelnet::SwarmObserveCatalog(dir, err));
        BOOST_CHECK(ok);
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(read(observers), good);
        BOOST_CHECK_EQUAL(read(aside), damaged);
        BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
        BOOST_CHECK_EQUAL(read(observers), good);
    }
    fs::remove(observers);
    fs::remove(aside);
    WriteFile(m_path_root / "catalog_bad_observers_target", "{}");
    fs::create_symlink(m_path_root / "catalog_bad_observers_target", observers);
    BOOST_CHECK(!modelnet::SwarmObserveCatalog(dir, err));
    BOOST_CHECK_EQUAL(err, "CATALOG_SYMLINK");
    BOOST_CHECK(fs::is_symlink(fs::symlink_status(observers)));
    BOOST_CHECK(!fs::exists(fs::symlink_status(aside)));
}

BOOST_AUTO_TEST_CASE(a_local_mapping_publishes_only_that_lineage)
{
    const fs::path dir = m_args.GetDataDirBase() / "swarm_observer_map";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir / "swarm");
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    WriteFile(dir / "swarm" / "lineage-mappings.json",
              "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":\"public\"}}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    std::ifstream in(dir / "swarm" / "observers.json");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK_EQUAL(root["subscriptions"][0]["lineage_id"].get_str(), kFamily);
    BOOST_CHECK_EQUAL(root["subscriptions"][0]["lineage_assurance"].get_str(), "VERIFIED_MAPPING");
    BOOST_CHECK_EQUAL(root["subscriptions"][0]["visibility"].get_str(), "public");
}

BOOST_AUTO_TEST_CASE(catalog_views_share_identity_visibility_and_invalidation)
{
    const fs::path dir = m_path_root / "catalog_views";
    fs::create_directories(dir / "swarm");
    const fs::path catalog = dir / "catalog.json";
    const fs::path mappings = dir / "swarm" / "lineage-mappings.json";
    const fs::path observers = dir / "swarm" / "observers.json";
    const fs::path contribution = dir / "swarm" / "contribution.json";
    const std::string eligible = "{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
        "\",\"bytes_verified\":true,\"incomplete\":false,\"visibility\":\"public\"}";
    const auto put_model = [&](const std::string& row) { WriteFile(catalog, "{\"models\":[" + row + "]}"); };
    std::string err;
    const auto refresh = [&] {
        BOOST_REQUIRE_MESSAGE(modelnet::SwarmObserveCatalog(dir, err), err);
        BOOST_REQUIRE_MESSAGE(modelnet::SwarmIntegrateCatalog(dir, err), err);
    };
    const auto check_identity = [&](const std::string& lineage, bool is_public, const std::string& assurance) {
        refresh();
        const UniValue observed = ReadJson(observers)["subscriptions"];
        const UniValue joined = ReadJson(contribution)["models"];
        BOOST_REQUIRE_EQUAL(observed.size(), 1U);
        BOOST_REQUIRE_EQUAL(joined.size(), 1U);
        BOOST_CHECK_EQUAL(observed[0]["lineage_id"].get_str(), lineage);
        BOOST_CHECK_EQUAL(joined[0]["lineage_id"].get_str(), lineage);
        BOOST_CHECK_EQUAL(joined[0]["model_id"].get_str(), kModel);
        BOOST_CHECK_EQUAL(joined[0]["economy_id"].get_str(), modelnet::SwarmEconomyIdentity(lineage));
        BOOST_CHECK_EQUAL(observed[0]["lineage_assurance"].get_str(), assurance);
        BOOST_CHECK_EQUAL(joined[0]["lineage_assurance"].get_str(), assurance);
        BOOST_CHECK_EQUAL(observed[0]["visibility"].get_str(), is_public ? "public" : "private");
        BOOST_CHECK_EQUAL(joined[0]["seed"].get_bool(), is_public);
        BOOST_CHECK_EQUAL(joined[0]["private_acquire"].get_bool(), !is_public);
        BOOST_CHECK(!joined[0]["kv_share"].get_bool());
        BOOST_CHECK_EQUAL(joined[0]["checkpoint_id"].get_str(), "");
        BOOST_CHECK_EQUAL(joined[0]["recipe"].get_str(), "");
    };
    put_model(eligible);
    check_identity(modelnet::SwarmProvisionalLineage(kModel), false, "PROVISIONAL_NOT_AUTHORITATIVE");
    WriteFile(mappings, "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":\"public\"}}");
    check_identity(kFamily, true, "VERIFIED_MAPPING");
    WriteFile(mappings, "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":\"private\"}}");
    check_identity(kFamily, false, "VERIFIED_MAPPING");
    fs::remove(mappings);
    check_identity(modelnet::SwarmProvisionalLineage(kModel), false, "PROVISIONAL_NOT_AUTHORITATIVE");

    // Each transition starts from an existing subscription, including re-add.
    for (const char* flags : {"\"bytes_verified\":false,\"incomplete\":false",
                                     "\"bytes_verified\":true,\"incomplete\":true",
                                     "\"bytes_verified\":true", // completeness unknown
                                     "\"bytes_verified\":true,\"incomplete\":\"false\""}) {
        put_model("{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel + "\"," + flags + "}");
        refresh();
        BOOST_CHECK(ReadJson(observers)["subscriptions"].empty());
        BOOST_CHECK(ReadJson(contribution)["models"].empty());
        put_model(eligible);
        refresh();
        BOOST_REQUIRE_EQUAL(ReadJson(observers)["subscriptions"].size(), 1U);
    }
    put_model("");
    refresh();
    BOOST_CHECK(ReadJson(observers)["subscriptions"].empty());
    BOOST_CHECK(ReadJson(contribution)["models"].empty());
    put_model(eligible);
    refresh();
    fs::remove(catalog);
    refresh();
    BOOST_CHECK(ReadJson(observers)["subscriptions"].empty());
    BOOST_CHECK(ReadJson(contribution)["models"].empty());

    // Unusable input preserves the last valid snapshot, reports failure, and
    // returns no partially parsed catalog to a caller.
    put_model(eligible);
    refresh();
    const std::string before_observer = ReadJson(observers).write();
    const std::string before_contribution = ReadJson(contribution).write();
    for (const std::string& bad : std::vector<std::string>{"{", "{\"models\":[" + eligible + "," + eligible + "]}"}) {
        WriteFile(catalog, bad);
        modelnet::SwarmCatalog entries;
        BOOST_CHECK(!modelnet::SwarmReadCatalog(dir, entries, err));
        BOOST_CHECK(entries.empty());
        BOOST_CHECK(!modelnet::SwarmObserveCatalog(dir, err));
        BOOST_CHECK(!modelnet::SwarmIntegrateCatalog(dir, err));
        BOOST_CHECK_EQUAL(ReadJson(observers).write(), before_observer);
        BOOST_CHECK_EQUAL(ReadJson(contribution).write(), before_contribution);
    }
    put_model(eligible);
    WriteFile(mappings, "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":false}}");
    BOOST_CHECK(!modelnet::SwarmObserveCatalog(dir, err));
    BOOST_CHECK(!modelnet::SwarmIntegrateCatalog(dir, err));
}

BOOST_AUTO_TEST_CASE(unchanged_generation_does_not_rewrite_derived_files)
{
    const fs::path dir = m_path_root / "catalog_quiet";
    fs::create_directories(dir / "swarm");
    const fs::path catalog = dir / "catalog.json";
    const fs::path mappings = dir / "swarm" / "lineage-mappings.json";
    WriteFile(catalog,
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false,\"quantization\":\"full\","
                  "\"checkpoint_id\":\"ckpt\",\"recipe\":\"recipe\"}]}");
    WriteFile(mappings, "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":\"public\"}}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_REQUIRE(modelnet::SwarmFormPlane(dir, err));
    const fs::path observers = dir / "swarm" / "observers.json";
    const fs::path contribution = dir / "swarm" / "contribution.json";
    const fs::path mesh = dir / "swarm" / "mesh-state.json";
    const fs::path networks = dir / "swarm" / "networks.json";
    const fs::path membership = dir / "swarm" / modelnet::kMembershipFile;
    const std::string membership_bytes = [&] {
        std::ifstream in(membership);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }();
    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(3);
    for (const fs::path& path : {observers, contribution, mesh, networks, membership}) {
        fs::last_write_time(path, old);
    }
    const auto observers_stamp = fs::last_write_time(observers);
    const auto contribution_stamp = fs::last_write_time(contribution);
    const auto mesh_stamp = fs::last_write_time(mesh);
    const auto networks_stamp = fs::last_write_time(networks);
    const auto membership_stamp = fs::last_write_time(membership);
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_REQUIRE(modelnet::SwarmFormPlane(dir, err));
    BOOST_CHECK(fs::last_write_time(observers) == observers_stamp);
    BOOST_CHECK(fs::last_write_time(contribution) == contribution_stamp);
    BOOST_CHECK(fs::last_write_time(mesh) == mesh_stamp);
    BOOST_CHECK(fs::last_write_time(networks) == networks_stamp);
    BOOST_CHECK(fs::last_write_time(membership) == membership_stamp);
    BOOST_CHECK_EQUAL(([&] {
                          std::ifstream in(membership);
                          return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                      })(),
                      membership_bytes);

    WriteFile(mappings, "{\"" + kArtifact + "\":{\"lineage_id\":\"" + kFamily + "\",\"visibility\":\"private\"}}");
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_CHECK(fs::last_write_time(observers) != observers_stamp);
    BOOST_CHECK(fs::last_write_time(contribution) != contribution_stamp);
    BOOST_CHECK_EQUAL(ReadJson(observers)["subscriptions"][0]["visibility"].get_str(), "private");
    BOOST_CHECK(!ReadJson(contribution)["models"][0]["seed"].get_bool());
    BOOST_CHECK(ReadJson(contribution)["models"][0]["private_acquire"].get_bool());

    WriteFile(catalog, "{\"models\":[]}");
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_CHECK(ReadJson(observers)["subscriptions"].empty());
    BOOST_CHECK(ReadJson(contribution)["models"].empty());
    BOOST_CHECK(ReadJson(networks)["family"]["member_artifact_ids"].empty());
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(fifos_at_derived_files_do_not_block_the_pass)
{
    const fs::path dir = m_path_root / "catalog_fifo";
    const fs::path swarm = dir / "swarm";
    fs::create_directories(swarm);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_REQUIRE(modelnet::SwarmFormPlane(dir, err));
    // Put a FIFO where a derived file was and run the step that reads it.
    // Opening a FIFO for reading waits for a writer, so a reader that opens
    // it does not return. Release such a reader so the case can fail instead
    // of hanging.
    const auto returns = [&](const std::string& name, const std::function<bool()>& step) {
        const fs::path file = swarm / fs::u8path(name);
        fs::remove(file);
        BOOST_REQUIRE_EQUAL(mkfifo(file.c_str(), 0600), 0);
        auto done = std::async(std::launch::async, step);
        const bool returned = done.wait_for(std::chrono::seconds{5}) == std::future_status::ready;
        while (done.wait_for(std::chrono::milliseconds{100}) != std::future_status::ready) {
            const int fd = open(file.c_str(), O_WRONLY | O_NONBLOCK);
            if (fd >= 0) close(fd);
        }
        done.get();
        if (fs::is_fifo(fs::symlink_status(file))) fs::remove(file);
        return returned;
    };
    BOOST_CHECK(returns("contribution.json", [&] { return modelnet::SwarmIntegrateCatalog(dir, err); }));
    BOOST_CHECK(fs::is_regular_file(swarm / "contribution.json"));
    BOOST_CHECK(returns("contribution.json", [&] { return modelnet::SwarmPublishLive(dir, err); }));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_CHECK(returns("networks.json", [&] { return modelnet::SwarmPublishLive(dir, err); }));
    BOOST_CHECK(fs::is_regular_file(swarm / "networks.json"));
    BOOST_CHECK(returns(modelnet::kMembershipFile, [&] { return modelnet::SwarmFormPlane(dir, err); }));
}
#endif

#ifndef WIN32
BOOST_AUTO_TEST_CASE(fifo_at_a_temp_file_does_not_block_the_write)
{
    const fs::path dir = m_path_root / "catalog_fifo_tmp";
    const fs::path swarm = dir / "swarm";
    fs::create_directories(swarm);
    WriteFile(dir / "catalog.json",
              "{\"models\":[{\"artifact_id\":\"" + kArtifact + "\",\"model_id\":\"" + kModel +
                  "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmObserveCatalog(dir, err));
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    const fs::path contribution = swarm / "contribution.json";
    const fs::path tmp = swarm / "contribution.json.tmp";
    const auto bytes = [](const fs::path& path) {
        if (!fs::is_regular_file(fs::symlink_status(path))) return std::string{"not a regular file"};
        std::ifstream in(path);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    };
    const std::string written = bytes(contribution);
    // contribution.json is written again only when it changed: remove it and
    // put a FIFO at its temp path. Opening a FIFO for writing waits for a
    // reader, so open the read end and drain it until the step returns, so
    // the case can fail instead of hanging.
    fs::remove(contribution);
    BOOST_REQUIRE_EQUAL(mkfifo(tmp.c_str(), 0600), 0);
    std::string join_err;
    auto done = std::async(std::launch::async, [&] { return modelnet::SwarmIntegrateCatalog(dir, join_err); });
    const bool returned = done.wait_for(std::chrono::seconds{5}) == std::future_status::ready;
    int fd = -1;
    while (done.wait_for(std::chrono::milliseconds{100}) != std::future_status::ready) {
        if (fd < 0) fd = open(tmp.c_str(), O_RDONLY | O_NONBLOCK);
        char buf[4096];
        while (fd >= 0 && read(fd, buf, sizeof(buf)) > 0) {
        }
    }
    if (fd >= 0) close(fd);
    BOOST_CHECK_MESSAGE(returned, "a FIFO at contribution.json.tmp blocks the swarm write");
    BOOST_CHECK(done.get());
    BOOST_CHECK_EQUAL(join_err, "");
    BOOST_CHECK_EQUAL(bytes(contribution), written);
    BOOST_CHECK(!fs::exists(fs::symlink_status(tmp)));
    // The temp file of an interrupted write is replaced too.
    fs::remove(contribution);
    fs::remove(tmp);
    WriteFile(tmp, "partial");
    BOOST_CHECK(modelnet::SwarmIntegrateCatalog(dir, err));
    BOOST_CHECK_EQUAL(bytes(contribution), written);
    BOOST_CHECK(!fs::exists(fs::symlink_status(tmp)));
}
#endif

#ifndef WIN32
BOOST_AUTO_TEST_CASE(readers_do_not_wait_on_a_fifo)
{
    const fs::path dir = m_path_root / "read_fifo";
    fs::create_directories(dir);
    const fs::path fifo = dir / "fifo.json";
    const fs::path fifo_link = dir / "fifo-link.json";
    const fs::path regular = dir / "regular.json";
    const fs::path regular_link = dir / "regular-link.json";
    BOOST_REQUIRE_EQUAL(mkfifo(fifo.c_str(), 0600), 0);
    fs::create_symlink(fifo, fifo_link);
    WriteFile(regular, "{}");
    fs::create_symlink(regular, regular_link);
    // Opening a FIFO for reading waits for a writer. Open the write end and
    // close it until the reads return, so the case can fail instead of hanging.
    std::string raw{"kept"}, link_raw{"kept"}, form_raw{"kept"}, form_err;
    auto done = std::async(std::launch::async, [&] {
        return std::vector<bool>{modelnet::SwarmReadRegularFile(fifo, raw),
                                 modelnet::SwarmReadRegularFile(fifo_link, link_raw),
                                 modelnet::SwarmFormRead(fifo, form_raw, form_err)};
    });
    const bool returned = done.wait_for(std::chrono::seconds{5}) == std::future_status::ready;
    while (done.wait_for(std::chrono::milliseconds{100}) != std::future_status::ready) {
        const int fd = open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
        if (fd >= 0) close(fd);
    }
    const std::vector<bool> results = done.get();
    BOOST_CHECK_MESSAGE(returned, "a swarm reader waits on a FIFO");
    BOOST_CHECK(!results[0]);
    BOOST_CHECK_EQUAL(raw, "kept");
    BOOST_CHECK(!results[1]);
    BOOST_CHECK_EQUAL(link_raw, "kept");
    BOOST_CHECK(!results[2]);
    BOOST_CHECK_EQUAL(form_err, "READ");
    BOOST_CHECK_EQUAL(form_raw, "kept");
    // A directory is not read either. Regular files, and links to them, read as before.
    std::string got{"kept"};
    BOOST_CHECK(!modelnet::SwarmReadRegularFile(dir, got));
    BOOST_CHECK_EQUAL(got, "kept");
    BOOST_CHECK(modelnet::SwarmReadRegularFile(regular, got));
    BOOST_CHECK_EQUAL(got, "{}");
    got.clear();
    BOOST_CHECK(modelnet::SwarmReadRegularFile(regular_link, got));
    BOOST_CHECK_EQUAL(got, "{}");
}

BOOST_AUTO_TEST_CASE(a_fifo_swapped_in_after_the_check_does_not_block_a_read)
{
    // A reader that checks the path and then opens it can open a FIFO that
    // replaced the file in between. Swap hard links to one FIFO and one
    // regular file in at the path while SwarmFormRead runs. The FIFO stays
    // reachable at its own name, so a blocked reader can be released. A read
    // that succeeds must have read the regular file.
    const fs::path dir = m_path_root / "read_fifo_swap";
    fs::create_directories(dir);
    const fs::path file = dir / fs::u8path(modelnet::kMembershipFile);
    const fs::path fifo = dir / "fifo";
    const fs::path regular = dir / "regular";
    const fs::path staged = dir / "staged";
    BOOST_REQUIRE_EQUAL(mkfifo(fifo.c_str(), 0600), 0);
    WriteFile(regular, "{}");
    fs::create_hard_link(regular, file);
    std::atomic<bool> stop{false};
    std::thread swapper([&] {
        while (!stop) {
            for (const fs::path* from : {&fifo, &regular}) {
                unlink(staged.c_str());
                if (link(from->c_str(), staged.c_str()) == 0) rename(staged.c_str(), file.c_str());
            }
        }
    });
    auto done = std::async(std::launch::async, [&] {
        std::vector<int> counts(3, 0); // read, refused, read but not the regular file
        for (int i = 0; i < 20000; ++i) {
            std::string raw, read_err;
            if (!modelnet::SwarmFormRead(file, raw, read_err)) {
                ++counts[1];
            } else {
                ++counts[raw == "{}" ? 0 : 2];
            }
        }
        return counts;
    });
    const bool returned = done.wait_for(std::chrono::seconds{10}) == std::future_status::ready;
    stop = true;
    swapper.join();
    while (done.wait_for(std::chrono::milliseconds{100}) != std::future_status::ready) {
        const int fd = open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
        if (fd >= 0) close(fd);
    }
    const std::vector<int> counts = done.get();
    BOOST_TEST_MESSAGE("read " << counts[0] << ", refused " << counts[1] << ", not the regular file " << counts[2]);
    BOOST_CHECK_MESSAGE(returned, "a FIFO swapped in after the check blocks the read");
    BOOST_CHECK_EQUAL(counts[2], 0);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
