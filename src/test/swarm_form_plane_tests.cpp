// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_form/types.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(swarm_form_plane_tests, BasicTestingSetup)

namespace {

class FormTree {
public:
    explicit FormTree(fs::path path_in) : path(std::move(path_in))
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~FormTree()
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    FormTree(const FormTree&) = delete;
    FormTree& operator=(const FormTree&) = delete;
    fs::path path;
};

std::string ReadFile(const fs::path& file)
{
    std::ifstream in(file, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

BOOST_AUTO_TEST_CASE(observer_entry_forms_once_and_keeps_the_plane_local)
{
    FormTree tree(m_path_root / "swarm-form-plane");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);
    {
        std::ofstream keep(model / "catalog.json");
        keep << "{}\n";
    }

    const fs::path relative_swarm{"swarm"};
    const bool swarm_existed = fs::exists(relative_swarm);

    std::string err = "stale";
    BOOST_CHECK(!modelnet::SwarmFormPlane(std::filesystem::path{}, err));
    BOOST_CHECK_EQUAL(err, "MODELDIR");
    if (!swarm_existed) {
        BOOST_CHECK(!fs::exists(relative_swarm));
    }
    BOOST_CHECK(!fs::exists(model / "swarm"));

    err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(fs::is_directory(model / "swarm"));
    BOOST_CHECK_EQUAL(ReadFile(model / "catalog.json"), "{}\n");

    const fs::path membership = model / "swarm" / modelnet::kMembershipFile;
    const std::string first = ReadFile(membership);
    err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(ReadFile(membership), first);

    modelnet::FormationPlane plane;
    err = "stale";
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.membership().node_id, "local");
    BOOST_CHECK(plane.membership().seeder);
    BOOST_CHECK(plane.membership().evaluator);
    BOOST_CHECK(plane.membership().modelnet_on);
    BOOST_CHECK(!plane.membership().training);
    BOOST_CHECK(!plane.membership().private_prompts);
    BOOST_CHECK_EQUAL(plane.membership().automatic_spend, "0");
    BOOST_CHECK_EQUAL(plane.membership().vram_mib, 0);
    BOOST_CHECK_EQUAL(plane.membership().cpu_thread_cap, 64);
    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK(plane.leader().empty());
    BOOST_CHECK(!plane.bytes_moved());
    BOOST_CHECK(!plane.launched_sidecar());
    BOOST_CHECK(plane.dns_seeds().empty());
    BOOST_CHECK(!plane.connects());

    err = "stale";
    BOOST_CHECK(!plane.Claim("", 1, err));
    BOOST_CHECK_EQUAL(err, "LEADER");
    BOOST_CHECK(plane.leader().empty());
    BOOST_CHECK(!fs::exists(plane.directory() / modelnet::kElectionFile));

    err = "stale";
    BOOST_CHECK(!plane.Discover("peer-other", "other-family", true, err));
    BOOST_CHECK_EQUAL(err, "FALSE_COMPAT");
    BOOST_CHECK(!plane.admitted("peer-other"));
    BOOST_CHECK(!plane.connects());

    err = "stale";
    BOOST_REQUIRE(plane.Discover("peer-family", modelnet::kFormationFamilyId, true, err));
    BOOST_CHECK(plane.admitted("peer-family"));
    BOOST_CHECK(!plane.connects());
    BOOST_CHECK(!plane.bytes_moved());

    err = "stale";
    BOOST_REQUIRE(plane.Claim("local", 1, err));
    const std::string election = ReadFile(plane.directory() / modelnet::kElectionFile);
    err = "stale";
    BOOST_CHECK(!plane.Claim("peer-family", 0, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(plane.leader(), "local");
    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK_EQUAL(ReadFile(plane.directory() / modelnet::kElectionFile), election);

    err = "stale";
    BOOST_REQUIRE(plane.Claim("peer-family", 2, err));
    BOOST_CHECK_EQUAL(plane.leader(), "peer-family");
    BOOST_CHECK_EQUAL(plane.epoch(), 2U);
    err = "stale";
    BOOST_CHECK(!plane.Claim("local", 1, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(plane.leader(), "peer-family");
    BOOST_CHECK(!plane.bytes_moved());
    BOOST_CHECK(!plane.launched_sidecar());
    BOOST_CHECK(plane.dns_seeds().empty());
    BOOST_CHECK(!plane.connects());
    BOOST_CHECK_EQUAL(plane.membership().automatic_spend, "0");
}

BOOST_AUTO_TEST_CASE(symlink_model_swarm_does_not_receive_a_membership)
{
    FormTree tree(m_path_root / "swarm-form-plane-symlink");
    const fs::path model = tree.path / "model";
    const fs::path target = tree.path / "target";
    fs::create_directories(model);
    fs::create_directories(target);
    fs::create_symlink(target, model / "swarm");

    std::string err = "stale";
    BOOST_CHECK(!modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK_EQUAL(err, "SYMLINK");
    BOOST_CHECK(!fs::exists(target / modelnet::kMembershipFile));
    BOOST_CHECK(fs::is_symlink(fs::symlink_status(model / "swarm")));
}

BOOST_AUTO_TEST_SUITE_END()
