// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_form/types.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(swarm_form_election_tests, BasicTestingSetup)

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

modelnet::FormationPlane Opened(const fs::path& model)
{
    modelnet::FormationPlane plane;
    std::string err;
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));
    return plane;
}

} // namespace

BOOST_AUTO_TEST_CASE(epoch_starts_at_one_and_empty_candidate_stores_nothing)
{
    FormTree tree(m_path_root / "swarm-form-election-empty");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);
    modelnet::FormationPlane plane = Opened(model);

    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK(plane.leader().empty());
    BOOST_CHECK(!fs::exists(plane.directory() / modelnet::kElectionFile));

    std::string err = "stale";
    BOOST_CHECK(!plane.Claim("", 1, err));
    BOOST_CHECK_EQUAL(err, "LEADER");
    BOOST_CHECK(plane.leader().empty());
    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK(!fs::exists(plane.directory() / modelnet::kElectionFile));
}

BOOST_AUTO_TEST_CASE(only_an_admitted_member_can_be_coordinator)
{
    FormTree tree(m_path_root / "swarm-form-election-admitted");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);
    modelnet::FormationPlane plane = Opened(model);

    std::string err = "stale";
    BOOST_CHECK(!plane.Claim("stranger", 1, err));
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
    BOOST_CHECK(plane.leader().empty());
    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK(!fs::exists(plane.directory() / modelnet::kElectionFile));

    err = "stale";
    BOOST_REQUIRE(plane.Claim("local", 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.leader(), "local");
    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK(fs::exists(plane.directory() / modelnet::kElectionFile));
    const std::string stored = ReadFile(plane.directory() / modelnet::kElectionFile);
    BOOST_CHECK(stored.find("\"automatic_spend\":\"0\"") != std::string::npos);
    BOOST_CHECK(stored.find("\"leader\":\"local\"") != std::string::npos);

    err = "stale";
    BOOST_CHECK(!plane.Claim("stranger", 2, err));
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
    BOOST_CHECK_EQUAL(plane.leader(), "local");
    BOOST_CHECK_EQUAL(plane.epoch(), 1U);
    BOOST_CHECK_EQUAL(ReadFile(plane.directory() / modelnet::kElectionFile), stored);
}

BOOST_AUTO_TEST_CASE(stale_epoch_does_not_replace_the_leader)
{
    FormTree tree(m_path_root / "swarm-form-election-stale");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);
    {
        modelnet::FormationPlane plane = Opened(model);
        std::string err = "stale";
        BOOST_REQUIRE(plane.Claim("local", 1, err));
        BOOST_REQUIRE(plane.Discover("peer-family", modelnet::kFormationFamilyId, true, err));
        err = "stale";
        BOOST_REQUIRE(plane.Claim("peer-family", 2, err));
        BOOST_CHECK_EQUAL(plane.leader(), "peer-family");
        BOOST_CHECK_EQUAL(plane.epoch(), 2U);
    }

    modelnet::FormationPlane again;
    std::string err = "stale";
    BOOST_REQUIRE(again.Open(model, err));
    BOOST_REQUIRE(again.Form(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(again.leader(), "peer-family");
    BOOST_CHECK_EQUAL(again.epoch(), 2U);
    const std::string stored = ReadFile(again.directory() / modelnet::kElectionFile);

    err = "stale";
    BOOST_CHECK(!again.Claim("local", 1, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(again.leader(), "peer-family");
    BOOST_CHECK_EQUAL(again.epoch(), 2U);
    BOOST_CHECK_EQUAL(ReadFile(again.directory() / modelnet::kElectionFile), stored);

    err = "stale";
    BOOST_CHECK(!again.Claim("local", 0, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(again.leader(), "peer-family");
    BOOST_CHECK_EQUAL(ReadFile(again.directory() / modelnet::kElectionFile), stored);

    err = "stale";
    BOOST_CHECK(!again.Claim("", 9, err));
    BOOST_CHECK_EQUAL(err, "LEADER");
    BOOST_CHECK_EQUAL(again.leader(), "peer-family");
    BOOST_CHECK_EQUAL(again.epoch(), 2U);
    BOOST_CHECK_EQUAL(ReadFile(again.directory() / modelnet::kElectionFile), stored);
}

BOOST_AUTO_TEST_SUITE_END()
