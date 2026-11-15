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

BOOST_FIXTURE_TEST_SUITE(swarm_form_discovery_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(false_compat_is_not_admitted_and_does_not_connect)
{
    FormTree tree(m_path_root / "swarm-form-discovery-false");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    modelnet::FormationPlane plane;
    std::string err = "stale";
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));
    const std::string before = ReadFile(plane.directory() / modelnet::kMembershipFile);

    err = "stale";
    BOOST_CHECK(!plane.Discover("peer-other", "other-family", true, err));
    BOOST_CHECK_EQUAL(err, "FALSE_COMPAT");
    BOOST_CHECK(!plane.admitted("peer-other"));
    BOOST_CHECK(!plane.connects());
    BOOST_CHECK(!plane.bytes_moved());
    BOOST_CHECK_EQUAL(ReadFile(plane.directory() / modelnet::kMembershipFile), before);

    err = "stale";
    BOOST_CHECK(!plane.Claim("peer-other", 2, err));
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
    BOOST_CHECK(plane.leader().empty());
}

BOOST_AUTO_TEST_CASE(matching_family_is_admitted_without_connecting)
{
    FormTree tree(m_path_root / "swarm-form-discovery-match");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    modelnet::FormationPlane plane;
    std::string err = "stale";
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));

    err = "stale";
    BOOST_REQUIRE(plane.Discover("peer-family", modelnet::kFormationFamilyId, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.admitted("peer-family"));
    BOOST_CHECK(plane.admitted("local"));
    BOOST_CHECK(!plane.connects());
    BOOST_CHECK(!plane.launched_sidecar());
    BOOST_CHECK(plane.dns_seeds().empty());

    const std::string raw = ReadFile(plane.directory() / modelnet::kMembershipFile);
    BOOST_CHECK(raw.find("peer-family") != std::string::npos);
    BOOST_CHECK(raw.find("\"hostname\"") == std::string::npos);
    BOOST_CHECK(raw.find("\"endpoint\"") == std::string::npos);
    BOOST_CHECK(raw.find("\"ip\"") == std::string::npos);

    err = "stale";
    BOOST_REQUIRE(plane.Discover("peer-quiet", modelnet::kFormationFamilyId, false, err));
    BOOST_CHECK(plane.admitted("peer-quiet"));
    BOOST_CHECK(!plane.connects());

    modelnet::FormationPlane again;
    err = "stale";
    BOOST_REQUIRE(again.Open(model, err));
    BOOST_REQUIRE(again.Form(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(again.admitted("peer-family"));
    BOOST_CHECK(again.admitted("peer-quiet"));
    BOOST_CHECK(!again.connects());
}

BOOST_AUTO_TEST_CASE(different_family_without_compat_claim_is_not_false_compat)
{
    FormTree tree(m_path_root / "swarm-form-discovery-family");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    modelnet::FormationPlane plane;
    std::string err = "stale";
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));
    const std::string before = ReadFile(plane.directory() / modelnet::kMembershipFile);

    err = "stale";
    BOOST_CHECK(!plane.Discover("peer-apart", "apart-family", false, err));
    BOOST_CHECK_EQUAL(err, "FAMILY");
    BOOST_CHECK(!plane.admitted("peer-apart"));
    BOOST_CHECK(!plane.connects());
    BOOST_CHECK_EQUAL(ReadFile(plane.directory() / modelnet::kMembershipFile), before);
}

BOOST_AUTO_TEST_SUITE_END()
