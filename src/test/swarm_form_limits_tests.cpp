// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/limits.h>
#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_form/types.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <filesystem>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(swarm_form_limits_tests, BasicTestingSetup)

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

bool DirectoryHasSeed(const fs::path& swarm)
{
    std::error_code ec;
    for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(swarm, ec)) {
        if (ec) return false;
        const fs::path child(entry.path());
        const std::string name = child.filename().utf8string();
        if (name.find("dns") != std::string::npos || name.find("seed") != std::string::npos) return true;
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_CASE(limits_stay_closed_before_any_form)
{
    modelnet::SwarmFormLimits limits;
    BOOST_CHECK(!limits.bytes_moved());
    BOOST_CHECK(!limits.launched_sidecar());
    BOOST_CHECK(limits.dns_seeds().empty());

    modelnet::FormationPlane plane;
    BOOST_CHECK(!plane.bytes_moved());
    BOOST_CHECK(!plane.launched_sidecar());
    BOOST_CHECK(plane.dns_seeds().empty());
    BOOST_CHECK(!plane.connects());
}

BOOST_AUTO_TEST_CASE(form_discover_and_claim_still_move_nothing)
{
    FormTree tree(m_path_root / "swarm-form-limits-ops");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    modelnet::FormationPlane plane;
    std::string err = "stale";
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));
    BOOST_REQUIRE(plane.Claim("local", 1, err));
    BOOST_REQUIRE(plane.Discover("peer-family", modelnet::kFormationFamilyId, true, err));
    BOOST_CHECK(!plane.Discover("peer-other", "other-family", true, err));

    BOOST_CHECK(!plane.bytes_moved());
    BOOST_CHECK(!plane.launched_sidecar());
    BOOST_CHECK(plane.dns_seeds().empty());
    BOOST_CHECK(!plane.connects());
    BOOST_CHECK(!DirectoryHasSeed(plane.directory()));
    BOOST_CHECK_EQUAL(plane.membership().automatic_spend, "0");
    BOOST_CHECK(!plane.membership().training);
    BOOST_CHECK(!plane.membership().private_prompts);
}

BOOST_AUTO_TEST_SUITE_END()
