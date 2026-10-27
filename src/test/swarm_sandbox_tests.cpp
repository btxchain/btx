// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandbox.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sandbox_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_helper)
{
    std::string err = "stale";
    const modelnet::SwarmSandboxStatus status = modelnet::SwarmProbeSandbox(fs::path{}, err);
    BOOST_CHECK(!status.present);
    BOOST_CHECK(!status.launched);
    BOOST_CHECK_EQUAL(status.code, "SANDBOX");
    BOOST_CHECK_EQUAL(err, "SANDBOX");
}

BOOST_AUTO_TEST_CASE(absent_helper)
{
    fs::path missing = fs::temp_directory_path();
    missing /= fs::u8path("btx-sandbox-probe-absent");
    std::string err = "stale";
    const modelnet::SwarmSandboxStatus status = modelnet::SwarmProbeSandbox(missing, err);
    BOOST_CHECK(!status.present);
    BOOST_CHECK(!status.launched);
    BOOST_CHECK_EQUAL(status.code, "SANDBOX_ABSENT");
    BOOST_CHECK_EQUAL(err, "SANDBOX_ABSENT");
}

BOOST_AUTO_TEST_CASE(installed_helper_is_not_launched)
{
    fs::path probe = fs::temp_directory_path();
    probe /= fs::u8path("btx-sandbox-probe");
    {
        std::ofstream out{probe};
        BOOST_REQUIRE(out);
        out << "sandbox-probe\n";
    }
    std::string err = "stale";
    const modelnet::SwarmSandboxStatus status = modelnet::SwarmProbeSandbox(probe, err);
    fs::remove(probe);
    BOOST_CHECK(status.present);
    BOOST_CHECK(!status.launched);
    BOOST_CHECK_EQUAL(status.code, "INSTALLED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
