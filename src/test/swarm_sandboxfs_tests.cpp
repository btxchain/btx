// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxfs.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxfs_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_root_is_path)
{
    modelnet::SwarmSandboxFs fs;
    std::string err;
    BOOST_CHECK(!fs.Allow("", "/sandbox/work/a", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!fs.allowed("/sandbox/work/a"));
    BOOST_CHECK(!fs.launched());

    err.clear();
    BOOST_CHECK(!fs.Allow("/sandbox/", "", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!fs.allowed(""));
    BOOST_CHECK(!fs.launched());
}

BOOST_AUTO_TEST_CASE(dotdot_is_escape)
{
    modelnet::SwarmSandboxFs fs;
    std::string err;
    const std::string path = "/sandbox/../etc";
    BOOST_CHECK(!fs.Allow("/sandbox/", path, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!fs.allowed(path));
    BOOST_CHECK(!fs.launched());
}

BOOST_AUTO_TEST_CASE(outside_prefix_is_escape)
{
    modelnet::SwarmSandboxFs fs;
    std::string err;
    BOOST_CHECK(!fs.Allow("/sandbox/", "/other/a", err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!fs.allowed("/other/a"));
    BOOST_CHECK(!fs.launched());

    err.clear();
    BOOST_CHECK(!fs.Allow("/sandbox/", "/sandbox-other/x", err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!fs.allowed("/sandbox-other/x"));
    BOOST_CHECK(!fs.launched());
}

BOOST_AUTO_TEST_CASE(allow_then_replay)
{
    modelnet::SwarmSandboxFs fs;
    std::string err = "stale";
    BOOST_REQUIRE(fs.Allow("/sandbox/", "/sandbox/work/a", err));
    BOOST_REQUIRE(fs.allowed("/sandbox/work/a"));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!fs.launched());

    BOOST_CHECK(!fs.Allow("/sandbox/", "/sandbox/work/a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(fs.allowed("/sandbox/work/a"));
    BOOST_CHECK(!fs.launched());
}

BOOST_AUTO_TEST_SUITE_END()
