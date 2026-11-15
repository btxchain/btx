// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifestok.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_manifestok_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(missing_child_digest_is_refused)
{
    modelnet::SwarmManifestOk manifest;
    std::string err = "prior";

    BOOST_CHECK(!manifest.usable("root-a"));
    BOOST_CHECK(!manifest.bytes_streamed());

    BOOST_CHECK(!manifest.Bind("root-a", {"aa", "bb"}, {"aa"}, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!manifest.usable("root-a"));
    BOOST_CHECK(!manifest.bytes_streamed());

    err = "prior";
    BOOST_CHECK(!manifest.Bind("", {"aa"}, {"aa"}, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!manifest.usable(""));
    BOOST_CHECK(!manifest.bytes_streamed());

    err = "prior";
    BOOST_CHECK(!manifest.Bind("root-empty", {}, {}, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!manifest.usable("root-empty"));
    BOOST_CHECK(!manifest.bytes_streamed());
}

BOOST_AUTO_TEST_CASE(fully_verified_root_is_usable)
{
    modelnet::SwarmManifestOk manifest;
    std::string err = "prior";

    BOOST_REQUIRE(manifest.Bind("root-a", {"aa", "bb"}, {"bb", "aa", "cc"}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.usable("root-a"));
    BOOST_CHECK(!manifest.usable("root-b"));
    BOOST_CHECK(!manifest.bytes_streamed());

    err = "prior";
    BOOST_CHECK(!manifest.Bind("root-a", {"aa", "bb"}, {"aa", "bb"}, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(manifest.usable("root-a"));
    BOOST_CHECK(!manifest.bytes_streamed());

    err = "prior";
    BOOST_REQUIRE(manifest.Bind("root-b", {"dd"}, {"dd"}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.usable("root-a"));
    BOOST_CHECK(manifest.usable("root-b"));
    BOOST_CHECK(!manifest.bytes_streamed());
}

BOOST_AUTO_TEST_CASE(bytes_streamed_stays_false)
{
    modelnet::SwarmManifestOk manifest;
    std::string err = "prior";

    BOOST_CHECK(!manifest.bytes_streamed());
    BOOST_CHECK(!manifest.Bind("root-a", {"aa", "bb"}, {"bb"}, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!manifest.usable("root-a"));
    BOOST_CHECK(!manifest.bytes_streamed());

    BOOST_REQUIRE(manifest.Bind("root-a", {"aa", "bb"}, {"aa", "bb"}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.usable("root-a"));
    BOOST_CHECK(!manifest.bytes_streamed());
}

BOOST_AUTO_TEST_SUITE_END()
