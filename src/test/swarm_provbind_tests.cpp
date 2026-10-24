// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_provbind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_provbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(missing_field_is_provenance)
{
    modelnet::SwarmProvBind prov;
    std::string err = "prior";
    std::string base = "untouched";
    std::string digest = "untouched";

    BOOST_CHECK(!prov.Bind("", "base", "recipe", true, false, "digest-a", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!prov.Bind("ckpt", "", "recipe", true, false, "digest-a", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!prov.Bind("ckpt", "base", "", true, false, "digest-a", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!prov.Bind("ckpt", "base", "recipe", true, false, "", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!prov.Bind("", "base", "recipe", false, true, "", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");

    BOOST_CHECK(!prov.Bound("ckpt", base, digest));
    BOOST_CHECK_EQUAL(base, "untouched");
    BOOST_CHECK_EQUAL(digest, "untouched");
}

BOOST_AUTO_TEST_CASE(withdrawn_or_unauthorized_dataset)
{
    modelnet::SwarmProvBind prov;
    std::string err = "prior";
    std::string base = "untouched";
    std::string digest = "untouched";

    BOOST_CHECK(!prov.Bind("ckpt", "base", "recipe", true, true, "digest-a", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!prov.Bind("ckpt", "base", "recipe", false, false, "digest-a", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!prov.Bind("ckpt", "base", "recipe", false, true, "digest-a", err));
    BOOST_CHECK_EQUAL(err, "DATASET");

    BOOST_CHECK(!prov.Bound("ckpt", base, digest));
    BOOST_CHECK_EQUAL(base, "untouched");
    BOOST_CHECK_EQUAL(digest, "untouched");
}

BOOST_AUTO_TEST_CASE(successful_bind)
{
    modelnet::SwarmProvBind prov;
    std::string err = "prior";
    BOOST_REQUIRE(prov.Bind("ckpt", "base-a", "recipe-a", true, false, "digest-a", err));
    BOOST_CHECK(err.empty());

    std::string base;
    std::string digest;
    BOOST_REQUIRE(prov.Bound("ckpt", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "digest-a");

    BOOST_CHECK(!prov.Bound("other", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "digest-a");
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_digest)
{
    modelnet::SwarmProvBind prov;
    std::string err = "prior";
    BOOST_REQUIRE(prov.Bind("ckpt", "base-a", "recipe-a", true, false, "digest-a", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!prov.Bind("ckpt", "base-b", "recipe-b", true, false, "digest-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    std::string base;
    std::string digest;
    BOOST_REQUIRE(prov.Bound("ckpt", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "digest-a");

    BOOST_REQUIRE(prov.Bind("ckpt-2", "base-c", "recipe-c", true, false, "digest-c", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(prov.Bound("ckpt-2", base, digest));
    BOOST_CHECK_EQUAL(base, "base-c");
    BOOST_CHECK_EQUAL(digest, "digest-c");
    BOOST_REQUIRE(prov.Bound("ckpt", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "digest-a");
}

BOOST_AUTO_TEST_SUITE_END()
