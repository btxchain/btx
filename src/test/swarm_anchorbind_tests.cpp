// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_anchorbind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_anchorbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_checkpoint_base_or_digest_is_anchor)
{
    modelnet::SwarmAnchorBind bind;
    std::string err = "prior";
    std::string base = "untouched";
    std::string digest = "untouched";

    BOOST_CHECK(!bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "untouched");
    BOOST_CHECK_EQUAL(digest, "untouched");

    BOOST_CHECK(!bind.Bind("", "base-a", "dig-a", err));
    BOOST_CHECK_EQUAL(err, "ANCHOR");
    BOOST_CHECK(!bind.Bound("", base, digest));
    BOOST_CHECK_EQUAL(base, "untouched");
    BOOST_CHECK_EQUAL(digest, "untouched");

    BOOST_CHECK(!bind.Bind("ckpt-a", "", "dig-a", err));
    BOOST_CHECK_EQUAL(err, "ANCHOR");
    BOOST_CHECK(!bind.Bound("ckpt-a", base, digest));

    BOOST_CHECK(!bind.Bind("ckpt-a", "base-a", "", err));
    BOOST_CHECK_EQUAL(err, "ANCHOR");
    BOOST_CHECK(!bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "untouched");
    BOOST_CHECK_EQUAL(digest, "untouched");
}

BOOST_AUTO_TEST_CASE(bind_same_again_and_conflicting_base)
{
    modelnet::SwarmAnchorBind bind;
    std::string err = "prior";
    std::string base;
    std::string digest;

    BOOST_REQUIRE(bind.Bind("ckpt-a", "base-a", "dig-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "dig-a");

    err = "prior";
    BOOST_CHECK(bind.Bind("ckpt-a", "base-a", "dig-a", err));
    BOOST_CHECK(err.empty());
    base.clear();
    digest.clear();
    BOOST_REQUIRE(bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "dig-a");

    err = "prior";
    BOOST_CHECK(!bind.Bind("ckpt-a", "base-b", "dig-a", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    base.clear();
    digest.clear();
    BOOST_REQUIRE(bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "dig-a");

    err = "prior";
    BOOST_CHECK(!bind.Bind("ckpt-a", "base-a", "dig-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    base.clear();
    digest.clear();
    BOOST_REQUIRE(bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "dig-a");

    err = "prior";
    BOOST_CHECK(bind.Bind("ckpt-a", "base-a", "dig-a", err));
    BOOST_CHECK(err.empty());

    BOOST_REQUIRE(bind.Bind("ckpt-b", "base-b", "dig-b", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(bind.Bound("ckpt-b", base, digest));
    BOOST_CHECK_EQUAL(base, "base-b");
    BOOST_CHECK_EQUAL(digest, "dig-b");
    BOOST_REQUIRE(bind.Bound("ckpt-a", base, digest));
    BOOST_CHECK_EQUAL(base, "base-a");
    BOOST_CHECK_EQUAL(digest, "dig-a");
}

BOOST_AUTO_TEST_SUITE_END()
