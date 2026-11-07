// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_headpin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_headpin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(incompatible_follow_leaves_base)
{
    modelnet::SwarmHeadPin pin;
    BOOST_CHECK_EQUAL(pin.active(), "base");

    std::string err = "prior";
    BOOST_CHECK(!pin.Follow(false, err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(!pin.Stage("", err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(pin.Stage("cand-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(!pin.Follow(false, err));
    BOOST_CHECK_EQUAL(err, "LOCAL_INCOMPATIBLE");
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(!pin.Follow(false, err));
    BOOST_CHECK_EQUAL(err, "LOCAL_INCOMPATIBLE");
    BOOST_CHECK_EQUAL(pin.active(), "base");
}

BOOST_AUTO_TEST_CASE(pin_leaves_base)
{
    modelnet::SwarmHeadPin pin;
    std::string err = "prior";
    BOOST_CHECK(!pin.Pin(err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(pin.active(), "base");

    BOOST_CHECK(pin.Stage("cand-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(pin.Pin(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(!pin.Follow(true, err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(pin.active(), "base");
}

BOOST_AUTO_TEST_CASE(compatible_follow_changes_active)
{
    modelnet::SwarmHeadPin pin;
    std::string err = "prior";
    BOOST_CHECK(pin.Stage("cand-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "base");

    err = "prior";
    BOOST_CHECK(pin.Follow(true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(!pin.Follow(true, err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(pin.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(pin.Stage("cand-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(pin.Pin(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pin.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(!pin.Follow(true, err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(pin.active(), "cand-a");
}

BOOST_AUTO_TEST_SUITE_END()
