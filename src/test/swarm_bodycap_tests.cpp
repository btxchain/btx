// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodycap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_bodycap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_id_is_body)
{
    modelnet::SwarmBodyCap body;
    body.body_id.clear();
    body.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmBodyCapResult result = modelnet::SwarmKeepBodyCap(body, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(33554432));
    BOOST_CHECK_EQUAL(result.code, "BODY");
    BOOST_CHECK_EQUAL(err, "BODY");
}

BOOST_AUTO_TEST_CASE(want_raise_is_held)
{
    modelnet::SwarmBodyCap body;
    body.body_id = "body-a";
    body.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmBodyCapResult result = modelnet::SwarmKeepBodyCap(body, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(33554432));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_raise_false_is_noted)
{
    modelnet::SwarmBodyCap body;
    body.body_id = "body-b";
    body.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmBodyCapResult result = modelnet::SwarmKeepBodyCap(body, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(33554432));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
