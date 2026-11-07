// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault09.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_fault09_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_artifact_id)
{
    std::string err = "prior";
    modelnet::SwarmFault09 in;
    in.artifact_id.clear();
    in.complete = true;
    in.want_accept = true;
    const modelnet::SwarmFault09Result out = modelnet::SwarmRecoverFault09(in, err);
    BOOST_CHECK_EQUAL(out.code, "ARTIFACT");
    BOOST_CHECK(!out.accepted);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
}

BOOST_AUTO_TEST_CASE(incomplete_even_when_want_accept)
{
    std::string err = "prior";
    modelnet::SwarmFault09 want;
    want.artifact_id = "artifact-9";
    want.complete = false;
    want.want_accept = true;
    const modelnet::SwarmFault09Result held_back = modelnet::SwarmRecoverFault09(want, err);
    BOOST_CHECK_EQUAL(held_back.code, "INCOMPLETE");
    BOOST_CHECK(!held_back.accepted);
    BOOST_CHECK(!held_back.bytes_moved);
    BOOST_CHECK(!held_back.committed);
    BOOST_CHECK(!held_back.broadcast);
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");

    modelnet::SwarmFault09 plain;
    plain.artifact_id = "artifact-9";
    plain.complete = false;
    plain.want_accept = false;
    const modelnet::SwarmFault09Result noted = modelnet::SwarmRecoverFault09(plain, err);
    BOOST_CHECK_EQUAL(noted.code, "INCOMPLETE");
    BOOST_CHECK(!noted.accepted);
    BOOST_CHECK(!noted.bytes_moved);
    BOOST_CHECK(!noted.committed);
    BOOST_CHECK(!noted.broadcast);
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(want_accept_is_held)
{
    std::string err = "prior";
    modelnet::SwarmFault09 in;
    in.artifact_id = "artifact-9";
    in.complete = true;
    in.want_accept = true;
    const modelnet::SwarmFault09Result out = modelnet::SwarmRecoverFault09(in, err);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK(!out.accepted);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(complete_without_accept_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmFault09 in;
    in.artifact_id = "artifact-9";
    in.complete = true;
    in.want_accept = false;
    const modelnet::SwarmFault09Result out = modelnet::SwarmRecoverFault09(in, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.accepted);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
