// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault19.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault19_tests, BasicTestingSetup)

static modelnet::SwarmFault19 NotedFault()
{
    modelnet::SwarmFault19 in;
    in.peer_id = "peer-1";
    in.advertised_compatible = false;
    in.actually_compatible = false;
    in.want_share = false;
    return in;
}

static void ExpectIdle(const modelnet::SwarmFault19Result& result)
{
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.connected);
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmFault19 in = NotedFault();
    in.peer_id.clear();
    in.advertised_compatible = true;
    in.actually_compatible = false;
    in.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(false_compat_is_family_not_compat_even_if_want_share)
{
    modelnet::SwarmFault19 in = NotedFault();
    in.advertised_compatible = true;
    in.actually_compatible = false;
    in.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "FAMILY_NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(false_compat_without_want_share_is_family_not_compat)
{
    modelnet::SwarmFault19 in = NotedFault();
    in.advertised_compatible = true;
    in.actually_compatible = false;
    in.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "FAMILY_NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(want_share_when_actually_compatible_is_held)
{
    modelnet::SwarmFault19 in = NotedFault();
    in.advertised_compatible = true;
    in.actually_compatible = true;
    in.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_share_when_not_advertised_is_held)
{
    modelnet::SwarmFault19 in = NotedFault();
    in.advertised_compatible = false;
    in.actually_compatible = true;
    in.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFault19 in = NotedFault();
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(matching_compat_without_share_is_noted)
{
    modelnet::SwarmFault19 in = NotedFault();
    in.advertised_compatible = true;
    in.actually_compatible = true;
    in.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmFault19Result result = modelnet::SwarmRecoverFault19(in, err);
    ExpectIdle(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
