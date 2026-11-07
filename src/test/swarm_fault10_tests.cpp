// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault10.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault10_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    modelnet::SwarmFault10 in;
    in.interrupted = true;
    in.durable = true;
    in.want_promote = true;
    std::string err = "prior";
    const modelnet::SwarmFault10Result result = modelnet::SwarmRecoverFault10(in, err);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(interrupted_is_gate_even_if_want_promote)
{
    modelnet::SwarmFault10 in;
    in.candidate_id = "cand-1";
    in.interrupted = true;
    in.durable = true;
    in.want_promote = true;
    std::string err = "prior";
    const modelnet::SwarmFault10Result result = modelnet::SwarmRecoverFault10(in, err);
    BOOST_CHECK_EQUAL(result.code, "GATE");
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "GATE");
}

BOOST_AUTO_TEST_CASE(want_promote_is_held)
{
    modelnet::SwarmFault10 in;
    in.candidate_id = "cand-1";
    in.interrupted = false;
    in.durable = true;
    in.want_promote = true;
    std::string err = "prior";
    const modelnet::SwarmFault10Result result = modelnet::SwarmRecoverFault10(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_is_recovered)
{
    modelnet::SwarmFault10 in;
    in.candidate_id = "cand-1";
    in.interrupted = false;
    in.durable = true;
    in.want_promote = false;
    std::string err = "prior";
    const modelnet::SwarmFault10Result result = modelnet::SwarmRecoverFault10(in, err);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    modelnet::SwarmFault10 in;
    in.candidate_id = "cand-1";
    std::string err = "prior";
    const modelnet::SwarmFault10Result result = modelnet::SwarmRecoverFault10(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
