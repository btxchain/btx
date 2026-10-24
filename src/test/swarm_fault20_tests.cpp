// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault20.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault20_tests, BasicTestingSetup)

static modelnet::SwarmFault20 NotedFault()
{
    modelnet::SwarmFault20 in;
    in.coord_id = "coord-1";
    in.survivor_id = "survivor-1";
    in.durable = true;
    in.payment_claim = false;
    in.want_continue = false;
    return in;
}

static void ExpectNeverMoved(const modelnet::SwarmFault20Result& result)
{
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_coord_id_is_coord)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.coord_id.clear();
    in.durable = true;
    in.payment_claim = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(both_ids_empty_is_coord)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.coord_id.clear();
    in.survivor_id.clear();
    in.payment_claim = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(empty_survivor_with_claim_is_no_survivor)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.survivor_id.clear();
    in.durable = true;
    in.payment_claim = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "NO_SURVIVOR");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK_EQUAL(err, "NO_SURVIVOR");
}

BOOST_AUTO_TEST_CASE(empty_survivor_without_claim_is_no_survivor)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.survivor_id.clear();
    in.payment_claim = false;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "NO_SURVIVOR");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(err, "NO_SURVIVOR");
}

BOOST_AUTO_TEST_CASE(not_durable_with_claim_is_lost)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.durable = false;
    in.payment_claim = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "LOST");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(not_durable_without_claim_is_lost)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.durable = false;
    in.payment_claim = false;
    in.want_continue = false;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "LOST");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(durable_want_continue_with_claim)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.durable = true;
    in.payment_claim = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.continued);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_want_continue_without_claim)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.durable = true;
    in.payment_claim = false;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.continued);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_without_continue_with_claim_is_noted)
{
    modelnet::SwarmFault20 in = NotedFault();
    in.durable = true;
    in.payment_claim = true;
    in.want_continue = false;
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_without_continue_without_claim_is_noted)
{
    modelnet::SwarmFault20 in = NotedFault();
    std::string err = "prior";
    const modelnet::SwarmFault20Result result = modelnet::SwarmRecoverFault20(in, err);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
