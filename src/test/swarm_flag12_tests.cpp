// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag12.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag12_tests, BasicTestingSetup)

static modelnet::SwarmFlag12 Ready()
{
    modelnet::SwarmFlag12 in;
    in.survivor_id = "survivor-1";
    in.work_id = "work-1";
    in.durable = true;
    in.payment_claim = false;
    in.want_continue = false;
    in.want_pass = false;
    return in;
}

static void CheckStill(const modelnet::SwarmFlag12Result& result)
{
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_survivor_id_is_node)
{
    modelnet::SwarmFlag12 in = Ready();
    in.survivor_id.clear();
    in.payment_claim = true;
    in.durable = true;
    in.want_continue = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result result = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    CheckStill(result);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(empty_work_id_is_node)
{
    modelnet::SwarmFlag12 in = Ready();
    in.work_id.clear();
    in.payment_claim = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result result = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    CheckStill(result);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(both_ids_empty_is_node)
{
    modelnet::SwarmFlag12 in = Ready();
    in.survivor_id.clear();
    in.work_id.clear();
    in.payment_claim = false;
    in.durable = true;
    in.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result result = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.continued);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    CheckStill(result);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag12 in = Ready();
    in.want_pass = true;
    in.want_continue = true;
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result claimed = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "UNQUALIFIED");
    BOOST_CHECK(!claimed.continued);
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    CheckStill(claimed);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");

    in.payment_claim = false;
    in.durable = false;
    err = "prior";
    const modelnet::SwarmFlag12Result bare = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(bare.code, "UNQUALIFIED");
    BOOST_CHECK(!bare.continued);
    BOOST_CHECK(!bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    CheckStill(bare);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(not_durable_is_lost)
{
    modelnet::SwarmFlag12 in = Ready();
    in.durable = false;
    in.want_continue = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result claimed = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "LOST");
    BOOST_CHECK(!claimed.continued);
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    CheckStill(claimed);
    BOOST_CHECK_EQUAL(err, "LOST");

    in.payment_claim = false;
    in.want_continue = false;
    err = "prior";
    const modelnet::SwarmFlag12Result bare = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(bare.code, "LOST");
    BOOST_CHECK(!bare.continued);
    BOOST_CHECK(!bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    CheckStill(bare);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(want_continue_is_durable)
{
    modelnet::SwarmFlag12 in = Ready();
    in.durable = true;
    in.want_continue = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result claimed = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "DURABLE");
    BOOST_CHECK(claimed.continued);
    BOOST_CHECK(claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    CheckStill(claimed);
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFlag12Result bare = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(bare.code, "DURABLE");
    BOOST_CHECK(bare.continued);
    BOOST_CHECK(bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    CheckStill(bare);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    modelnet::SwarmFlag12 in = Ready();
    in.durable = true;
    in.want_continue = false;
    in.want_pass = false;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFlag12Result claimed = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "NOTED");
    BOOST_CHECK(!claimed.continued);
    BOOST_CHECK(claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    CheckStill(claimed);
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFlag12Result bare = modelnet::SwarmStageRecover(in, err);
    BOOST_CHECK_EQUAL(bare.code, "NOTED");
    BOOST_CHECK(!bare.continued);
    BOOST_CHECK(bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    CheckStill(bare);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
