// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault01.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault01_tests, BasicTestingSetup)

static modelnet::SwarmFault01 NotedWork()
{
    modelnet::SwarmFault01 in;
    in.coord_id = "coord-1";
    in.work_id = "work-1";
    in.pending = false;
    in.durable = false;
    in.payment_claim = false;
    in.want_commit = false;
    in.want_reassign = false;
    return in;
}

static void ExpectNoSpend(const modelnet::SwarmFault01Result& result)
{
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_coord_id_is_coord)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.coord_id.clear();
    in.payment_claim = true;
    in.want_commit = true;
    in.pending = true;
    in.durable = true;
    in.want_reassign = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(empty_work_id_is_coord)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.work_id.clear();
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(both_ids_empty_is_coord)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.coord_id.clear();
    in.work_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(want_commit_is_stale_and_preserves_payment)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.want_commit = true;
    in.payment_claim = true;
    in.pending = true;
    in.durable = false;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(want_commit_without_payment_claim_is_stale)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.want_commit = true;
    in.payment_claim = false;
    in.durable = true;
    in.want_reassign = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(pending_not_durable_is_lost_and_preserves_payment)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.pending = true;
    in.durable = false;
    in.payment_claim = true;
    in.want_reassign = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "LOST");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(pending_not_durable_without_payment_claim_is_lost)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.pending = true;
    in.durable = false;
    in.payment_claim = false;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "LOST");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(durable_want_reassign_is_reassigned_and_preserves_payment)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.durable = true;
    in.want_reassign = true;
    in.payment_claim = true;
    in.pending = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "REASSIGNED");
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(result.reassigned);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_want_reassign_without_payment_claim)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.durable = true;
    in.want_reassign = true;
    in.payment_claim = false;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "REASSIGNED");
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(result.reassigned);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_is_durable_and_preserves_payment)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.durable = true;
    in.want_reassign = false;
    in.payment_claim = true;
    in.pending = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_without_payment_claim)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.durable = true;
    in.payment_claim = false;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFault01 in = NotedWork();
    in.payment_claim = true;
    in.want_reassign = true;
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_without_payment_claim_is_noted)
{
    modelnet::SwarmFault01 in = NotedWork();
    std::string err = "prior";
    const modelnet::SwarmFault01Result result = modelnet::SwarmRecoverFault01(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.reassigned);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoSpend(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
