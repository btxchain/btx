// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault05.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

modelnet::SwarmFault05 Fault(std::string worker_id, std::string work_id, bool result_sent, bool durable, bool payment_claim, bool want_reassign)
{
    modelnet::SwarmFault05 in;
    in.worker_id = std::move(worker_id);
    in.work_id = std::move(work_id);
    in.result_sent = result_sent;
    in.durable = durable;
    in.payment_claim = payment_claim;
    in.want_reassign = want_reassign;
    return in;
}

void ExpectStill(const modelnet::SwarmFault05Result& out)
{
    BOOST_CHECK(!out.committed);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.broadcast);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_fault05_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_worker_or_work_is_worker)
{
    std::string err = "prior";
    const modelnet::SwarmFault05Result no_worker = modelnet::SwarmRecoverFault05(
        Fault("", "work", true, true, true, true), err);
    BOOST_CHECK_EQUAL(no_worker.code, "WORKER");
    BOOST_CHECK(!no_worker.committed);
    BOOST_CHECK(!no_worker.reassigned);
    BOOST_CHECK(!no_worker.recovered);
    BOOST_CHECK(!no_worker.payment_preserved);
    BOOST_CHECK(!no_worker.bytes_moved);
    BOOST_CHECK(!no_worker.broadcast);
    BOOST_CHECK_EQUAL(err, "WORKER");

    err = "prior";
    const modelnet::SwarmFault05Result no_work = modelnet::SwarmRecoverFault05(
        Fault("worker", "", true, true, true, true), err);
    BOOST_CHECK_EQUAL(no_work.code, "WORKER");
    BOOST_CHECK(!no_work.reassigned);
    BOOST_CHECK(!no_work.recovered);
    BOOST_CHECK(!no_work.payment_preserved);
    ExpectStill(no_work);
    BOOST_CHECK_EQUAL(err, "WORKER");

    err = "prior";
    const modelnet::SwarmFault05Result neither = modelnet::SwarmRecoverFault05(
        Fault("", "", false, false, false, false), err);
    BOOST_CHECK_EQUAL(neither.code, "WORKER");
    BOOST_CHECK(!neither.payment_preserved);
    ExpectStill(neither);
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(result_sent_without_durable_is_lost)
{
    std::string err = "prior";
    const modelnet::SwarmFault05Result claimed = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", true, false, true, true), err);
    BOOST_CHECK_EQUAL(claimed.code, "LOST");
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(!claimed.reassigned);
    BOOST_CHECK(claimed.payment_preserved);
    ExpectStill(claimed);
    BOOST_CHECK_EQUAL(err, "LOST");

    err = "prior";
    const modelnet::SwarmFault05Result unclaimed = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", true, false, false, false), err);
    BOOST_CHECK_EQUAL(unclaimed.code, "LOST");
    BOOST_CHECK(!unclaimed.recovered);
    BOOST_CHECK(!unclaimed.reassigned);
    BOOST_CHECK(!unclaimed.payment_preserved);
    ExpectStill(unclaimed);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(durable_want_reassign_is_reassigned)
{
    std::string err = "prior";
    const modelnet::SwarmFault05Result after_result = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", true, true, true, true), err);
    BOOST_CHECK_EQUAL(after_result.code, "REASSIGNED");
    BOOST_CHECK(after_result.recovered);
    BOOST_CHECK(after_result.reassigned);
    BOOST_CHECK(!after_result.committed);
    BOOST_CHECK(after_result.payment_preserved);
    ExpectStill(after_result);
    BOOST_CHECK(err.empty());

    err = "prior";
    const modelnet::SwarmFault05Result before_result = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", false, true, false, true), err);
    BOOST_CHECK_EQUAL(before_result.code, "REASSIGNED");
    BOOST_CHECK(before_result.recovered);
    BOOST_CHECK(before_result.reassigned);
    BOOST_CHECK(!before_result.payment_preserved);
    ExpectStill(before_result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(result_sent_and_durable_is_durable)
{
    std::string err = "prior";
    const modelnet::SwarmFault05Result claimed = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", true, true, true, false), err);
    BOOST_CHECK_EQUAL(claimed.code, "DURABLE");
    BOOST_CHECK(claimed.recovered);
    BOOST_CHECK(!claimed.reassigned);
    BOOST_CHECK(!claimed.committed);
    BOOST_CHECK(claimed.payment_preserved);
    ExpectStill(claimed);
    BOOST_CHECK(err.empty());

    err = "prior";
    const modelnet::SwarmFault05Result unclaimed = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", true, true, false, false), err);
    BOOST_CHECK_EQUAL(unclaimed.code, "DURABLE");
    BOOST_CHECK(unclaimed.recovered);
    BOOST_CHECK(!unclaimed.reassigned);
    BOOST_CHECK(!unclaimed.payment_preserved);
    ExpectStill(unclaimed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    std::string err = "prior";
    const modelnet::SwarmFault05Result idle = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", false, false, true, true), err);
    BOOST_CHECK_EQUAL(idle.code, "NOTED");
    BOOST_CHECK(!idle.recovered);
    BOOST_CHECK(!idle.reassigned);
    BOOST_CHECK(idle.payment_preserved);
    ExpectStill(idle);
    BOOST_CHECK(err.empty());

    err = "prior";
    const modelnet::SwarmFault05Result durable_kept = modelnet::SwarmRecoverFault05(
        Fault("worker", "work", false, true, false, false), err);
    BOOST_CHECK_EQUAL(durable_kept.code, "NOTED");
    BOOST_CHECK(!durable_kept.recovered);
    BOOST_CHECK(!durable_kept.reassigned);
    BOOST_CHECK(!durable_kept.payment_preserved);
    ExpectStill(durable_kept);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
