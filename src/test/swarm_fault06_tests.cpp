// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault06.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault06_tests, BasicTestingSetup)

static modelnet::SwarmFault06 FreshReceipt()
{
    modelnet::SwarmFault06 in;
    in.receipt_id = "receipt-1";
    in.seen_before = false;
    in.durable = false;
    in.payment_claim = false;
    in.want_accept = false;
    return in;
}

static void ExpectNoAccept(const modelnet::SwarmFault06Result& result)
{
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.receipt_id.clear();
    in.seen_before = true;
    in.durable = true;
    in.payment_claim = true;
    in.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(seen_before_durable_is_replay_and_preserves_payment)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.seen_before = true;
    in.durable = true;
    in.payment_claim = true;
    in.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "REPLAY");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "REPLAY");
}

BOOST_AUTO_TEST_CASE(seen_before_without_durable_or_payment_is_replay)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.seen_before = true;
    in.durable = false;
    in.payment_claim = false;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "REPLAY");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "REPLAY");
}

BOOST_AUTO_TEST_CASE(want_accept_is_held_and_preserves_payment)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.want_accept = true;
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_accept_without_payment_claim_is_held)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.want_accept = true;
    in.payment_claim = false;
    in.durable = true;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_is_durable_and_preserves_payment)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_without_payment_claim)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.durable = true;
    in.payment_claim = false;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_receipt_is_noted)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_receipt_without_payment_claim_is_noted)
{
    modelnet::SwarmFault06 in = FreshReceipt();
    std::string err = "prior";
    const modelnet::SwarmFault06Result result = modelnet::SwarmRecoverFault06(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
