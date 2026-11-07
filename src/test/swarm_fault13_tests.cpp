// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault13.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault13_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_earn_id_is_earn)
{
    modelnet::SwarmFault13 in;
    in.earned = true;
    in.durable = true;
    in.payment_claim = true;
    in.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmFault13Result result = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(result.code, "EARN");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK_EQUAL(err, "EARN");
}

BOOST_AUTO_TEST_CASE(want_settle_is_held)
{
    modelnet::SwarmFault13 in;
    in.earn_id = "earn-1";
    in.earned = true;
    in.durable = true;
    in.payment_claim = true;
    in.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmFault13Result claimed = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "HELD");
    BOOST_CHECK(!claimed.settled);
    BOOST_CHECK(!claimed.broadcast);
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK(!claimed.committed);
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    in.earned = true;
    in.durable = false;
    err = "prior";
    const modelnet::SwarmFault13Result unclaimed = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(unclaimed.code, "HELD");
    BOOST_CHECK(!unclaimed.settled);
    BOOST_CHECK(!unclaimed.broadcast);
    BOOST_CHECK(!unclaimed.recovered);
    BOOST_CHECK(!unclaimed.payment_preserved);
    BOOST_CHECK(!unclaimed.committed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(earned_not_durable_is_lost)
{
    modelnet::SwarmFault13 in;
    in.earn_id = "earn-1";
    in.earned = true;
    in.durable = false;
    in.payment_claim = true;
    in.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmFault13Result claimed = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "LOST");
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK(!claimed.settled);
    BOOST_CHECK(!claimed.broadcast);
    BOOST_CHECK(!claimed.committed);
    BOOST_CHECK_EQUAL(err, "LOST");

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault13Result unclaimed = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(unclaimed.code, "LOST");
    BOOST_CHECK(!unclaimed.recovered);
    BOOST_CHECK(!unclaimed.payment_preserved);
    BOOST_CHECK(!unclaimed.settled);
    BOOST_CHECK(!unclaimed.broadcast);
    BOOST_CHECK(!unclaimed.committed);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(earned_and_durable_is_earned)
{
    modelnet::SwarmFault13 in;
    in.earn_id = "earn-1";
    in.earned = true;
    in.durable = true;
    in.payment_claim = false;
    in.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmFault13Result without_claim = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(without_claim.code, "EARNED");
    BOOST_CHECK(without_claim.recovered);
    BOOST_CHECK(without_claim.payment_preserved);
    BOOST_CHECK(!without_claim.settled);
    BOOST_CHECK(!without_claim.broadcast);
    BOOST_CHECK(!without_claim.committed);
    BOOST_CHECK(err.empty());

    in.payment_claim = true;
    err = "prior";
    const modelnet::SwarmFault13Result with_claim = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(with_claim.code, "EARNED");
    BOOST_CHECK(with_claim.recovered);
    BOOST_CHECK(with_claim.payment_preserved);
    BOOST_CHECK(!with_claim.settled);
    BOOST_CHECK(!with_claim.broadcast);
    BOOST_CHECK(!with_claim.committed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    modelnet::SwarmFault13 in;
    in.earn_id = "earn-1";
    in.earned = false;
    in.durable = false;
    in.payment_claim = true;
    in.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmFault13Result claimed = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(claimed.code, "NOTED");
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK(!claimed.settled);
    BOOST_CHECK(!claimed.broadcast);
    BOOST_CHECK(!claimed.committed);
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    in.durable = true;
    err = "prior";
    const modelnet::SwarmFault13Result durable_without_earn = modelnet::SwarmRecoverFault13(in, err);
    BOOST_CHECK_EQUAL(durable_without_earn.code, "NOTED");
    BOOST_CHECK(!durable_without_earn.recovered);
    BOOST_CHECK(!durable_without_earn.payment_preserved);
    BOOST_CHECK(!durable_without_earn.settled);
    BOOST_CHECK(!durable_without_earn.broadcast);
    BOOST_CHECK(!durable_without_earn.committed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
