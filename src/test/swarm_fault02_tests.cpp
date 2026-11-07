// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault02.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault02_tests, BasicTestingSetup)

static modelnet::SwarmFault02 Ready()
{
    modelnet::SwarmFault02 in;
    in.lease_id = "lease-1";
    in.old_epoch = "epoch-old";
    in.new_epoch = "epoch-new";
    in.lease_expired = true;
    in.durable = false;
    in.payment_claim = false;
    in.want_commit = false;
    return in;
}

static void CheckIdle(const modelnet::SwarmFault02Result& result)
{
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_lease_id_is_lease)
{
    modelnet::SwarmFault02 in = Ready();
    in.lease_id.clear();
    in.payment_claim = true;
    in.want_commit = true;
    in.durable = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result result = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(result);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(result.code, "LEASE");
    BOOST_CHECK_EQUAL(err, "LEASE");
}

BOOST_AUTO_TEST_CASE(empty_old_epoch_is_lease)
{
    modelnet::SwarmFault02 in = Ready();
    in.old_epoch.clear();
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result result = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(result);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(result.code, "LEASE");
    BOOST_CHECK_EQUAL(err, "LEASE");
}

BOOST_AUTO_TEST_CASE(empty_new_epoch_is_lease)
{
    modelnet::SwarmFault02 in = Ready();
    in.new_epoch.clear();
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result result = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(result);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(result.code, "LEASE");
    BOOST_CHECK_EQUAL(err, "LEASE");
}

BOOST_AUTO_TEST_CASE(want_commit_is_stale)
{
    modelnet::SwarmFault02 in = Ready();
    in.want_commit = true;
    in.payment_claim = true;
    in.lease_expired = false;
    std::string err = "prior";
    const modelnet::SwarmFault02Result claimed = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(claimed);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault02Result bare = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(bare);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(unexpired_lease_is_held)
{
    modelnet::SwarmFault02 in = Ready();
    in.lease_expired = false;
    in.new_epoch = in.old_epoch;
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result claimed = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(claimed);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "HELD");
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault02Result bare = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(bare);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(same_epoch_is_same_epoch)
{
    modelnet::SwarmFault02 in = Ready();
    in.new_epoch = in.old_epoch;
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result claimed = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(claimed);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "SAME_EPOCH");
    BOOST_CHECK_EQUAL(err, "SAME_EPOCH");

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault02Result bare = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(bare);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "SAME_EPOCH");
    BOOST_CHECK_EQUAL(err, "SAME_EPOCH");
}

BOOST_AUTO_TEST_CASE(durable_expired_replacement_is_replaced)
{
    modelnet::SwarmFault02 in = Ready();
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result claimed = modelnet::SwarmRecoverFault02(in, err);
    BOOST_CHECK(!claimed.committed);
    BOOST_CHECK(claimed.replaced);
    BOOST_CHECK(claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK(!claimed.bytes_moved);
    BOOST_CHECK(!claimed.broadcast);
    BOOST_CHECK_EQUAL(claimed.code, "REPLACED");
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault02Result bare = modelnet::SwarmRecoverFault02(in, err);
    BOOST_CHECK(!bare.committed);
    BOOST_CHECK(bare.replaced);
    BOOST_CHECK(bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK(!bare.bytes_moved);
    BOOST_CHECK(!bare.broadcast);
    BOOST_CHECK_EQUAL(bare.code, "REPLACED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(expired_without_durable_is_lost)
{
    modelnet::SwarmFault02 in = Ready();
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault02Result claimed = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(claimed);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "LOST");
    BOOST_CHECK_EQUAL(err, "LOST");

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault02Result bare = modelnet::SwarmRecoverFault02(in, err);
    CheckIdle(bare);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "LOST");
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_SUITE_END()
