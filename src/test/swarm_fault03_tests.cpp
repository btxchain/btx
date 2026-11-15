// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault03.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault03_tests, BasicTestingSetup)

static modelnet::SwarmFault03 Ready()
{
    modelnet::SwarmFault03 in;
    in.epoch_id = "epoch-1";
    in.current_epoch = "epoch-1";
    in.durable = false;
    in.payment_claim = false;
    in.want_commit = false;
    return in;
}

static void CheckQuiet(const modelnet::SwarmFault03Result& result)
{
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_epoch_id_is_epoch)
{
    modelnet::SwarmFault03 in = Ready();
    in.epoch_id.clear();
    in.current_epoch = "epoch-now";
    in.durable = true;
    in.payment_claim = true;
    in.want_commit = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result result = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(result);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(result.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");
}

BOOST_AUTO_TEST_CASE(empty_current_epoch_is_epoch)
{
    modelnet::SwarmFault03 in = Ready();
    in.current_epoch.clear();
    in.durable = true;
    in.payment_claim = true;
    in.want_commit = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result result = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(result);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(result.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");
}

BOOST_AUTO_TEST_CASE(both_epochs_empty_is_epoch)
{
    modelnet::SwarmFault03 in = Ready();
    in.epoch_id.clear();
    in.current_epoch.clear();
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result result = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(result);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.payment_preserved);
    BOOST_CHECK_EQUAL(result.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");
}

BOOST_AUTO_TEST_CASE(mismatched_epoch_is_stale)
{
    modelnet::SwarmFault03 in = Ready();
    in.epoch_id = "epoch-old";
    in.current_epoch = "epoch-now";
    in.durable = true;
    in.want_commit = false;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result claimed = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(claimed);
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault03Result bare = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(bare);
    BOOST_CHECK(!bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(want_commit_is_stale)
{
    modelnet::SwarmFault03 in = Ready();
    in.want_commit = true;
    in.durable = true;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result claimed = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(claimed);
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault03Result bare = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(bare);
    BOOST_CHECK(!bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(durable_matching_epoch_is_durable)
{
    modelnet::SwarmFault03 in = Ready();
    in.durable = true;
    in.want_commit = false;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result claimed = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(claimed);
    BOOST_CHECK(claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "DURABLE");
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault03Result bare = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(bare);
    BOOST_CHECK(bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "DURABLE");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(matching_epoch_without_durable_is_noted)
{
    modelnet::SwarmFault03 in = Ready();
    in.durable = false;
    in.want_commit = false;
    in.payment_claim = true;
    std::string err = "prior";
    const modelnet::SwarmFault03Result claimed = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(claimed);
    BOOST_CHECK(!claimed.recovered);
    BOOST_CHECK(claimed.payment_preserved);
    BOOST_CHECK_EQUAL(claimed.code, "NOTED");
    BOOST_CHECK(err.empty());

    in.payment_claim = false;
    err = "prior";
    const modelnet::SwarmFault03Result bare = modelnet::SwarmRecoverFault03(in, err);
    CheckQuiet(bare);
    BOOST_CHECK(!bare.recovered);
    BOOST_CHECK(!bare.payment_preserved);
    BOOST_CHECK_EQUAL(bare.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
