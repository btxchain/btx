// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sighashout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sighashout_tests, BasicTestingSetup)

static modelnet::SwarmSighashOut NotedTx()
{
    modelnet::SwarmSighashOut tx;
    tx.tx_id = "tx-1";
    tx.covers_outputs = true;
    tx.want_sign = false;
    return tx;
}

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmSighashOut tx = NotedTx();
    tx.tx_id.clear();
    std::string err = "prior";
    const modelnet::SwarmSighashOutResult result = modelnet::SwarmNoteSighashOutputs(tx, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(skips_outputs_without_want_sign_is_not_signed)
{
    modelnet::SwarmSighashOut tx = NotedTx();
    tx.covers_outputs = false;
    tx.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSighashOutResult result = modelnet::SwarmNoteSighashOutputs(tx, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign_with_covers_outputs_is_held)
{
    modelnet::SwarmSighashOut tx = NotedTx();
    tx.covers_outputs = true;
    tx.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmSighashOutResult result = modelnet::SwarmNoteSighashOutputs(tx, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(covers_outputs_without_want_sign_is_noted)
{
    modelnet::SwarmSighashOut tx = NotedTx();
    tx.covers_outputs = true;
    tx.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSighashOutResult result = modelnet::SwarmNoteSighashOutputs(tx, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
