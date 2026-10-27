// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag11.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag11_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_invoice_id)
{
    modelnet::SwarmFlag11 in;
    in.regtest = true;
    in.want_settle = true;
    in.want_mine = true;
    in.want_pass = true;
    std::string err = "stale";
    const modelnet::SwarmFlag11Result result = modelnet::SwarmStagePay(in, err);
    BOOST_CHECK_EQUAL(result.code, "INVOICE");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.txid.empty());
    BOOST_CHECK_EQUAL(err, "INVOICE");
}

BOOST_AUTO_TEST_CASE(not_regtest)
{
    modelnet::SwarmFlag11 in;
    in.invoice_id = "inv-a";
    in.want_settle = true;
    in.want_mine = true;
    in.want_pass = true;
    std::string err = "stale";
    const modelnet::SwarmFlag11Result result = modelnet::SwarmStagePay(in, err);
    BOOST_CHECK_EQUAL(result.code, "MAINNET");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.txid.empty());
    BOOST_CHECK_EQUAL(err, "MAINNET");
}

BOOST_AUTO_TEST_CASE(want_mine_refused)
{
    modelnet::SwarmFlag11 in;
    in.invoice_id = "inv-a";
    in.regtest = true;
    in.want_settle = true;
    in.want_mine = true;
    in.want_pass = true;
    std::string err = "stale";
    const modelnet::SwarmFlag11Result result = modelnet::SwarmStagePay(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_MINED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.txid.empty());
    BOOST_CHECK_EQUAL(err, "NOT_MINED");
}

BOOST_AUTO_TEST_CASE(want_settle_unbroadcast)
{
    modelnet::SwarmFlag11 in;
    in.invoice_id = "inv-a";
    in.regtest = true;
    in.want_settle = true;
    in.want_pass = true;
    std::string err = "stale";
    const modelnet::SwarmFlag11Result result = modelnet::SwarmStagePay(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.txid.empty());
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_pass_unqualified)
{
    modelnet::SwarmFlag11 in;
    in.invoice_id = "inv-a";
    in.regtest = true;
    in.want_pass = true;
    std::string err = "stale";
    const modelnet::SwarmFlag11Result result = modelnet::SwarmStagePay(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.txid.empty());
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmFlag11 in;
    in.invoice_id = "inv-a";
    in.regtest = true;
    std::string err = "stale";
    const modelnet::SwarmFlag11Result result = modelnet::SwarmStagePay(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.txid.empty());
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
