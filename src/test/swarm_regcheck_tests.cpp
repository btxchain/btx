// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_regcheck.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_regcheck_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_check)
{
    modelnet::SwarmRegCheck check;
    check.check_id.clear();
    check.script_present = true;
    check.utxo_known = true;
    check.want_mine = false;
    check.want_broadcast = false;
    std::string err{"stale"};
    const modelnet::SwarmRegCheckResult result = modelnet::SwarmCheckRegtest(check, err);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
    BOOST_CHECK_EQUAL(result.script_ok, false);
}

BOOST_AUTO_TEST_CASE(script_missing)
{
    modelnet::SwarmRegCheck check;
    check.check_id = "reg-script";
    check.script_present = false;
    check.utxo_known = true;
    check.want_mine = false;
    check.want_broadcast = false;
    std::string err{"stale"};
    const modelnet::SwarmRegCheckResult result = modelnet::SwarmCheckRegtest(check, err);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "SCRIPT");
    BOOST_CHECK_EQUAL(err, "SCRIPT");
    BOOST_CHECK_EQUAL(result.script_ok, false);
}

BOOST_AUTO_TEST_CASE(utxo_unknown)
{
    modelnet::SwarmRegCheck check;
    check.check_id = "reg-utxo";
    check.script_present = true;
    check.utxo_known = false;
    check.want_mine = false;
    check.want_broadcast = false;
    std::string err{"stale"};
    const modelnet::SwarmRegCheckResult result = modelnet::SwarmCheckRegtest(check, err);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "UTXO");
    BOOST_CHECK_EQUAL(err, "UTXO");
    BOOST_CHECK_EQUAL(result.script_ok, false);
}

BOOST_AUTO_TEST_CASE(want_mine_held)
{
    modelnet::SwarmRegCheck check;
    check.check_id = "reg-held";
    check.script_present = true;
    check.utxo_known = true;
    check.want_mine = true;
    check.want_broadcast = false;
    std::string err{"stale"};
    const modelnet::SwarmRegCheckResult result = modelnet::SwarmCheckRegtest(check, err);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.script_ok, true);
}

BOOST_AUTO_TEST_CASE(neither_want_noted)
{
    modelnet::SwarmRegCheck check;
    check.check_id = "reg-noted";
    check.script_present = true;
    check.utxo_known = true;
    check.want_mine = false;
    check.want_broadcast = false;
    std::string err{"stale"};
    const modelnet::SwarmRegCheckResult result = modelnet::SwarmCheckRegtest(check, err);
    BOOST_CHECK_EQUAL(result.mined, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.script_ok, true);
}

BOOST_AUTO_TEST_SUITE_END()
