// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_profit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_profit_tests, BasicTestingSetup)

static modelnet::SwarmProfitShare FilledShare()
{
    modelnet::SwarmProfitShare share;
    share.instrument_id = "instrument-1";
    share.atoms = 1;
    share.profit_share = false;
    return share;
}

BOOST_AUTO_TEST_CASE(empty_instrument_id_is_instrument)
{
    modelnet::SwarmProfitShare share = FilledShare();
    share.instrument_id.clear();
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "INSTRUMENT");
    BOOST_CHECK_EQUAL(err, "INSTRUMENT");
}

BOOST_AUTO_TEST_CASE(negative_atoms_are_instrument)
{
    modelnet::SwarmProfitShare share = FilledShare();
    share.atoms = -1;
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "INSTRUMENT");
    BOOST_CHECK_EQUAL(err, "INSTRUMENT");
}

BOOST_AUTO_TEST_CASE(empty_instrument_id_wins_over_profit_share)
{
    modelnet::SwarmProfitShare share = FilledShare();
    share.instrument_id.clear();
    share.atoms = 42;
    share.profit_share = true;
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "INSTRUMENT");
    BOOST_CHECK_EQUAL(err, "INSTRUMENT");
}

BOOST_AUTO_TEST_CASE(negative_atoms_win_over_profit_share)
{
    modelnet::SwarmProfitShare share = FilledShare();
    share.atoms = -5;
    share.profit_share = true;
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "INSTRUMENT");
    BOOST_CHECK_EQUAL(err, "INSTRUMENT");
}

BOOST_AUTO_TEST_CASE(profit_share_with_positive_atoms_is_refused)
{
    modelnet::SwarmProfitShare share = FilledShare();
    share.atoms = 42;
    share.profit_share = true;
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "PROFIT_REFUSED");
    BOOST_CHECK_EQUAL(err, "PROFIT_REFUSED");
}

BOOST_AUTO_TEST_CASE(noted_share_is_not_accepted)
{
    modelnet::SwarmProfitShare share = FilledShare();
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_atoms_are_noted)
{
    modelnet::SwarmProfitShare share = FilledShare();
    share.atoms = 0;
    std::string err = "prior";
    const modelnet::SwarmProfitShareResult result = modelnet::SwarmNoteProfitShare(share, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
