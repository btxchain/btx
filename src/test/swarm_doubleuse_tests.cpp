// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_doubleuse.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_doubleuse_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_outpoint_is_outpoint)
{
    modelnet::SwarmDoubleUse use;
    use.outpoint.clear();
    use.escrow_lot = false;
    use.channel_collateral = false;
    std::string err = "prior";
    const modelnet::SwarmDoubleUseResult result = modelnet::SwarmNoteDoubleUse(use, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "OUTPOINT");
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
}

BOOST_AUTO_TEST_CASE(empty_outpoint_wins_over_both_roles)
{
    modelnet::SwarmDoubleUse use;
    use.outpoint.clear();
    use.escrow_lot = true;
    use.channel_collateral = true;
    std::string err = "prior";
    const modelnet::SwarmDoubleUseResult result = modelnet::SwarmNoteDoubleUse(use, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "OUTPOINT");
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
}

BOOST_AUTO_TEST_CASE(both_roles_are_double_use)
{
    modelnet::SwarmDoubleUse use;
    use.outpoint = "opaque-outpoint";
    use.escrow_lot = true;
    use.channel_collateral = true;
    std::string err = "prior";
    const modelnet::SwarmDoubleUseResult result = modelnet::SwarmNoteDoubleUse(use, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "DOUBLE_USE");
    BOOST_CHECK_EQUAL(err, "DOUBLE_USE");
}

BOOST_AUTO_TEST_CASE(escrow_only_is_noted)
{
    modelnet::SwarmDoubleUse use;
    use.outpoint = "escrow-lot-outpoint";
    use.escrow_lot = true;
    use.channel_collateral = false;
    std::string err = "prior";
    const modelnet::SwarmDoubleUseResult result = modelnet::SwarmNoteDoubleUse(use, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(collateral_only_is_noted)
{
    modelnet::SwarmDoubleUse use;
    use.outpoint = "channel-collateral-outpoint";
    use.escrow_lot = false;
    use.channel_collateral = true;
    std::string err = "prior";
    const modelnet::SwarmDoubleUseResult result = modelnet::SwarmNoteDoubleUse(use, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
