// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_balclass.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_balclass_tests, BasicTestingSetup)

static modelnet::SwarmBalanceMove NotedMove()
{
    modelnet::SwarmBalanceMove move;
    move.from_class = "earning";
    move.to_class = "earning";
    move.atoms = 1;
    return move;
}

BOOST_AUTO_TEST_CASE(unknown_class_is_balance)
{
    modelnet::SwarmBalanceMove move = NotedMove();
    move.from_class = "wallet";
    std::string err = "prior";
    const modelnet::SwarmBalanceMoveResult result = modelnet::SwarmNoteBalanceClass(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "BALANCE");
    BOOST_CHECK_EQUAL(err, "BALANCE");
}

BOOST_AUTO_TEST_CASE(nonpositive_atoms_are_balance)
{
    modelnet::SwarmBalanceMove move = NotedMove();
    move.atoms = 0;
    std::string err = "prior";
    const modelnet::SwarmBalanceMoveResult result = modelnet::SwarmNoteBalanceClass(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "BALANCE");
    BOOST_CHECK_EQUAL(err, "BALANCE");

    move.atoms = -1;
    err = "prior";
    const modelnet::SwarmBalanceMoveResult negative = modelnet::SwarmNoteBalanceClass(move, err);
    BOOST_CHECK(!negative.moved);
    BOOST_CHECK_EQUAL(negative.code, "BALANCE");
    BOOST_CHECK_EQUAL(err, "BALANCE");
}

BOOST_AUTO_TEST_CASE(escrow_to_collateral_is_separate)
{
    modelnet::SwarmBalanceMove move = NotedMove();
    move.from_class = "escrow";
    move.to_class = "collateral";
    std::string err = "prior";
    const modelnet::SwarmBalanceMoveResult result = modelnet::SwarmNoteBalanceClass(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(earning_to_earning_is_noted)
{
    modelnet::SwarmBalanceMove move = NotedMove();
    std::string err = "prior";
    const modelnet::SwarmBalanceMoveResult result = modelnet::SwarmNoteBalanceClass(move, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
