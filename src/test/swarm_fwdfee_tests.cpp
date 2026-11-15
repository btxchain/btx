// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fwdfee.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fwdfee_tests, BasicTestingSetup)

static modelnet::SwarmForwardFee NotedFee()
{
    modelnet::SwarmForwardFee fee;
    fee.hop_id = "hop-a";
    fee.amount = 1000000;
    fee.base = 5;
    fee.ppm = 100;
    fee.sender_first_edge = false;
    return fee;
}

BOOST_AUTO_TEST_CASE(empty_hop_id_is_fee)
{
    modelnet::SwarmForwardFee fee = NotedFee();
    fee.hop_id.clear();
    std::string err = "prior";
    const modelnet::SwarmForwardFeeResult result = modelnet::SwarmNoteForwardFee(fee, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.code, "FEE");
    BOOST_CHECK_EQUAL(err, "FEE");
}

BOOST_AUTO_TEST_CASE(amount_zero_is_fee)
{
    modelnet::SwarmForwardFee fee = NotedFee();
    fee.amount = 0;
    std::string err = "prior";
    const modelnet::SwarmForwardFeeResult result = modelnet::SwarmNoteForwardFee(fee, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.code, "FEE");
    BOOST_CHECK_EQUAL(err, "FEE");
}

BOOST_AUTO_TEST_CASE(sender_first_edge_is_no_fee)
{
    modelnet::SwarmForwardFee fee = NotedFee();
    fee.amount = 1000000;
    fee.base = 5;
    fee.ppm = 100;
    fee.sender_first_edge = true;
    std::string err = "prior";
    const modelnet::SwarmForwardFeeResult result = modelnet::SwarmNoteForwardFee(fee, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.code, "NO_FEE");
    BOOST_CHECK_EQUAL(err, "NO_FEE");
}

BOOST_AUTO_TEST_CASE(ppm_note_is_one_hundred_five)
{
    modelnet::SwarmForwardFee fee = NotedFee();
    fee.amount = 1000000;
    fee.base = 5;
    fee.ppm = 100;
    fee.sender_first_edge = false;
    std::string err = "prior";
    const modelnet::SwarmForwardFeeResult result = modelnet::SwarmNoteForwardFee(fee, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 105);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(one_atom_one_ppm_rounds_up_to_one)
{
    modelnet::SwarmForwardFee fee = NotedFee();
    fee.amount = 1;
    fee.base = 0;
    fee.ppm = 1;
    fee.sender_first_edge = false;
    std::string err = "prior";
    const modelnet::SwarmForwardFeeResult result = modelnet::SwarmNoteForwardFee(fee, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 1);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
