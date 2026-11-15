// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/channelset.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

std::vector<unsigned char> Pubkey(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_channelset_refund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(refund_without_open_is_channel)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(!plane.Refund(1000, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.refund_outputs() == 0);
    BOOST_REQUIRE(plane.refund_value() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(refund_height_below_one_builds_nothing)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Open("lane", 1000, Pubkey(0x21), Pubkey(0x22), err));

    BOOST_REQUIRE(!plane.Refund(0, err));
    BOOST_REQUIRE_EQUAL(err, "REFUND_HEIGHT");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.refund_height() == 0);
    BOOST_REQUIRE(plane.refund_outputs() == 0);
    BOOST_REQUIRE(!plane.funded());

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(-3, err));
    BOOST_REQUIRE_EQUAL(err, "REFUND_HEIGHT");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.refund_height() == 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(refund_builds_in_memory_and_second_is_replay)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Open("lane", 1000, Pubkey(0x21), Pubkey(0x22), err));
    BOOST_REQUIRE(!plane.refund_built());

    BOOST_REQUIRE(plane.Refund(1000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.refund_built());
    BOOST_REQUIRE(plane.refund_height() == 1000);
    BOOST_REQUIRE(plane.refund_outputs() == 1);
    BOOST_REQUIRE(plane.refund_value() == 1000);
    BOOST_REQUIRE(!plane.funded());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.multi_hop_qualified());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(50, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.refund_built());
    BOOST_REQUIRE(plane.refund_height() == 1000);
    BOOST_REQUIRE(plane.refund_outputs() == 1);
    BOOST_REQUIRE(plane.refund_value() == 1000);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
