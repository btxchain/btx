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

BOOST_FIXTURE_TEST_SUITE(swarm_channelset_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name_is_channel)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    const std::vector<unsigned char> sponsor = Pubkey(0x21);
    const std::vector<unsigned char> worker = Pubkey(0x22);

    BOOST_REQUIRE(plane.name().empty());
    BOOST_REQUIRE(plane.capacity() == 0);
    BOOST_REQUIRE(!plane.Open("", 10, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(plane.name().empty());
    BOOST_REQUIRE(plane.capacity() == 0);
    BOOST_REQUIRE(!plane.funded());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(capacity_below_one_is_capacity)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    const std::vector<unsigned char> sponsor = Pubkey(0x21);
    const std::vector<unsigned char> worker = Pubkey(0x22);

    BOOST_REQUIRE(!plane.Open("lane", 0, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "CAPACITY");
    BOOST_REQUIRE(plane.name().empty());
    BOOST_REQUIRE(plane.capacity() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", -1, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "CAPACITY");
    BOOST_REQUIRE(plane.name().empty());
    BOOST_REQUIRE(!plane.funded());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(pubkey_size_is_key)
{
    BOOST_REQUIRE_EQUAL(MLDSA44_PUBKEY_SIZE, 1312U);

    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    const std::vector<unsigned char> sponsor = Pubkey(0x21);
    const std::vector<unsigned char> worker = Pubkey(0x22);
    const std::vector<unsigned char> empty;
    const std::vector<unsigned char> short_key(static_cast<std::size_t>(MLDSA44_PUBKEY_SIZE) - 1, 0x41);
    const std::vector<unsigned char> long_key(static_cast<std::size_t>(MLDSA44_PUBKEY_SIZE) + 1, 0x42);
    const std::vector<unsigned char> spend_sized(MLDSA44_SECRET_KEY_SIZE, 0x43);

    BOOST_REQUIRE(!plane.Open("lane", 10, empty, worker, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(plane.name().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", 10, short_key, worker, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(plane.capacity() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", 10, sponsor, short_key, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", 10, long_key, worker, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", 10, sponsor, long_key, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", 10, spend_sized, worker, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(plane.name().empty());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.funded());

    err = "prior";
    BOOST_REQUIRE(plane.Open("lane", 10, sponsor, worker, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 10);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(second_open_of_any_name_leaves_the_first)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    const std::vector<unsigned char> sponsor = Pubkey(0x21);
    const std::vector<unsigned char> worker = Pubkey(0x22);
    const std::vector<unsigned char> bad(1, 0x01);

    BOOST_REQUIRE(plane.Open("lane", 1000, sponsor, worker, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 1000);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Open("other", 1, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_OPENED");
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 1000);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("lane", 1000, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_OPENED");
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 1000);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("", 1000, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 1000);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("other", 0, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "CAPACITY");
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 1000);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("other", 1000, bad, worker, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE_EQUAL(plane.name(), "lane");
    BOOST_REQUIRE(plane.capacity() == 1000);

    err = "prior";
    BOOST_REQUIRE(plane.Refund(1000, err));
    BOOST_REQUIRE(plane.refund_built());
    BOOST_REQUIRE(plane.Fund(err));
    BOOST_REQUIRE(plane.funded());
    BOOST_REQUIRE(plane.Payout(40, 100, 1000, err));
    BOOST_REQUIRE(plane.cumulative() == 40);
    BOOST_REQUIRE(plane.capacity() == 1000);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(channels_are_independent)
{
    modelnet::SwarmChannelSet first;
    modelnet::SwarmChannelSet second;
    std::string err;
    const std::vector<unsigned char> sponsor = Pubkey(0x21);
    const std::vector<unsigned char> worker = Pubkey(0x22);

    BOOST_REQUIRE(first.Open("a", 5, sponsor, worker, err));
    BOOST_REQUIRE(second.Open("b", 7, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(first.name(), "a");
    BOOST_REQUIRE(first.capacity() == 5);
    BOOST_REQUIRE_EQUAL(second.name(), "b");
    BOOST_REQUIRE(second.capacity() == 7);
    BOOST_REQUIRE(!first.Open("c", 9, sponsor, worker, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_OPENED");
    BOOST_REQUIRE_EQUAL(second.name(), "b");
    BOOST_REQUIRE(second.capacity() == 7);
    BOOST_REQUIRE_EQUAL(first.automatic_spend(), "0");
    BOOST_REQUIRE_EQUAL(second.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
