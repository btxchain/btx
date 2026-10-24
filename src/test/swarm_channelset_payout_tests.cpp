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

bool OpenFunded(modelnet::SwarmChannelSet& plane, int64_t capacity, int refund_height, std::string& err)
{
    if (!plane.Open("lane", capacity, Pubkey(0x31), Pubkey(0x32), err)) return false;
    if (!plane.Refund(refund_height, err)) return false;
    if (!plane.Fund(err)) return false;
    return true;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_channelset_payout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unfunded_payout_builds_nothing)
{
    modelnet::SwarmChannelSet closed;
    std::string err = "prior";
    BOOST_REQUIRE(!closed.Payout(1, 100, 1000, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_FUNDED");
    BOOST_REQUIRE(closed.cumulative() == 0);
    BOOST_REQUIRE(closed.payout_outputs() == 0);

    modelnet::SwarmChannelSet plane;
    BOOST_REQUIRE(plane.Open("lane", 1000, Pubkey(0x31), Pubkey(0x32), err));
    BOOST_REQUIRE(plane.Refund(1000, err));
    BOOST_REQUIRE(!plane.funded());
    BOOST_REQUIRE(!plane.Payout(40, 100, 1000, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_FUNDED");
    BOOST_REQUIRE(plane.cumulative() == 0);
    BOOST_REQUIRE(plane.payout_outputs() == 0);
    BOOST_REQUIRE(plane.payout_worker_value() == 0);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 0);
    BOOST_REQUIRE(plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(margin_does_not_pay)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(OpenFunded(plane, 1000, 1000, err));

    BOOST_REQUIRE(!plane.Payout(5000, 900, 1000, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.cumulative() == 0);
    BOOST_REQUIRE(plane.payout_outputs() == 0);
    BOOST_REQUIRE(plane.refund_height() == 1000);

    err = "prior";
    BOOST_REQUIRE(!plane.Payout(10, 900, 900, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.cumulative() == 0);
    BOOST_REQUIRE(plane.payout_outputs() == 0);
    BOOST_REQUIRE(plane.refund_height() == 1000);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(margin_boundary_is_the_close_window)
{
    modelnet::SwarmChannelSet closed;
    std::string err;
    BOOST_REQUIRE(OpenFunded(closed, 10, 260, err));
    BOOST_REQUIRE(!closed.Payout(1, 100, 260, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(closed.cumulative() == 0);
    BOOST_REQUIRE(closed.payout_outputs() == 0);
    BOOST_REQUIRE(!closed.broadcast());

    modelnet::SwarmChannelSet open;
    BOOST_REQUIRE(OpenFunded(open, 10, 261, err));
    BOOST_REQUIRE(open.Payout(1, 100, 261, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(open.cumulative() == 1);
    BOOST_REQUIRE(open.payout_worker_value() == 1);
    BOOST_REQUIRE(open.payout_outputs() == 2);
    BOOST_REQUIRE(!open.broadcast());
    BOOST_REQUIRE(open.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(cumulative_above_capacity_is_short)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(OpenFunded(plane, 50, 400, err));

    BOOST_REQUIRE(!plane.Payout(51, 100, 400, err));
    BOOST_REQUIRE_EQUAL(err, "SHORT");
    BOOST_REQUIRE(plane.cumulative() == 0);
    BOOST_REQUIRE(plane.payout_outputs() == 0);
    BOOST_REQUIRE(plane.payout_worker_value() == 0);

    BOOST_REQUIRE(plane.Payout(50, 100, 400, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cumulative() == 50);
    BOOST_REQUIRE(plane.payout_worker_value() == 50);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 0);
    BOOST_REQUIRE(plane.payout_outputs() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Payout(51, 100, 400, err));
    BOOST_REQUIRE_EQUAL(err, "SHORT");
    BOOST_REQUIRE(plane.cumulative() == 50);
    BOOST_REQUIRE(plane.payout_worker_value() == 50);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(lower_cumulative_is_stale)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(OpenFunded(plane, 1000, 1000, err));

    BOOST_REQUIRE(plane.Payout(40, 100, 1000, err));
    BOOST_REQUIRE(plane.cumulative() == 40);
    BOOST_REQUIRE(plane.payout_worker_value() == 40);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 960);

    err = "prior";
    BOOST_REQUIRE(!plane.Payout(39, 100, 1000, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cumulative() == 40);
    BOOST_REQUIRE(plane.payout_worker_value() == 40);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 960);
    BOOST_REQUIRE(plane.payout_outputs() == 2);

    BOOST_REQUIRE(plane.Payout(40, 100, 1000, err));
    BOOST_REQUIRE(plane.cumulative() == 40);
    BOOST_REQUIRE(plane.Payout(41, 100, 1000, err));
    BOOST_REQUIRE(plane.cumulative() == 41);
    BOOST_REQUIRE(plane.payout_worker_value() == 41);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 959);

    err = "prior";
    BOOST_REQUIRE(!plane.Payout(0, 100, 1000, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cumulative() == 41);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.multi_hop_qualified());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(payout_passes_refund_height_through)
{
    modelnet::SwarmChannelSet plane;
    std::string err = "prior";
    BOOST_REQUIRE(OpenFunded(plane, 1000, 1000, err));

    BOOST_REQUIRE(!plane.Payout(10, 100, 1161, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRY_CHANGE");
    BOOST_REQUIRE(plane.cumulative() == 0);
    BOOST_REQUIRE(plane.refund_height() == 1000);
    BOOST_REQUIRE(plane.payout_outputs() == 0);

    BOOST_REQUIRE(plane.Payout(10, 100, 1000, err));
    BOOST_REQUIRE(plane.cumulative() == 10);
    BOOST_REQUIRE(plane.payout_worker_value() == 10);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 990);
    BOOST_REQUIRE(plane.payout_outputs() == 2);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
