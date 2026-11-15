// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_replaystall.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_replaystall_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(negative_tip_is_stall)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = -1;
    in.stall_height = 10;
    in.want_mine = true;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "STALL");
    BOOST_CHECK_EQUAL(err, "STALL");
}

BOOST_AUTO_TEST_CASE(negative_stall_height_is_stall)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = 4;
    in.stall_height = -1;
    in.want_mine = false;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "STALL");
    BOOST_CHECK_EQUAL(err, "STALL");
}

BOOST_AUTO_TEST_CASE(want_mine_below_stall_is_refused)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = 3;
    in.stall_height = 10;
    in.want_mine = true;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "MINE_REFUSED");
    BOOST_CHECK_EQUAL(err, "MINE_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_mine_at_stall_is_refused)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = 10;
    in.stall_height = 10;
    in.want_mine = true;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "MINE_REFUSED");
    BOOST_CHECK_EQUAL(err, "MINE_REFUSED");
}

BOOST_AUTO_TEST_CASE(tip_at_stall_is_held)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = 10;
    in.stall_height = 10;
    in.want_mine = false;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(tip_above_stall_is_held)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = 12;
    in.stall_height = 10;
    in.want_mine = false;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(tip_below_stall_is_below)
{
    modelnet::SwarmReplayStall in;
    in.tip_height = 3;
    in.stall_height = 10;
    in.want_mine = false;
    std::string err = "preset";
    const modelnet::SwarmReplayStallResult r = modelnet::SwarmNoteReplayStall(in, err);
    BOOST_CHECK(!r.mined);
    BOOST_CHECK_EQUAL(r.code, "BELOW");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
