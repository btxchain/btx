// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminheight.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_adminheight_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_yields_channel)
{
    modelnet::SwarmAdminHeight height;
    height.channel_id.clear();
    height.height = 90;
    height.admin = false;
    height.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminHeightResult result = modelnet::SwarmNoteAdminHeight(height, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK_EQUAL(result.height, 0);
}

BOOST_AUTO_TEST_CASE(negative_height_yields_range)
{
    modelnet::SwarmAdminHeight height;
    height.channel_id = "ch-1";
    height.height = -1;
    height.admin = false;
    height.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminHeightResult result = modelnet::SwarmNoteAdminHeight(height, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(result.height, 0);
}

BOOST_AUTO_TEST_CASE(admin_true_want_move_false_yields_held)
{
    modelnet::SwarmAdminHeight height;
    height.channel_id = "ch-1";
    height.height = 90;
    height.admin = true;
    height.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminHeightResult result = modelnet::SwarmNoteAdminHeight(height, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.height, 90);
}

BOOST_AUTO_TEST_CASE(want_move_true_admin_false_yields_held)
{
    modelnet::SwarmAdminHeight height;
    height.channel_id = "ch-1";
    height.height = 90;
    height.admin = false;
    height.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmAdminHeightResult result = modelnet::SwarmNoteAdminHeight(height, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.height, 90);
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmAdminHeight height;
    height.channel_id = "ch-1";
    height.height = 90;
    height.admin = false;
    height.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminHeightResult result = modelnet::SwarmNoteAdminHeight(height, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.height, 90);
}

BOOST_AUTO_TEST_SUITE_END()
