// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_holdrot_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_split)
{
    modelnet::SwarmHoldRot split;
    split.split_id.clear();
    split.fixed_holdout = false;
    split.want_rotate = false;
    std::string err;
    const modelnet::SwarmHoldRotResult result = modelnet::SwarmNoteHoldRot(split, err);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
    BOOST_CHECK(!result.rotated);
}

BOOST_AUTO_TEST_CASE(fixed_holdout_not_rotating)
{
    modelnet::SwarmHoldRot split;
    split.split_id = "split-1";
    split.fixed_holdout = true;
    split.want_rotate = false;
    std::string err;
    const modelnet::SwarmHoldRotResult result = modelnet::SwarmNoteHoldRot(split, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROTATING");
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
    BOOST_CHECK(!result.rotated);
}

BOOST_AUTO_TEST_CASE(want_rotate_held)
{
    modelnet::SwarmHoldRot split;
    split.split_id = "split-2";
    split.fixed_holdout = false;
    split.want_rotate = true;
    std::string err;
    const modelnet::SwarmHoldRotResult result = modelnet::SwarmNoteHoldRot(split, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.rotated);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmHoldRot split;
    split.split_id = "split-3";
    split.fixed_holdout = false;
    split.want_rotate = false;
    std::string err = "stale";
    const modelnet::SwarmHoldRotResult result = modelnet::SwarmNoteHoldRot(split, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.rotated);
}

BOOST_AUTO_TEST_SUITE_END()
