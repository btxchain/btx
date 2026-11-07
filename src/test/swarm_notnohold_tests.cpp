// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_split_id_is_split)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHold note;
    note.holdout = true;
    note.want_train = true;
    const modelnet::SwarmNotNoHoldResult result = modelnet::SwarmNoteNotNoHold(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(holdout_is_not_train)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHold note;
    note.split_id = "split-note";
    note.holdout = true;
    note.want_train = false;
    const modelnet::SwarmNotNoHoldResult result = modelnet::SwarmNoteNotNoHold(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRAIN");
    BOOST_CHECK_EQUAL(err, "NOT_TRAIN");
}

BOOST_AUTO_TEST_CASE(want_train_on_non_holdout_is_not_train)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHold note;
    note.split_id = "split-note";
    note.holdout = false;
    note.want_train = true;
    const modelnet::SwarmNotNoHoldResult result = modelnet::SwarmNoteNotNoHold(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRAIN");
    BOOST_CHECK_EQUAL(err, "NOT_TRAIN");
}

BOOST_AUTO_TEST_CASE(plain_non_holdout_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHold note;
    note.split_id = "split-note";
    note.holdout = false;
    note.want_train = false;
    const modelnet::SwarmNotNoHoldResult result = modelnet::SwarmNoteNotNoHold(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
