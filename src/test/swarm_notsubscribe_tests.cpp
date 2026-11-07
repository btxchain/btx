// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsubscribe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsubscribe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_model_id)
{
    modelnet::SwarmNotSubscribe note;
    std::string err = "stale";
    const modelnet::SwarmNotSubscribeResult result = modelnet::SwarmNoteNotSubscribe(note, err);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK(!result.subscribed);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(want_subscribe_not_subscribed)
{
    modelnet::SwarmNotSubscribe note;
    note.model_id = "model-1";
    note.want_subscribe = true;
    std::string err = "stale";
    const modelnet::SwarmNotSubscribeResult result = modelnet::SwarmNoteNotSubscribe(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SUBSCRIBED");
    BOOST_CHECK(!result.subscribed);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK_EQUAL(err, "NOT_SUBSCRIBED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotSubscribe note;
    note.model_id = "model-1";
    std::string err = "stale";
    const modelnet::SwarmNotSubscribeResult result = modelnet::SwarmNoteNotSubscribe(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.subscribed);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
