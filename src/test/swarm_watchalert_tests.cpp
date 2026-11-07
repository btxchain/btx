// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchalert.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchalert_tests, BasicTestingSetup)

static modelnet::SwarmWatchAlert NotedAlert()
{
    modelnet::SwarmWatchAlert alert;
    alert.channel_id = "ch-1";
    alert.prior_secret_released = false;
    alert.draining = false;
    alert.stale_state = false;
    return alert;
}

static void ExpectFlagsFalse(const modelnet::SwarmWatchAlertResult& result)
{
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_watch)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "WATCH");
    BOOST_CHECK_EQUAL(err, "WATCH");
}

BOOST_AUTO_TEST_CASE(empty_channel_id_wins_over_other_flags)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.channel_id.clear();
    alert.prior_secret_released = true;
    alert.draining = true;
    alert.stale_state = true;
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "WATCH");
    BOOST_CHECK_EQUAL(err, "WATCH");
}

BOOST_AUTO_TEST_CASE(prior_secret_released_is_hashlock_remedy)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.prior_secret_released = true;
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HASHLOCK_REMEDY");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(prior_secret_released_wins_over_draining_and_stale)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.prior_secret_released = true;
    alert.draining = true;
    alert.stale_state = true;
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HASHLOCK_REMEDY");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(draining_is_drain_and_notify)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.draining = true;
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "DRAIN_AND_NOTIFY");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(draining_wins_over_stale_state)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.draining = true;
    alert.stale_state = true;
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "DRAIN_AND_NOTIFY");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(stale_state_is_stale_state_alert)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    alert.stale_state = true;
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "STALE_STATE_ALERT");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmWatchAlert alert = NotedAlert();
    std::string err = "prior";
    const modelnet::SwarmWatchAlertResult result = modelnet::SwarmNoteWatchAlert(alert, err);
    ExpectFlagsFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
