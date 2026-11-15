// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoablate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotNoAblate note;
    note.want_change = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoAblateResult result = modelnet::SwarmNoteNotNoAblate(note, err);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_change_not_changed)
{
    modelnet::SwarmNotNoAblate note;
    note.run_id = "run-a";
    note.want_change = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoAblateResult result = modelnet::SwarmNoteNotNoAblate(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHANGED");
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(err, "NOT_CHANGED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotNoAblate note;
    note.run_id = "run-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoAblateResult result = modelnet::SwarmNoteNotNoAblate(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
