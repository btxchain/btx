// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoassumed.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoassumed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoAssumed note;
    note.assumed = true;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAssumedResult result = modelnet::SwarmNoteNotNoAssumed(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.exits, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(assumed_without_publish_is_unmeasured)
{
    modelnet::SwarmNotNoAssumed note;
    note.run_id = "run-1";
    note.assumed = true;
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAssumedResult result = modelnet::SwarmNoteNotNoAssumed(note, err);
    // An assumed mass-exit size is not a measurement.
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.exits, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    modelnet::SwarmNotNoAssumed note;
    note.run_id = "run-1";
    note.assumed = false;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAssumedResult result = modelnet::SwarmNoteNotNoAssumed(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.exits, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAssumed note;
    BOOST_CHECK(!note.assumed);
    BOOST_CHECK(!note.want_publish);
    note.run_id = "run-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoAssumedResult result = modelnet::SwarmNoteNotNoAssumed(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.exits, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
