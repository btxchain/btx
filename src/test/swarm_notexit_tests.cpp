// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notexit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notexit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    modelnet::SwarmNotExit note;
    note.batch_id.clear();
    note.want_measure = false;
    std::string err = "prior";
    const modelnet::SwarmNotExitResult result = modelnet::SwarmNoteNotExit(note, err);
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK_EQUAL(err, "BATCH");
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(want_measure_is_measure_refused)
{
    modelnet::SwarmNotExit note;
    note.batch_id = "batch-1";
    note.want_measure = true;
    std::string err = "prior";
    const modelnet::SwarmNotExitResult result = modelnet::SwarmNoteNotExit(note, err);
    BOOST_CHECK_EQUAL(result.code, "MEASURE_REFUSED");
    BOOST_CHECK_EQUAL(err, "MEASURE_REFUSED");
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotExit note;
    note.batch_id = "batch-1";
    note.want_measure = false;
    std::string err = "prior";
    const modelnet::SwarmNotExitResult result = modelnet::SwarmNoteNotExit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_SUITE_END()
