// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonegative.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnonegative_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_result_id_is_result)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNegative note;
    note.negative = true;
    note.want_drop = true;
    const modelnet::SwarmNotNoNegativeResult result = modelnet::SwarmNoteNotNoNegative(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "RESULT");
    BOOST_CHECK_EQUAL(err, "RESULT");
}

BOOST_AUTO_TEST_CASE(negative_without_drop_is_kept)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNegative note;
    note.result_id = "result-1";
    note.negative = true;
    note.want_drop = false;
    const modelnet::SwarmNotNoNegativeResult result = modelnet::SwarmNoteNotNoNegative(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(want_drop_is_kept)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNegative note;
    note.result_id = "result-1";
    note.negative = false;
    note.want_drop = true;
    const modelnet::SwarmNotNoNegativeResult result = modelnet::SwarmNoteNotNoNegative(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNegative note;
    note.result_id = "result-1";
    note.negative = false;
    note.want_drop = false;
    const modelnet::SwarmNotNoNegativeResult result = modelnet::SwarmNoteNotNoNegative(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
