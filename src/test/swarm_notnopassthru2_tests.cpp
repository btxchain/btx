// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopassthru2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopassthru2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_check_id_is_check)
{
    modelnet::SwarmNotNoPassThru2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoPassThru2Result result = modelnet::SwarmNoteNotNoPassThru2(note, err);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
}

BOOST_AUTO_TEST_CASE(passthrough_true_want_start_false_is_not_started)
{
    modelnet::SwarmNotNoPassThru2 note;
    note.check_id = "check-1";
    note.passthrough = true;
    note.want_start = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPassThru2Result result = modelnet::SwarmNoteNotNoPassThru2(note, err);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(want_start_true_passthrough_false_is_held)
{
    modelnet::SwarmNotNoPassThru2 note;
    note.check_id = "check-1";
    note.passthrough = false;
    note.want_start = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPassThru2Result result = modelnet::SwarmNoteNotNoPassThru2(note, err);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmNotNoPassThru2 note;
    note.check_id = "check-1";
    note.passthrough = false;
    note.want_start = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPassThru2Result result = modelnet::SwarmNoteNotNoPassThru2(note, err);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
