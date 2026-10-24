// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notflagship.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notflagship_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_stage_id_is_stage)
{
    modelnet::SwarmNotFlagship note;
    std::string err = "prior";
    const modelnet::SwarmNotFlagshipResult result = modelnet::SwarmNoteNotFlagship(note, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.code, "STAGE");
    BOOST_CHECK_EQUAL(err, "STAGE");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmNotFlagship note;
    note.stage_id = "stage-1";
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotFlagshipResult result = modelnet::SwarmNoteNotFlagship(note, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotFlagship note;
    note.stage_id = "stage-1";
    note.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmNotFlagshipResult result = modelnet::SwarmNoteNotFlagship(note, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
