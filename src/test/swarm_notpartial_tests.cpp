// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpartial.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notpartial_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_artifact_id_is_artifact)
{
    modelnet::SwarmNotPartial note;
    std::string err = "prior";
    const modelnet::SwarmNotPartialResult result = modelnet::SwarmNoteNotPartial(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
}

BOOST_AUTO_TEST_CASE(want_accept_is_not_shown)
{
    modelnet::SwarmNotPartial note;
    note.artifact_id = "artifact-1";
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotPartialResult result = modelnet::SwarmNoteNotPartial(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHOWN");
    BOOST_CHECK_EQUAL(err, "NOT_SHOWN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotPartial note;
    note.artifact_id = "artifact-1";
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotPartialResult result = modelnet::SwarmNoteNotPartial(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
