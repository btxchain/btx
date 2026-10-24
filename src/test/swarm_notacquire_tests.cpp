// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notacquire.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notacquire_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_artifact_id_is_artifact)
{
    modelnet::SwarmNotAcquire note;
    std::string err = "prior";
    const modelnet::SwarmNotAcquireResult result = modelnet::SwarmNoteNotAcquire(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
}

BOOST_AUTO_TEST_CASE(want_verify_is_unverified)
{
    modelnet::SwarmNotAcquire note;
    note.artifact_id = "artifact-1";
    note.want_verify = true;
    std::string err = "prior";
    const modelnet::SwarmNotAcquireResult result = modelnet::SwarmNoteNotAcquire(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.code, "UNVERIFIED");
    BOOST_CHECK_EQUAL(err, "UNVERIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotAcquire note;
    note.artifact_id = "artifact-1";
    note.want_verify = false;
    std::string err = "prior";
    const modelnet::SwarmNotAcquireResult result = modelnet::SwarmNoteNotAcquire(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
