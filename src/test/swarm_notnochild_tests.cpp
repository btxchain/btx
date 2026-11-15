// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochild.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnochild_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_manifest_id_is_manifest)
{
    modelnet::SwarmNotNoChild note;
    note.child_matches = false;
    note.want_stream = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChildResult result = modelnet::SwarmNoteNotNoChild(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(child_mismatch_is_incomplete_when_want_stream_is_false)
{
    modelnet::SwarmNotNoChild note;
    note.manifest_id = "manifest-1";
    note.child_matches = false;
    note.want_stream = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChildResult result = modelnet::SwarmNoteNotNoChild(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(want_stream_is_held)
{
    modelnet::SwarmNotNoChild note;
    note.manifest_id = "manifest-1";
    note.child_matches = true;
    note.want_stream = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChildResult result = modelnet::SwarmNoteNotNoChild(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoChild note;
    note.manifest_id = "manifest-1";
    note.child_matches = true;
    note.want_stream = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChildResult result = modelnet::SwarmNoteNotNoChild(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
