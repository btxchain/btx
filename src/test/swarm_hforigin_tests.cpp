// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hforigin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hforigin_tests, BasicTestingSetup)

static modelnet::SwarmHfOrigin NotedOrigin()
{
    modelnet::SwarmHfOrigin note;
    note.model_id = "org/model";
    note.hugging_face = false;
    note.want_lineage_authority = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_model_id_is_origin)
{
    modelnet::SwarmHfOrigin note = NotedOrigin();
    note.model_id.clear();
    std::string err = "prior";
    const modelnet::SwarmHfOriginResult result = modelnet::SwarmNoteHfOrigin(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "ORIGIN");
    BOOST_CHECK_EQUAL(err, "ORIGIN");
}

BOOST_AUTO_TEST_CASE(want_lineage_authority_with_hugging_face_is_not_authority)
{
    modelnet::SwarmHfOrigin note = NotedOrigin();
    note.hugging_face = true;
    note.want_lineage_authority = true;
    std::string err = "prior";
    const modelnet::SwarmHfOriginResult result = modelnet::SwarmNoteHfOrigin(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(hugging_face_is_held_and_is_not_lineage_authority)
{
    modelnet::SwarmHfOrigin note = NotedOrigin();
    note.hugging_face = true;
    std::string err = "prior";
    const modelnet::SwarmHfOriginResult result = modelnet::SwarmNoteHfOrigin(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmHfOrigin note = NotedOrigin();
    std::string err = "prior";
    const modelnet::SwarmHfOriginResult result = modelnet::SwarmNoteHfOrigin(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
