// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_publishback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_publishback_tests, BasicTestingSetup)

static modelnet::SwarmPublishBack NotedPublishBack()
{
    modelnet::SwarmPublishBack note;
    note.model_id = "org/model";
    note.hugging_face = false;
    note.want_publish_back = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_model_id_is_origin)
{
    modelnet::SwarmPublishBack note = NotedPublishBack();
    note.model_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPublishBackResult result = modelnet::SwarmNotePublishBack(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "ORIGIN");
    BOOST_CHECK_EQUAL(err, "ORIGIN");
}

BOOST_AUTO_TEST_CASE(want_publish_back_with_hugging_face_is_not_authority)
{
    modelnet::SwarmPublishBack note = NotedPublishBack();
    note.hugging_face = true;
    note.want_publish_back = true;
    std::string err = "prior";
    const modelnet::SwarmPublishBackResult result = modelnet::SwarmNotePublishBack(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(hugging_face_is_held_and_does_not_publish)
{
    modelnet::SwarmPublishBack note = NotedPublishBack();
    note.hugging_face = true;
    std::string err = "prior";
    const modelnet::SwarmPublishBackResult result = modelnet::SwarmNotePublishBack(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmPublishBack note = NotedPublishBack();
    std::string err = "prior";
    const modelnet::SwarmPublishBackResult result = modelnet::SwarmNotePublishBack(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
