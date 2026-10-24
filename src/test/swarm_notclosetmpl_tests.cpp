// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notclosetmpl.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notclosetmpl_tests, BasicTestingSetup)

static modelnet::SwarmNotCloseTmpl NotedNote()
{
    modelnet::SwarmNotCloseTmpl note;
    note.channel_id = "channel-1";
    note.template_count = 1;
    note.want_close = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotCloseTmpl note = NotedNote();
    note.channel_id.clear();
    note.template_count = 0;
    note.want_close = true;
    std::string err = "prior";
    const modelnet::SwarmNotCloseTmplResult result = modelnet::SwarmNoteNotCloseTmpl(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(template_count_0_is_one_template)
{
    modelnet::SwarmNotCloseTmpl note = NotedNote();
    note.template_count = 0;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotCloseTmplResult result = modelnet::SwarmNoteNotCloseTmpl(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "ONE_TEMPLATE");
    BOOST_CHECK_EQUAL(err, "ONE_TEMPLATE");
}

BOOST_AUTO_TEST_CASE(template_count_2_is_one_template)
{
    modelnet::SwarmNotCloseTmpl note = NotedNote();
    note.template_count = 2;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotCloseTmplResult result = modelnet::SwarmNoteNotCloseTmpl(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "ONE_TEMPLATE");
    BOOST_CHECK_EQUAL(err, "ONE_TEMPLATE");
}

BOOST_AUTO_TEST_CASE(want_close_with_one_template_is_held)
{
    modelnet::SwarmNotCloseTmpl note = NotedNote();
    note.template_count = 1;
    note.want_close = true;
    std::string err = "prior";
    const modelnet::SwarmNotCloseTmplResult result = modelnet::SwarmNoteNotCloseTmpl(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_with_one_template_is_noted)
{
    modelnet::SwarmNotCloseTmpl note = NotedNote();
    note.template_count = 1;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotCloseTmplResult result = modelnet::SwarmNoteNotCloseTmpl(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
