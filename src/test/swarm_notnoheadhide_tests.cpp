// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoheadhide.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoheadhide_tests, BasicTestingSetup)

static modelnet::SwarmNotNoHeadHide NotedNote()
{
    modelnet::SwarmNotNoHeadHide note;
    note.head_id = "head-1";
    note.want_hide = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_head_id_is_head)
{
    modelnet::SwarmNotNoHeadHide note = NotedNote();
    note.head_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoHeadHideResult result = modelnet::SwarmNoteNotNoHeadHide(note, err);
    BOOST_CHECK(!result.hidden);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "HEAD");
    BOOST_CHECK_EQUAL(err, "HEAD");
}

BOOST_AUTO_TEST_CASE(hiding_one_does_not_train)
{
    modelnet::SwarmNotNoHeadHide note = NotedNote();
    note.want_hide = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHeadHideResult result = modelnet::SwarmNoteNotNoHeadHide(note, err);
    BOOST_CHECK(!result.hidden);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "VISIBLE");
    BOOST_CHECK_EQUAL(err, "VISIBLE");
}

BOOST_AUTO_TEST_CASE(several_heads_stay_visible)
{
    const char* heads[] = {"head-a", "head-b", "head-c"};
    for (const char* head : heads) {
        modelnet::SwarmNotNoHeadHide note;
        note.head_id = head;
        note.want_hide = false;
        std::string err = "prior";
        const modelnet::SwarmNotNoHeadHideResult result = modelnet::SwarmNoteNotNoHeadHide(note, err);
        BOOST_CHECK(!result.hidden);
        BOOST_CHECK(!result.trained);
        BOOST_CHECK_EQUAL(result.code, "NOTED");
        BOOST_CHECK(err.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
