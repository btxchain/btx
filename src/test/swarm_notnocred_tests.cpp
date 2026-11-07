// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocred.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocred_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCred NotedNote()
{
    modelnet::SwarmNotNoCred note;
    note.cred_id = "cred-1";
    note.want_use = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_cred_id_is_cred)
{
    modelnet::SwarmNotNoCred note = NotedNote();
    note.cred_id.clear();
    note.want_use = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCredResult result = modelnet::SwarmNoteNotNoCred(note, err);
    BOOST_CHECK(!result.used);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "CRED");
    BOOST_CHECK_EQUAL(err, "CRED");
}

BOOST_AUTO_TEST_CASE(want_use_is_refused)
{
    modelnet::SwarmNotNoCred note = NotedNote();
    note.want_use = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCredResult result = modelnet::SwarmNoteNotNoCred(note, err);
    BOOST_CHECK(!result.used);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCred note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoCredResult result = modelnet::SwarmNoteNotNoCred(note, err);
    BOOST_CHECK(!result.used);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
