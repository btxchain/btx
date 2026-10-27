// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogrant.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogrant_tests, BasicTestingSetup)

static modelnet::SwarmNotNoGrant NotedNote()
{
    modelnet::SwarmNotNoGrant note;
    note.license_id = "license-1";
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotNoGrant note = NotedNote();
    note.license_id.clear();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGrantResult result = modelnet::SwarmNoteNotNoGrant(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(want_train_is_not_grant)
{
    modelnet::SwarmNotNoGrant note = NotedNote();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGrantResult result = modelnet::SwarmNoteNotNoGrant(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGrant note = NotedNote();
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGrantResult result = modelnet::SwarmNoteNotNoGrant(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
