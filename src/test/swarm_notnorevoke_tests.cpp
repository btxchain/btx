// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevoke.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorevoke_tests, BasicTestingSetup)

static modelnet::SwarmNotNoRevoke NotedNote()
{
    modelnet::SwarmNotNoRevoke note;
    note.grant_id = "grant-1";
    note.want_revoke = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_grant_id_is_grant)
{
    modelnet::SwarmNotNoRevoke note = NotedNote();
    note.grant_id.clear();
    note.want_revoke = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRevokeResult result = modelnet::SwarmNoteNotNoRevoke(note, err);
    BOOST_CHECK(!result.revoked);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "GRANT");
    BOOST_CHECK_EQUAL(err, "GRANT");
}

BOOST_AUTO_TEST_CASE(want_revoke_is_held)
{
    modelnet::SwarmNotNoRevoke note = NotedNote();
    note.want_revoke = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRevokeResult result = modelnet::SwarmNoteNotNoRevoke(note, err);
    BOOST_CHECK(!result.revoked);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRevoke note = NotedNote();
    note.want_revoke = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRevokeResult result = modelnet::SwarmNoteNotNoRevoke(note, err);
    BOOST_CHECK(!result.revoked);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
