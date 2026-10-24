// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcredential.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcredential_tests, BasicTestingSetup)

static modelnet::SwarmNotCredential NotedNote()
{
    modelnet::SwarmNotCredential note;
    note.item_id = "item-1";
    note.is_credential = false;
    note.want_admit = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_item_id_is_item)
{
    modelnet::SwarmNotCredential note = NotedNote();
    note.item_id.clear();
    note.is_credential = true;
    note.want_admit = true;
    std::string err = "prior";
    const modelnet::SwarmNotCredentialResult result = modelnet::SwarmNoteNotCredential(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "ITEM");
    BOOST_CHECK_EQUAL(err, "ITEM");
}

BOOST_AUTO_TEST_CASE(credential_without_want_admit_is_credential)
{
    modelnet::SwarmNotCredential note = NotedNote();
    note.is_credential = true;
    note.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmNotCredentialResult result = modelnet::SwarmNoteNotCredential(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "CREDENTIAL");
    BOOST_CHECK_EQUAL(err, "CREDENTIAL");
}

BOOST_AUTO_TEST_CASE(want_admit_without_credential_is_credential)
{
    modelnet::SwarmNotCredential note = NotedNote();
    note.is_credential = false;
    note.want_admit = true;
    std::string err = "prior";
    const modelnet::SwarmNotCredentialResult result = modelnet::SwarmNoteNotCredential(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "CREDENTIAL");
    BOOST_CHECK_EQUAL(err, "CREDENTIAL");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCredential note = NotedNote();
    note.is_credential = false;
    note.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmNotCredentialResult result = modelnet::SwarmNoteNotCredential(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
