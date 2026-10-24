// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notresearchkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notresearchkey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    modelnet::SwarmNotResearchKey note;
    note.key_id.clear();
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotResearchKeyResult result = modelnet::SwarmNoteNotResearchKey(note, err);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK(!result.spend_key);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(want_spend_is_no_key)
{
    modelnet::SwarmNotResearchKey note;
    note.key_id = "key-1";
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotResearchKeyResult result = modelnet::SwarmNoteNotResearchKey(note, err);
    BOOST_CHECK_EQUAL(result.code, "NO_KEY");
    BOOST_CHECK_EQUAL(err, "NO_KEY");
    BOOST_CHECK(!result.spend_key);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotResearchKey note;
    note.key_id = "key-1";
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotResearchKeyResult result = modelnet::SwarmNoteNotResearchKey(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.spend_key);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_SUITE_END()
