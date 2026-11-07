// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseed.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoseed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_seed_id_is_seed)
{
    modelnet::SwarmNotNoSeed note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedResult result = modelnet::SwarmNoteNotNoSeed(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "SEED");
    BOOST_CHECK_EQUAL(err, "SEED");
}

BOOST_AUTO_TEST_CASE(want_publish_is_not_authority)
{
    modelnet::SwarmNotNoSeed note;
    note.seed_id = "seed-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedResult result = modelnet::SwarmNoteNotNoSeed(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSeed note;
    note.seed_id = "seed-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedResult result = modelnet::SwarmNoteNotNoSeed(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
