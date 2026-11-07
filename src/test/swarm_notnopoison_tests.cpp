// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopoison.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopoison_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sample_id_is_sample)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPoison note;
    note.poisoned = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoPoisonResult result = modelnet::SwarmNoteNotNoPoison(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "SAMPLE");
    BOOST_CHECK_EQUAL(err, "SAMPLE");
}

BOOST_AUTO_TEST_CASE(poisoned_without_publish_is_frozen)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPoison note;
    note.sample_id = "sample-1";
    note.poisoned = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoPoisonResult result = modelnet::SwarmNoteNotNoPoison(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(want_publish_is_frozen)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPoison note;
    note.sample_id = "sample-1";
    note.poisoned = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoPoisonResult result = modelnet::SwarmNoteNotNoPoison(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPoison note;
    note.sample_id = "sample-1";
    note.poisoned = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoPoisonResult result = modelnet::SwarmNoteNotNoPoison(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
