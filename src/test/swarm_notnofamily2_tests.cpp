// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofamily2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofamily2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_family_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamily2 note;
    note.private_family = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoFamily2Result result = modelnet::SwarmNoteNotNoFamily2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(private_family)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamily2 note;
    note.family_id = "family-1";
    note.private_family = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoFamily2Result result = modelnet::SwarmNoteNotNoFamily2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamily2 note;
    note.family_id = "family-1";
    note.private_family = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoFamily2Result result = modelnet::SwarmNoteNotNoFamily2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamily2 note;
    note.family_id = "family-1";
    note.private_family = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoFamily2Result result = modelnet::SwarmNoteNotNoFamily2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
