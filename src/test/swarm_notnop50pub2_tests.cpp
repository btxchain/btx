// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop50pub2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnop50pub2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sample_id_is_sample)
{
    std::string err = "prior";
    modelnet::SwarmNotNoP50Pub2 note;
    note.want_publish = true;
    const modelnet::SwarmNotNoP50Pub2Result result = modelnet::SwarmNoteNotNoP50Pub2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "SAMPLE");
    BOOST_CHECK_EQUAL(err, "SAMPLE");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoP50Pub2 note;
    note.sample_id = "sample-a";
    note.want_publish = true;
    const modelnet::SwarmNotNoP50Pub2Result result = modelnet::SwarmNoteNotNoP50Pub2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(sample_without_publish_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoP50Pub2 note;
    note.sample_id = "sample-a";
    note.want_publish = false;
    const modelnet::SwarmNotNoP50Pub2Result result = modelnet::SwarmNoteNotNoP50Pub2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
