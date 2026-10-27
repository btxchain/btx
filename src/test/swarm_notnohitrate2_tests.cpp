// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohitrate2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohitrate2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sample_id)
{
    modelnet::SwarmNotNoHitRate2 note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHitRate2Result result = modelnet::SwarmNoteNotNoHitRate2(note, err);
    BOOST_CHECK_EQUAL(result.code, "SAMPLE");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hits, 0);
    BOOST_CHECK_EQUAL(err, "SAMPLE");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    modelnet::SwarmNotNoHitRate2 note;
    note.sample_id = "sample-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHitRate2Result result = modelnet::SwarmNoteNotNoHitRate2(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hits, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoHitRate2 note;
    note.sample_id = "sample-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoHitRate2Result result = modelnet::SwarmNoteNotNoHitRate2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hits, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
