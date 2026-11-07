// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomultiplier2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomultiplier2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sample_id_yields_sample)
{
    modelnet::SwarmNotNoMultiplier2 note;
    note.sample_id.clear();
    note.want_publish = true;
    std::string err;
    const modelnet::SwarmNotNoMultiplier2Result result = modelnet::SwarmNoteNotNoMultiplier2(note, err);
    BOOST_CHECK_EQUAL(result.code, "SAMPLE");
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK(!result.published);
}

BOOST_AUTO_TEST_CASE(want_publish_yields_held)
{
    modelnet::SwarmNotNoMultiplier2 note;
    note.sample_id = "sample-1";
    note.want_publish = true;
    std::string err;
    const modelnet::SwarmNotNoMultiplier2Result result = modelnet::SwarmNoteNotNoMultiplier2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.published);
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmNotNoMultiplier2 note;
    note.sample_id = "sample-1";
    note.want_publish = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoMultiplier2Result result = modelnet::SwarmNoteNotNoMultiplier2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.published);
}

BOOST_AUTO_TEST_SUITE_END()
