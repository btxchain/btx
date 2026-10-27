// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomult.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomult_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotNoMult note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoMultResult result = modelnet::SwarmNoteNotNoMult(note, err);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.multiplier, 0);
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    modelnet::SwarmNotNoMult note;
    note.run_id = "run-a";
    note.want_publish = true;
    std::string err;
    const modelnet::SwarmNotNoMultResult result = modelnet::SwarmNoteNotNoMult(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.multiplier, 0);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoMult note;
    note.run_id = "run-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoMultResult result = modelnet::SwarmNoteNotNoMult(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.multiplier, 0);
}

BOOST_AUTO_TEST_SUITE_END()
