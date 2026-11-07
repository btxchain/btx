// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notp50.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notp50_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_latency)
{
    modelnet::SwarmNotP50 note;
    std::string err = "prior";
    const modelnet::SwarmNotP50Result result = modelnet::SwarmNoteNotP50(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.latency_us, 0);
    BOOST_CHECK_EQUAL(result.code, "LATENCY");
    BOOST_CHECK_EQUAL(err, "LATENCY");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotP50 note;
    note.run_id = "run-a";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotP50Result result = modelnet::SwarmNoteNotP50(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.latency_us, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotP50 note;
    note.run_id = "run-a";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotP50Result result = modelnet::SwarmNoteNotP50(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.latency_us, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
