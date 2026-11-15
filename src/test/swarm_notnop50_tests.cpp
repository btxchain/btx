// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop50.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnop50_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    std::string err = "prior";
    modelnet::SwarmNotNoP50 note;
    note.want_publish = true;
    const modelnet::SwarmNotNoP50Result result = modelnet::SwarmNoteNotNoP50(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.milliseconds, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotNoP50 note;
    note.run_id = "run-a";
    note.want_publish = true;
    const modelnet::SwarmNotNoP50Result result = modelnet::SwarmNoteNotNoP50(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.milliseconds, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(run_without_publish_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoP50 note;
    note.run_id = "run-a";
    note.want_publish = false;
    const modelnet::SwarmNotNoP50Result result = modelnet::SwarmNoteNotNoP50(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.milliseconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
