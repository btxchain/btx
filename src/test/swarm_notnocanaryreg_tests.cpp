// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocanaryreg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocanaryreg_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCanaryReg note;
    note.regression = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoCanaryRegResult result = modelnet::SwarmNoteNotNoCanaryReg(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(regression_without_want_publish_is_canary)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCanaryReg note;
    note.run_id = "run-1";
    note.regression = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoCanaryRegResult result = modelnet::SwarmNoteNotNoCanaryReg(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "CANARY");
    BOOST_CHECK_EQUAL(err, "CANARY");
}

BOOST_AUTO_TEST_CASE(want_publish_is_block)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCanaryReg note;
    note.run_id = "run-1";
    note.regression = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoCanaryRegResult result = modelnet::SwarmNoteNotNoCanaryReg(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "BLOCK");
    BOOST_CHECK_EQUAL(err, "BLOCK");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCanaryReg note;
    note.run_id = "run-1";
    note.regression = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoCanaryRegResult result = modelnet::SwarmNoteNotNoCanaryReg(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
