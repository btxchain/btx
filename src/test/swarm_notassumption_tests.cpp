// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notassumption.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notassumption_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_close_id_is_close)
{
    std::string err = "prior";
    modelnet::SwarmNotAssumption note;
    note.want_measure = true;
    const modelnet::SwarmNotAssumptionResult result = modelnet::SwarmNoteNotAssumption(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "CLOSE");
    BOOST_CHECK_EQUAL(err, "CLOSE");
}

BOOST_AUTO_TEST_CASE(want_measure_is_measure_refused)
{
    std::string err = "prior";
    modelnet::SwarmNotAssumption note;
    note.close_id = "close-1";
    note.want_measure = true;
    const modelnet::SwarmNotAssumptionResult result = modelnet::SwarmNoteNotAssumption(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "MEASURE_REFUSED");
    BOOST_CHECK_EQUAL(err, "MEASURE_REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotAssumption note;
    note.close_id = "close-1";
    note.want_measure = false;
    const modelnet::SwarmNotAssumptionResult result = modelnet::SwarmNoteNotAssumption(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
