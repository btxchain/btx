// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomassexit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomassexit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_island_id_is_island)
{
    modelnet::SwarmNotNoMassExit note;
    note.assumed_size = true;
    note.want_measure = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMassExitResult result = modelnet::SwarmNoteNotNoMassExit(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(assumed_size_without_measure_is_unmeasured)
{
    modelnet::SwarmNotNoMassExit note;
    note.island_id = "island-1";
    note.assumed_size = true;
    note.want_measure = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoMassExitResult result = modelnet::SwarmNoteNotNoMassExit(note, err);
    // An assumed mass-exit size, including 8000 bytes, is not a measurement and moves no bytes.
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_measure_is_unmeasured)
{
    modelnet::SwarmNotNoMassExit note;
    note.island_id = "island-1";
    note.assumed_size = false;
    note.want_measure = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMassExitResult result = modelnet::SwarmNoteNotNoMassExit(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoMassExit note;
    BOOST_CHECK(!note.assumed_size);
    BOOST_CHECK(!note.want_measure);
    note.island_id = "island-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoMassExitResult result = modelnet::SwarmNoteNotNoMassExit(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
