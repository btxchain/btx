// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoabortscan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoabortscan_tests, BasicTestingSetup)

static modelnet::SwarmNotNoAbortScan NotedNote()
{
    modelnet::SwarmNotNoAbortScan note;
    note.field_id = "field-1";
    note.wrong_type = false;
    note.want_scan = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_field_id_is_field)
{
    modelnet::SwarmNotNoAbortScan note = NotedNote();
    note.field_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoAbortScanResult result = modelnet::SwarmNoteNotNoAbortScan(note, err);
    BOOST_CHECK(!result.scanned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FIELD");
    BOOST_CHECK_EQUAL(err, "FIELD");
}

BOOST_AUTO_TEST_CASE(wrong_type_aborts_even_without_scan)
{
    modelnet::SwarmNotNoAbortScan note = NotedNote();
    note.wrong_type = true;
    note.want_scan = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAbortScanResult result = modelnet::SwarmNoteNotNoAbortScan(note, err);
    BOOST_CHECK(!result.scanned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ABORT");
    BOOST_CHECK_EQUAL(err, "ABORT");
}

BOOST_AUTO_TEST_CASE(want_scan_is_held)
{
    modelnet::SwarmNotNoAbortScan note = NotedNote();
    note.wrong_type = false;
    note.want_scan = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAbortScanResult result = modelnet::SwarmNoteNotNoAbortScan(note, err);
    BOOST_CHECK(!result.scanned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAbortScan note = NotedNote();
    note.wrong_type = false;
    note.want_scan = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAbortScanResult result = modelnet::SwarmNoteNotNoAbortScan(note, err);
    BOOST_CHECK(!result.scanned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
