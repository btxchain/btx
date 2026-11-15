// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogradexp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogradexp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_update_id_is_update)
{
    modelnet::SwarmNotNoGradExp note;
    std::string err = "prior";
    const modelnet::SwarmNotNoGradExpResult result = modelnet::SwarmNoteNotNoGradExp(note, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "UPDATE");
    BOOST_CHECK_EQUAL(err, "UPDATE");
}

BOOST_AUTO_TEST_CASE(want_export_is_not_exported)
{
    modelnet::SwarmNotNoGradExp note;
    note.update_id = "update-1";
    note.want_export = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGradExpResult result = modelnet::SwarmNoteNotNoGradExp(note, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_EXPORTED");
    BOOST_CHECK_EQUAL(err, "NOT_EXPORTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGradExp note;
    note.update_id = "update-1";
    note.want_export = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGradExpResult result = modelnet::SwarmNoteNotNoGradExp(note, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
