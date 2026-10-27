// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearned.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoearned_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_row_id_is_row)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarned note;
    note.coordinator_gone = true;
    note.want_drop = true;
    const modelnet::SwarmNotNoEarnedResult result = modelnet::SwarmNoteNotNoEarned(note, err);
    BOOST_CHECK_EQUAL(result.dropped, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "ROW");
    BOOST_CHECK_EQUAL(err, "ROW");
}

BOOST_AUTO_TEST_CASE(coordinator_gone_without_drop_is_kept)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarned note;
    note.row_id = "row-1";
    note.coordinator_gone = true;
    note.want_drop = false;
    const modelnet::SwarmNotNoEarnedResult result = modelnet::SwarmNoteNotNoEarned(note, err);
    BOOST_CHECK_EQUAL(result.dropped, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(want_drop_is_kept)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarned note;
    note.row_id = "row-1";
    note.coordinator_gone = false;
    note.want_drop = true;
    const modelnet::SwarmNotNoEarnedResult result = modelnet::SwarmNoteNotNoEarned(note, err);
    BOOST_CHECK_EQUAL(result.dropped, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarned note;
    note.row_id = "row-1";
    note.coordinator_gone = false;
    note.want_drop = false;
    const modelnet::SwarmNotNoEarnedResult result = modelnet::SwarmNoteNotNoEarned(note, err);
    BOOST_CHECK_EQUAL(result.dropped, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
