// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearnpre.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoearnpre_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_row_id_is_row)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarnPre note;
    note.unsettled = true;
    note.want_record = true;
    const modelnet::SwarmNotNoEarnPreResult result = modelnet::SwarmNoteNotNoEarnPre(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "ROW");
    BOOST_CHECK_EQUAL(err, "ROW");
}

BOOST_AUTO_TEST_CASE(unsettled_without_record_is_not_recorded)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarnPre note;
    note.row_id = "row-1";
    note.unsettled = true;
    note.want_record = false;
    const modelnet::SwarmNotNoEarnPreResult result = modelnet::SwarmNoteNotNoEarnPre(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOT_RECORDED");
    BOOST_CHECK_EQUAL(err, "NOT_RECORDED");
}

BOOST_AUTO_TEST_CASE(want_record_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarnPre note;
    note.row_id = "row-1";
    note.unsettled = false;
    note.want_record = true;
    const modelnet::SwarmNotNoEarnPreResult result = modelnet::SwarmNoteNotNoEarnPre(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarnPre note;
    note.row_id = "row-1";
    note.unsettled = false;
    note.want_record = false;
    const modelnet::SwarmNotNoEarnPreResult result = modelnet::SwarmNoteNotNoEarnPre(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
