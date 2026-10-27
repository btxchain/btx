// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreplace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoreplace_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_coord_id)
{
    modelnet::SwarmNotNoReplace note;
    note.gone = true;
    note.want_install = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoReplaceResult result = modelnet::SwarmNoteNotNoReplace(note, err);
    BOOST_CHECK(!result.installed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(gone_is_not_installed)
{
    modelnet::SwarmNotNoReplace note;
    note.coord_id = "coord-1";
    note.gone = true;
    note.want_install = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoReplaceResult result = modelnet::SwarmNoteNotNoReplace(note, err);
    BOOST_CHECK(!result.installed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_INSTALLED");
    BOOST_CHECK_EQUAL(err, "NOT_INSTALLED");
}

BOOST_AUTO_TEST_CASE(want_install_is_held)
{
    modelnet::SwarmNotNoReplace note;
    note.coord_id = "coord-1";
    note.gone = false;
    note.want_install = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoReplaceResult result = modelnet::SwarmNoteNotNoReplace(note, err);
    BOOST_CHECK(!result.installed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoReplace note;
    note.coord_id = "coord-1";
    note.gone = false;
    note.want_install = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoReplaceResult result = modelnet::SwarmNoteNotNoReplace(note, err);
    BOOST_CHECK(!result.installed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
