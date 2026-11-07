// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosealopen2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosealopen2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id_is_piece)
{
    modelnet::SwarmNotNoSealOpen2 note;
    note.sealed = true;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealOpen2Result result = modelnet::SwarmNoteNotNoSealOpen2(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(sealed_is_not_opened)
{
    modelnet::SwarmNotNoSealOpen2 note;
    note.piece_id = "piece-1";
    note.sealed = true;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealOpen2Result result = modelnet::SwarmNoteNotNoSealOpen2(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPENED");
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmNotNoSealOpen2 note;
    note.piece_id = "piece-1";
    note.sealed = false;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealOpen2Result result = modelnet::SwarmNoteNotNoSealOpen2(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSealOpen2 note;
    note.piece_id = "piece-1";
    note.sealed = false;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealOpen2Result result = modelnet::SwarmNoteNotNoSealOpen2(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
